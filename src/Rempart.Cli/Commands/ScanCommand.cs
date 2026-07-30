using Rempart.Core.Cli;
using Rempart.Core.Dns;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Pac;
using Rempart.Core.Providers;
using Rempart.Core.Reports;
using Rempart.Core.Reputation;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;
using Rempart.Windows;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Audits the local machine, or replays a snapshot offline — the command every other one
/// exists around.
/// </summary>
internal static class ScanCommand
{
    public static int Run(string[] args)
    {
        var snapshotPath = OptionValue(args, "--from");
        var asJson = HasFlag(args, "--json");

        ProviderSet providers;
        string origin;

        if (snapshotPath is not null)
        {
            // Offline replay: the same collection code, without Windows. The wiring is
            // SnapshotProviders.Replaying rather than twenty lines written here, so that
            // the guard which checks every provider is wired reads the list this command
            // actually runs on — it used to read a copy that lived in the test suite.
            var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(snapshotPath));
            providers = SnapshotProviders.Replaying(snapshot);
            origin = snapshot.CapturedAtUtc;
        }
        else
        {
            RequireWindows();
            providers = LiveProviders.All();
            origin = UtcNow();
        }

        // The update store only applies to live scans. A replay reproduces a past scan:
        // injecting this machine's store would make it non-deterministic, and make a
        // fixture depend on local state. On replay, only the embedded baseline counts.
        var resolution = snapshotPath is null
            ? ResolveLiveCatalog(args)
            : new CatalogResolution(RuleCatalog.Load(RulesDirectory(args)),
                DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);

        // The store's verdict rides along inside the result: the JSON report is re-rendered
        // later by "rempart report", and a note kept outside would vanish there — exactly
        // the silence ADR-002 (D17) forbids. AppliedTo puts it there, and puts a store this
        // version broke down on among the findings as well, so that it reaches the exit
        // code — the channel the header note does not have. It lives in Core rather than
        // here for the reason this whole method is read as text: no test compiles Cli.
        var result = resolution.AppliedTo(
                new ScanEngine(CollectorsFor(args), resolution.Rules)
                    .Run(providers, ToolVersion(), origin,
                        ScanEngine.DefaultFindingCollectors(resolution.Blocklist, resolution.Catalog),
                        resolution.AsOfUtc))
            with
            {
                // Extra rules change what the score means, so where they came from is said
                // outright rather than left to be inferred from a fingerprint that moved.
                RulesNote = RulesDirectory(args) is { } directory
                    ? $"Règles supplémentaires chargées depuis {directory}."
                    : null,
            };

        // Everything from here on runs on a finished scan, and every one of these steps used
        // to be able to end it: what they throw had nothing in front of it but the catch-all
        // in Program, one statement before the report was written out. OptionalStep is the
        // door they all go through now — building the source, using it and closing it all
        // happen inside, and a step that fails becomes a line of the report instead. Held
        // shut by ScanCommandStepTests, which reads this method as text because the Linux
        // job does not compile this project.

        // Only on a live scan. A replay reproduces a past scan: hashing the stick this
        // binary happens to sit on would make a fixture depend on local state, exactly why
        // the update store is not consulted on replay either.
        if (snapshotPath is null)
        {
            result = OptionalStep.Ran(result, "sceau d'intégrité", scan => scan with
            {
                IntegrityNote = SealCommand.SealNote(AppContext.BaseDirectory),
            });
        }

        // VirusTotal enrichment — the scan's only network call, never on by default
        // (ADR-001, D9) and never on replay: that is a past snapshot, not the current
        // machine. The key comes from --virustotal-key or the environment.
        var virusTotalKey = OptionValue(args, "--virustotal-key")
            ?? Environment.GetEnvironmentVariable("REMPART_VT_KEY");

        if (snapshotPath is null && !string.IsNullOrWhiteSpace(virusTotalKey))
        {
            var flagged = result.Findings.Count(f => f.Severity != FindingSeverity.Benign
                && f.Details.ContainsKey("sha256"));

            Console.Error.WriteLine($"Consultation VirusTotal de {flagged} constat(s) signalé(s)…");

            result = OptionalStep.Ran(result, "--virustotal-key", scan =>
            {
                using var reputation = new VirusTotalReputation(virusTotalKey);
                return scan with
                {
                    Findings = [.. FindingEnrichment.WithReputation(scan.Findings, reputation)],
                };
            });
        }

        // PAC script retrieval — the scan's second possible network call, explicit opt-in
        // (--fetch-pac) and never on replay: a past snapshot must not trigger traffic.
        // Only fetches for flagged proxy findings that carry a URL.
        if (snapshotPath is null && HasFlag(args, "--fetch-pac"))
        {
            var withPac = result.Findings.Count(f => f.Severity != FindingSeverity.Benign
                && f.Details.ContainsKey("pac") && f.Details["pac"].Length > 0);

            Console.Error.WriteLine($"Récupération de {withPac} script(s) PAC signalé(s)…");

            result = OptionalStep.Ran(result, "--fetch-pac", scan =>
            {
                using var fetcher = new LivePacFetcher();
                return scan with
                {
                    Findings = [.. PacEnrichment.WithRouting(scan.Findings, fetcher)],
                };
            });
        }

        // Active DoH/DoT probe — the other opt-in network call, never by default nor on
        // replay. Measures encrypted-resolver latency and separates the finding (encrypted
        // DNS blocked) from the advice (the fastest one), which stays out of the score.
        if (snapshotPath is null && HasFlag(args, "--probe-dns"))
        {
            Console.Error.WriteLine("Sonde des résolveurs DNS chiffrés (DoH/DoT)…");

            result = OptionalStep.Ran(result, "--probe-dns", scan =>
            {
                using var probe = new LiveDnsProbe();
                var (report, probeFindings) = DnsProbeAnalysis.Analyse(probe.Probe());
                return scan with
                {
                    Findings = [.. scan.Findings, .. probeFindings],
                    DnsProbe = report,
                };
            });
        }

        if (asJson)
        {
            Console.WriteLine(RempartJson.Serialise(result));
        }
        else
        {
            Console.Write(ConsoleReport.HumanReadable(result));
        }

        // The packaged report — the stick's deliverable. Asked for explicitly: a scan
        // piped into a script must not litter the drive it runs from.
        if (HasFlag(args, "--report") && !WriteReportBundle(args, result))
        {
            return 1;
        }

        // Neither a missing privilege nor a control left unverifiable is an execution
        // error, and the caller who reads nothing but this number must still be able to
        // tell them apart from a scan that saw the whole machine.
        return (int)ExitCodes.ForScan(result);
    }

    /// <summary>
    /// Writes the three report files into <c>&lt;root&gt;/&lt;hostname&gt;-&lt;date&gt;/</c>,
    /// the layout a stick carries across machines.
    ///
    /// <para>
    /// The default root sits next to the binary, so plugging the stick in and running
    /// <c>rempart scan --report</c> files the report with the others, with nothing to
    /// configure. Failing to write is reported and returns false: the caller asked for a
    /// report, and a scan that printed to the console while silently producing no file
    /// would be the worst of both.
    /// </para>
    ///
    /// <para>
    /// The guard is as wide as what it covers, which is the rule the seal note was just
    /// held to and this method had not been. <c>ReportBundle.Build</c> is not a write: it
    /// renders the HTML, renders the Markdown and serialises the JSON, and what those
    /// throw is not <c>IOException or UnauthorizedAccessException</c> — that pair is the
    /// obvious one, and obvious is how a filter ends up narrower than its body. Naming the
    /// folder was outside the <c>try</c> altogether. Anything past the pair keeps the
    /// French sentence naming the folder; only the read-only hint is held back, because a
    /// rendering that failed is not a stick with its tab down and saying so would be a
    /// guess dressed as advice.
    /// </para>
    /// </summary>
    private static bool WriteReportBundle(string[] args, ScanResult result)
    {
        var root = OptionalValue(args, "--report")
            ?? Path.Combine(AppContext.BaseDirectory, "reports");

        // Named before the try so the message below has somewhere to point even when it is
        // the naming itself that failed.
        var folder = root;

        try
        {
            folder = FreeFolder(root, ReportBundle.FolderName(result));

            Directory.CreateDirectory(folder);

            foreach (var file in ReportBundle.Build(result))
            {
                File.WriteAllText(Path.Combine(folder, file.Name), file.Content);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"Rapport non écrit dans {folder} : {ex.Message}");

            if (ex is IOException or UnauthorizedAccessException)
            {
                // The common case is a write-protected stick, which is a sensible way to
                // carry an audit tool: say what to do rather than surface a bare IO error.
                Console.Error.WriteLine(
                    "Support en lecture seule ? Indiquer un autre dossier : --report <dossier>.");
            }

            return false;
        }

        Console.WriteLine();
        Console.WriteLine($"Rapport écrit dans {folder}");
        Console.WriteLine($"  {ReportBundle.HtmlName,-14} à ouvrir dans un navigateur, autonome");
        Console.WriteLine($"  {ReportBundle.MarkdownName,-14} à coller dans un ticket");
        Console.WriteLine($"  {ReportBundle.JsonName,-14} la donnée complète, constats bénins compris");
        return true;
    }
}
