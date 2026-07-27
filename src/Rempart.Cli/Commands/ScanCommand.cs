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
            // Offline replay: the same collection code, without Windows.
            var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(snapshotPath));
            providers = new ProviderSet(
                new SnapshotRegistryProvider(snapshot),
                new SnapshotSystemInfoProvider(snapshot),
                services: new SnapshotServiceStateProvider(snapshot),
                policy: new SnapshotSecurityPolicyProvider(snapshot),
                wmi: new SnapshotWmiProvider(snapshot),
                signatures: new SnapshotSignatureProvider(snapshot),
                files: new SnapshotFileSystemProvider(snapshot),
                scheduledTasks: new SnapshotScheduledTaskProvider(snapshot),
                drivers: new SnapshotDriverProvider(snapshot),
                processes: new SnapshotProcessProvider(snapshot),
                listeningPorts: new SnapshotListeningPortProvider(snapshot),
                firewall: new SnapshotFirewallProvider(snapshot),
                dns: new SnapshotDnsProvider(snapshot),
                hostsFile: new SnapshotHostsFileProvider(snapshot),
                proxy: new SnapshotProxyProvider(snapshot),
                wifi: new SnapshotWifiProfileProvider(snapshot),
                softwareInventory: new SnapshotSoftwareInventoryProvider(snapshot),
                browserExtensions: new SnapshotBrowserExtensionProvider(snapshot),
                componentStore: new SnapshotComponentStoreProvider(snapshot));
            origin = snapshot.CapturedAtUtc;
        }
        else
        {
            RequireWindows();
            providers = new ProviderSet(
                new LiveRegistryProvider(),
                new LiveSystemInfoProvider(),
                services: new LiveServiceStateProvider(),
                policy: new LiveSecurityPolicyProvider(),
                wmi: new Rempart.Windows.Wmi.LiveWmiProvider(),
                signatures: new LiveSignatureProvider(),
                files: new LiveFileSystemProvider(),
                scheduledTasks: new Rempart.Windows.Tasks.LiveScheduledTaskProvider(),
                drivers: new LiveDriverProvider(),
                processes: new LiveProcessProvider(),
                listeningPorts: new LiveListeningPortProvider(),
                firewall: new LiveFirewallProvider(),
                dns: new LiveDnsProvider(),
                hostsFile: new LiveHostsFileProvider(),
                proxy: new LiveProxyProvider(),
                wifi: new LiveWifiProfileProvider(),
                softwareInventory: new LiveSoftwareInventoryProvider(),
                browserExtensions: new LiveBrowserExtensionProvider(),
                componentStore: new LiveComponentStoreProvider());
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
        // the silence ADR-002 (D17) forbids.
        var result = new ScanEngine(CollectorsFor(args), resolution.Rules)
            .Run(providers, ToolVersion(), origin, resolution.AsOfUtc,
                ScanEngine.DefaultFindingCollectors(resolution.Blocklist, resolution.Catalog))
            with
            {
                UpdateNote = resolution.UpdateNote,

                // Only on a live scan. A replay reproduces a past scan: hashing the stick
                // this binary happens to sit on would make a fixture depend on local state,
                // exactly why the update store is not consulted on replay either.
                IntegrityNote = snapshotPath is null ? SealCommand.SealNote(AppContext.BaseDirectory) : null,

                // Extra rules change what the score means, so where they came from is said
                // outright rather than left to be inferred from a fingerprint that moved.
                RulesNote = RulesDirectory(args) is { } directory
                    ? $"Règles supplémentaires chargées depuis {directory}."
                    : null,
            };

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

            using var reputation = new VirusTotalReputation(virusTotalKey);
            result = result with
            {
                Findings = [.. FindingEnrichment.WithReputation(result.Findings, reputation)],
            };
        }

        // PAC script retrieval — the scan's second possible network call, explicit opt-in
        // (--fetch-pac) and never on replay: a past snapshot must not trigger traffic.
        // Only fetches for flagged proxy findings that carry a URL.
        if (snapshotPath is null && HasFlag(args, "--fetch-pac"))
        {
            var withPac = result.Findings.Count(f => f.Severity != FindingSeverity.Benign
                && f.Details.ContainsKey("pac") && f.Details["pac"].Length > 0);

            Console.Error.WriteLine($"Récupération de {withPac} script(s) PAC signalé(s)…");

            using var fetcher = new LivePacFetcher();
            result = result with
            {
                Findings = [.. PacEnrichment.WithRouting(result.Findings, fetcher)],
            };
        }

        // Active DoH/DoT probe — the other opt-in network call, never by default nor on
        // replay. Measures encrypted-resolver latency and separates the finding (encrypted
        // DNS blocked) from the advice (the fastest one), which stays out of the score.
        if (snapshotPath is null && HasFlag(args, "--probe-dns"))
        {
            Console.Error.WriteLine("Sonde des résolveurs DNS chiffrés (DoH/DoT)…");

            using var probe = new LiveDnsProbe();
            var (report, probeFindings) = DnsProbeAnalysis.Analyse(probe.Probe());
            result = result with
            {
                Findings = [.. result.Findings, .. probeFindings],
                DnsProbe = report,
            };
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
    /// </summary>
    private static bool WriteReportBundle(string[] args, ScanResult result)
    {
        var root = OptionalValue(args, "--report")
            ?? Path.Combine(AppContext.BaseDirectory, "reports");

        var folder = FreeFolder(root, ReportBundle.FolderName(result));

        try
        {
            Directory.CreateDirectory(folder);

            foreach (var file in ReportBundle.Build(result))
            {
                File.WriteAllText(Path.Combine(folder, file.Name), file.Content);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The common case is a write-protected stick, which is a sensible way to carry
            // an audit tool: say what to do rather than surface a bare IO error.
            Console.Error.WriteLine();
            Console.Error.WriteLine($"Rapport non écrit dans {folder} : {ex.Message}");
            Console.Error.WriteLine(
                "Support en lecture seule ? Indiquer un autre dossier : --report <dossier>.");
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
