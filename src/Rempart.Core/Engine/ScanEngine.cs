using Rempart.Core.Collectors;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Core.Engine;

public sealed record ScanResult(
    string ToolVersion,
    string StartedAtUtc,
    List<CollectorResult> Collectors,
    List<Verdict> Verdicts,
    List<Finding> Findings,
    ScoreCard? Score,
    /// <summary>Identifies the evaluated rule catalog: two reports are comparable only
    /// if they share the same fingerprint.</summary>
    string RulesFingerprint,
    /// <summary>Age of the evaluated data at scan time (ADR-002, D15).</summary>
    DataAge DataAge,
    /// <summary>Result of the active DoH/DoT probe, or null if it was not requested
    /// (--probe-dns). Kept out of the score: it is a recommendation, not a verdict.</summary>
    Dns.DnsProbeReport? DnsProbe = null,

    /// <summary>
    /// What the update store had to say — applied, or refused and why (ADR-002, D17).
    ///
    /// Carried by the result rather than passed alongside it, because the JSON report is
    /// re-rendered later by <c>rempart report</c>: a note living outside the result
    /// would silently vanish from the re-rendered report, and "the update was refused"
    /// is precisely the sentence that must never go missing.
    /// </summary>
    string? UpdateNote = null,

    /// <summary>What the stick's integrity seal concluded, when there is one to read.</summary>
    string? IntegrityNote = null,

    /// <summary>
    /// Where extra rules came from, when the evaluated catalog is not the embedded one
    /// alone.
    ///
    /// Three notes, three versions of the same question the reader of a report has to
    /// answer before comparing it to another: is this the catalog I think it is, was it
    /// updated, and is the tool that produced it the one that was sealed.
    /// </summary>
    string? RulesNote = null);

/// <summary>
/// Runs the collectors, then evaluates the rules.
///
/// Two distinct and deliberately decoupled stages: collectors describe the machine,
/// rules judge it. A collector carries no thresholds, and a rule never reads Windows
/// except through the providers.
///
/// A failing collector is reported and the scan continues: a partial report that
/// discloses its gaps is better than no report.
/// </summary>
public sealed class ScanEngine(IReadOnlyList<ICollector> collectors, IReadOnlyList<Rule> rules)
{
    /// <summary>
    /// Field collectors: they describe values known in advance, where the finding collectors
    /// below enumerate what is present. This table is the only place a scan learns of one,
    /// bar the opt-in wiring of <c>CliHost.CollectorsFor</c>.
    ///
    /// <para>
    /// Nothing in the compiler relates it to the classes in <c>Collectors/</c>, and the
    /// omission it lets through is the addition rather than the removal: a collector written
    /// and never registered contributes no key under <c>collectors[]</c>, so every golden
    /// reference stays identical to the byte. Reproduced on this repository — a new field
    /// collector left out of this line failed nothing in the whole suite, while emptying the
    /// line fails a dozen renderings, which is coverage of the collector and not of the table.
    /// Reflection would do away with the table but is excluded by ADR-001 (Native AOT), so
    /// <c>FieldCollectorRegistrationTests</c> confronts it with the assembly, with
    /// <c>Collectors/</c>, and with the flag behind which the one absent collector sits.
    /// </para>
    /// </summary>
    public static IReadOnlyList<ICollector> DefaultCollectors => [new InventoryCollector()];

    /// <summary>
    /// Finding collectors, supplied with the driver blocklist and the bloatware catalog in
    /// effect. Separate from field collectors: they enumerate what is present instead of
    /// describing values known in advance. Both lists come from the update store (D12); when
    /// it has nothing to hand over, the caller passes them empty and the collectors judge on
    /// signature alone.
    ///
    /// <para>
    /// Every implementation of <see cref="IFindingCollector"/> belongs here, and this table is
    /// the only place a scan learns of one. Nothing in the compiler relates it to the classes
    /// in <c>Findings/</c>, and a collector missing from it is invisible rather than broken:
    /// it produces no finding, so every golden reference stays identical to the byte and the
    /// report says « rien trouvé » about the surface it was written to watch. Four such
    /// omissions were reproduced on this file with the whole suite green. Reflection would
    /// remove the table but is excluded by ADR-001 (Native AOT), so
    /// <c>FindingCollectorRegistrationTests</c> confronts it with the assembly and with
    /// <c>Findings/</c> instead.
    /// </para>
    /// </summary>
    public static IReadOnlyList<IFindingCollector> DefaultFindingCollectors(
        Updates.DriverBlocklist blocklist, Updates.BloatwareCatalog catalog) =>
    [
        new AutorunsCollector(),
        new WmiSubscriptionsCollector(),
        new ScheduledTasksCollector(),
        new LoadedDriversCollector(blocklist),
        new RunningProcessesCollector(),
        new LogonExtensibilityCollector(),
        new LsaPackagesCollector(),
        new UnquotedServicePathCollector(),
        new ComHijackCollector(),
        new ListeningPortsCollector(),
        new DnsResolverCollector(),
        new HostsFileCollector(),
        new ProxyCollector(),
        new WifiProfileCollector(),
        new SoftwareInventoryCollector(catalog),
        new BrowserExtensionsCollector(),
    ];

    public ScanEngine(IReadOnlyList<ICollector> collectors)
        : this(collectors, [])
    {
    }

    public static ScanEngine Default(string? externalRules = null) =>
        new(DefaultCollectors, RuleCatalog.Load(externalRules));

    /// <summary>
    /// Reads every key the rules might consult, without evaluating anything.
    ///
    /// Without this, a snapshot would only contain the reads actually performed on the
    /// source machine: a rule out of scope there — machine not domain-joined, RDP
    /// disabled — would have recorded nothing, and replay would fail as soon as the
    /// context changes. A fixture must be replayable everywhere, not only under the
    /// conditions of its capture.
    /// </summary>
    public void Prefetch(ProviderSet providers)
    {
        foreach (var rule in rules)
        {
            Rules.CheckReader.Touch(rule.Check, providers);

            if (rule.AppliesWhen?.Registry is { } condition)
            {
                Rules.CheckReader.Touch(condition, providers);
            }
        }
    }

    /// <summary>
    /// Runs the field collectors, evaluates the rules, then runs the finding collectors.
    ///
    /// <para>
    /// <paramref name="findingCollectors"/> is demanded, not defaulted. It fell back to
    /// <c>DefaultFindingCollectors(DriverBlocklist.Empty, BloatwareCatalog.Empty)</c>, which
    /// put the driver blocklist and the bloatware catalog one deleted argument away from
    /// being lost: still sixteen collectors, still a whole report, and « aucun pilote bloqué,
    /// aucun bloatware » about a machine carrying both. Nothing observable separated that run
    /// from a correct one — no missing key, no count moved, every golden reference identical
    /// to the byte — so the compiler holds the link instead, the reasoning #136 settled on
    /// when it changed <c>ListValues</c>' return type rather than adding an overload beside
    /// it. It sits ahead of <paramref name="dataAsOfUtc"/> so that no optional parameter
    /// precedes it, and so that a call that used to omit it stops compiling rather than
    /// binding its date here.
    /// </para>
    ///
    /// <para>
    /// Empty lists remain a legitimate answer — a replay passes the empty blocklist with the
    /// embedded catalog, and a test judging on signature alone passes both empty. What
    /// changed is that the caller has to say so.
    /// </para>
    /// </summary>
    public ScanResult Run(
        ProviderSet providers, string toolVersion, string startedAtUtc,
        IReadOnlyList<IFindingCollector> findingCollectors, string? dataAsOfUtc = null)
    {
        var results = new List<CollectorResult>(collectors.Count);

        foreach (var collector in collectors)
        {
            try
            {
                results.Add(collector.Collect(providers));
            }
            catch (Exception ex)
            {
                results.Add(new CollectorResult(
                    collector.Name,
                    CollectorStatus.Failed,
                    [],
                    [$"Le collecteur a échoué : {ex.Message}"]));
            }
        }

        // Applicability conditions rely on machine facts as much as on the registry:
        // the evaluator needs both.
        var system = providers.SystemInfo.Read();

        var verdicts = rules
            .Select(rule => RuleEvaluator.Evaluate(rule, providers, system))
            .ToList();

        var findings = new List<Finding>();
        foreach (var collector in findingCollectors)
        {
            try
            {
                findings.AddRange(collector.Collect(providers));
            }
            catch (Exception ex)
            {
                // A finding collector that fails must not abort the scan — a partial report
                // that discloses its gaps beats no report.
                //
                // Told apart from a refusal, which it looked exactly like: same severity, same
                // shape, and neither reached the exit code. The two ask for opposite things
                // from whoever reads the number — this one is a bug and elevation will not fix
                // it — and a field collector that throws has said so since the first milestone,
                // through the CollectorStatus.Failed just above.
                findings.Add(Finding.Broken(
                    collector.Name, "collecteur", $"Enumeration interrompue : {ex.Message}"));
            }
        }

        return new ScanResult(
            toolVersion,
            startedAtUtc,
            results,
            verdicts,
            findings,
            verdicts.Count > 0 ? Scoring.Compute(verdicts) : null,
            RuleCatalog.Fingerprint(rules),
            // Measured against the scan time: live scans use the real time, replays use
            // the frozen capture time. The reference date is the embedded catalog's, or
            // the applied update's if the caller provides one.
            DataFreshness.At(dataAsOfUtc ?? RuleCatalog.EmbeddedAsOfUtc, startedAtUtc));
    }
}
