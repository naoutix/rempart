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
    Dns.DnsProbeReport? DnsProbe = null);

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
    public static IReadOnlyList<ICollector> DefaultCollectors => [new InventoryCollector()];

    /// <summary>
    /// Finding collectors. Separate from field collectors: they enumerate what is
    /// present instead of describing values known in advance.
    /// </summary>
    /// <summary>
    /// Finding collectors, supplied with the driver blocklist in effect. The list comes
    /// from the update store (D12); when unavailable it is empty and the collector
    /// judges drivers on their signature alone.
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

    public ScanResult Run(
        ProviderSet providers, string toolVersion, string startedAtUtc, string? dataAsOfUtc = null,
        IReadOnlyList<IFindingCollector>? findingCollectors = null)
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
        foreach (var collector in findingCollectors
            ?? DefaultFindingCollectors(Updates.DriverBlocklist.Empty, Updates.BloatwareCatalog.Empty))
        {
            try
            {
                findings.AddRange(collector.Collect(providers));
            }
            catch (Exception ex)
            {
                // A finding collector that fails must not abort the scan.
                findings.Add(new Finding(collector.Name, "collecteur", collector.Name,
                    FindingSeverity.Notable, [$"Enumeration interrompue : {ex.Message}"], new Dictionary<string, string>()));
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
