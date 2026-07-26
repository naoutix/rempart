using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Rules;

namespace Rempart.Core.Reports;

/// <summary>One family of findings, its flagged members separated from its total.</summary>
public sealed record FindingGroup(string Kind, IReadOnlyList<Finding> Flagged, int Total);

/// <summary>
/// The ordered, derived view both renderers consume.
///
/// It exists so HTML and Markdown cannot drift apart on what they show or in which
/// order: two renderers filtering findings on their own would eventually disagree, and
/// the disagreement would show up as a finding present in one report and absent from
/// the other — the worst possible bug for an audit tool.
///
/// Ordering is deterministic down to ties, because the reports are golden-tested.
/// </summary>
public sealed record ReportView(
    string MachineName,

    /// <summary>Scan date, <c>yyyy-MM-dd</c>, derived from the ISO instant.</summary>
    string ScanDate,

    /// <summary>Rules that failed, worst first.</summary>
    IReadOnlyList<Verdict> Failures,

    /// <summary>Rules that could not be read. Never counted as compliant.</summary>
    IReadOnlyList<Verdict> Unverifiable,

    int Passed,
    int NotApplicable,

    /// <summary>Findings by family, families carrying something to examine first.</summary>
    IReadOnlyList<FindingGroup> Groups,

    int FlaggedFindings,
    int TotalFindings,

    /// <summary>Was the scan elevated? Decides whether the report opens on a caveat.</summary>
    bool Elevated,

    /// <summary>Collectors that did not return everything, whatever the reason.</summary>
    IReadOnlyList<CollectorResult> DegradedCollectors,

    ScanResult Result)
{
    /// <summary>
    /// Fields of the component store analysis, in the order a reader needs them: the
    /// whole, then the part that cannot be freed, then the two that can, then the total.
    /// </summary>
    public static readonly IReadOnlyList<(string Label, string Field)> ComponentStoreLayers =
    [
        ("taille réelle du magasin", "store.actualSizeBytes"),
        ("partagé avec Windows — non récupérable", "store.sharedWithWindowsBytes"),
        ("sauvegardes et fonctionnalités désactivées", "store.backupsAndDisabledFeaturesBytes"),
        ("cache et données temporaires", "store.cacheAndTemporaryBytes"),
        ("récupérable au total", "store.reclaimableBytes"),
    ];

    /// <summary>
    /// The component store fields, or null when the analysis was not requested — it is
    /// opt-in, so its absence is the ordinary case and must not print an empty section.
    /// </summary>
    public IReadOnlyDictionary<string, string?>? ComponentStore =>
        Result.Collectors.FirstOrDefault(c =>
            c.Name == "component-store" && c.Status == CollectorStatus.Ok)?.Fields;

    public static ReportView From(ScanResult result)
    {
        var inventory = result.Collectors.FirstOrDefault(c => c.Name == "inventory");

        var groups = result.Findings
            .GroupBy(f => f.Kind, StringComparer.Ordinal)
            .Select(g => new FindingGroup(
                g.Key,
                [.. g.Where(f => f.Severity != FindingSeverity.Benign).OrderByDescending(f => f.Severity)
                    .ThenBy(f => f.Source, StringComparer.Ordinal)
                    .ThenBy(f => f.Target, StringComparer.Ordinal)],
                g.Count()))
            // Families with something to examine come first: a reader who stops after
            // the first screen must have seen the problems, not the inventory.
            .OrderByDescending(g => g.Flagged.Count)
            .ThenBy(g => g.Kind, StringComparer.Ordinal)
            .ToList();

        return new ReportView(
            MachineName: Field(inventory, "machine.name") ?? "machine inconnue",
            ScanDate: DateOf(result.StartedAtUtc),
            Failures: [.. result.Verdicts.Where(v => v.Status == VerdictStatus.Fail)
                .OrderByDescending(v => v.Severity).ThenBy(v => v.RuleId, StringComparer.Ordinal)],
            Unverifiable: [.. result.Verdicts.Where(v => v.Status == VerdictStatus.Unknown)
                .OrderBy(v => v.RuleId, StringComparer.Ordinal)],
            Passed: result.Verdicts.Count(v => v.Status == VerdictStatus.Pass),
            NotApplicable: result.Verdicts.Count(v => v.Status == VerdictStatus.NotApplicable),
            Groups: groups,
            FlaggedFindings: groups.Sum(g => g.Flagged.Count),
            TotalFindings: result.Findings.Count,
            // Absent field means an inventory that could not be read: treat as
            // non-elevated, so the report warns rather than reassures.
            Elevated: string.Equals(Field(inventory, "scan.elevated"), "True",
                StringComparison.OrdinalIgnoreCase),
            DegradedCollectors: [.. result.Collectors.Where(c => c.Status != CollectorStatus.Ok)],
            Result: result);
    }

    private static string? Field(CollectorResult? collector, string name) =>
        collector is not null && collector.Fields.TryGetValue(name, out var value)
            ? value
            : null;

    /// <summary>
    /// Date portion of an ISO instant, without parsing it. A capture replayed on a
    /// machine in another culture must yield the same folder name as on the machine
    /// that produced it — <c>DateTime.Parse</c> would not guarantee that.
    /// </summary>
    public static string DateOf(string isoInstant) =>
        isoInstant.Length >= 10 ? isoInstant[..10] : isoInstant;
}

/// <summary>
/// The words the report uses. Centralised because the two renderers must name the same
/// thing identically — and because rule texts and CLI output are French while the code
/// is English (see the language policy in CONTRIBUTING).
/// </summary>
public static class ReportLabels
{
    public static string Of(Severity severity) => severity switch
    {
        Severity.Critical => "critique",
        Severity.High => "élevée",
        Severity.Medium => "moyenne",
        Severity.Low => "faible",
        _ => "info",
    };

    public static string Of(FindingSeverity severity) => severity switch
    {
        FindingSeverity.Suspicious => "suspect",
        FindingSeverity.Notable => "notable",
        _ => "bénin",
    };

    public static string Of(CollectorStatus status) => status switch
    {
        CollectorStatus.Ok => "complet",
        CollectorStatus.InsufficientPrivileges => "droits insuffisants",
        CollectorStatus.Unavailable => "indisponible sur cette machine",
        _ => "en échec",
    };

    /// <summary>
    /// Finding families, named for a reader rather than for the code. An unknown family
    /// falls back to its identifier: a new collector must not silently print nothing.
    /// </summary>
    public static string Family(string kind) => kind switch
    {
        "autorun" => "démarrage automatique",
        "browser-extension" => "extensions de navigateur",
        "com-hijack" => "détournement COM",
        "dns-resolver" => "résolveurs DNS",
        "driver" => "pilotes chargés",
        "hosts" => "fichier hosts",
        "listening-port" => "ports en écoute",
        "logon-extensibility" => "points d'extension à l'ouverture de session",
        "lsa-package" => "paquets LSA",
        "process" => "processus courants",
        "proxy" => "proxy et PAC",
        "scheduled-task" => "tâches planifiées",
        "software" => "logiciels installés",
        "unquoted-service-path" => "chemins de service non guillemetés",
        "wifi-profile" => "profils Wi-Fi",
        "wmi-subscription" => "abonnements WMI permanents",
        _ => kind,
    };

    /// <summary>
    /// A size in units a human reads. Binary multiples, because that is what Windows
    /// and DISM report.
    /// </summary>
    public static string Bytes(long bytes)
    {
        string[] units = ["o", "Kio", "Mio", "Gio", "Tio"];
        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{bytes} o"
            : string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"{value:0.#} {units[unit]}");
    }
}
