using System.Globalization;
using Rempart.Core.Diff;
using Rempart.Core.Engine;

namespace Rempart.Core.Survey;

/// <summary>One value, and how many machines of a given build hold it.</summary>
public sealed record ValueTally(string Value, int Machines, IReadOnlyList<string> Examples);

/// <summary>What one Windows build was observed to hold, worst spread first.</summary>
public sealed record BuildTally(string Build, IReadOnlyList<ValueTally> Values)
{
    public int Machines => Values.Sum(value => value.Machines);
}

/// <summary>
/// What one key is worth across every machine that has been captured.
///
/// <para>
/// <c>diff</c> compares two reports, <c>index</c> aggregates machines, <c>drift</c> aggregates
/// dates. None of them answers the question every deferred rule turns on: <b>does this key
/// hold the same value everywhere, and does it depend on the Windows build?</b> That is
/// <c>DET-WINDEFAULT</c> — some sixty defaults validated on one machine — and it is what
/// stands between the TLS and IPv6 rules and being shipped. A default guessed from one
/// machine is the mistake M1 already paid for once.
/// </para>
///
/// <para>
/// <b>A machine counts once, however often it was scanned.</b> The folders this reads are the
/// ones <c>drift</c> reads, which by design hold a series per machine: counting reports would
/// let a weekly-scanned machine outvote nine others ten to one. The most recent report of each
/// machine is the one that answers — an edition upgraded in March is what the machine is now.
/// </para>
/// </summary>
public sealed record FieldSurvey(
    string Name,

    /// <summary>The name was read as a rule identifier rather than as a collector field.</summary>
    bool IsRule,

    int Reports,
    int Machines,
    IReadOnlyList<BuildTally> Builds)
{
    /// <summary>
    /// One value, everywhere. False when nothing was observed at all, and deliberately: a
    /// survey nobody could answer must not print the sentence a unanimous one prints.
    /// </summary>
    public bool Agrees =>
        Machines > 0
        && Builds.SelectMany(build => build.Values)
            .Select(value => value.Value)
            .Distinct(StringComparer.Ordinal)
            .Count() == 1;

    /// <summary>Machines with no readable build are surveyed apart rather than folded in.</summary>
    internal const string UnknownBuild = "build inconnue";

    /// <summary>
    /// A name carrying a dot is a collector field; one without is a rule identifier. The two
    /// naming conventions have never overlapped — <c>tls.1_2.client.enabled</c> against
    /// <c>WIN-LEG-003</c> — and reading the shape beats asking the caller to say which.
    /// </summary>
    public static bool NamesARule(string name) => !name.Contains('.', StringComparison.Ordinal);

    public static FieldSurvey Of(string name, IEnumerable<ScanResult> reports)
    {
        var isRule = NamesARule(name);
        var all = reports.ToList();

        // One entry per machine, holding its most recent report.
        var latest = new Dictionary<string, ScanResult>(StringComparer.Ordinal);

        foreach (var report in all)
        {
            var machine = ScanDiff.MachineName(report);

            if (!latest.TryGetValue(machine, out var kept) || Later(report, kept))
            {
                latest[machine] = report;
            }
        }

        var observations = latest
            .Select(entry => (Machine: entry.Key, Build: BuildOf(entry.Value), Value: Read(entry.Value, name, isRule)))
            .Where(observation => observation.Value is not null)
            .ToList();

        var builds = observations
            .GroupBy(observation => observation.Build, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new BuildTally(group.Key,
            [
                .. group
                    .GroupBy(observation => observation.Value!, StringComparer.Ordinal)
                    .OrderByDescending(values => values.Count())
                    .ThenBy(values => values.Key, StringComparer.Ordinal)
                    .Select(values => new ValueTally(
                        values.Key,
                        values.Count(),
                        [.. values.Select(observation => observation.Machine)
                            .OrderBy(machine => machine, StringComparer.Ordinal)
                            .Take(3)])),
            ]))
            .ToList();

        return new FieldSurvey(name, isRule, all.Count, observations.Count, builds);
    }

    /// <summary>
    /// A verdict's observed value for a rule, or a collector's field. Both are "what this
    /// machine had", which is why one command answers for both: the sixty defaults of
    /// DET-WINDEFAULT are verdicts, and the SCHANNEL values that will one day become rules
    /// are fields, and the question asked of them is word for word the same.
    /// </summary>
    private static string? Read(ScanResult report, string name, bool isRule) =>
        isRule
            ? report.Verdicts
                .FirstOrDefault(verdict =>
                    string.Equals(verdict.RuleId, name, StringComparison.OrdinalIgnoreCase))?.Observed
            : report.Collectors
                .Select(collector => collector.Fields.TryGetValue(name, out var value) ? value : null)
                .FirstOrDefault(value => value is not null);

    /// <summary>
    /// The build, and the edition beside it.
    ///
    /// <para>
    /// Grouping on the build alone conflates two machines that are not comparable: build
    /// 26100 is <em>both</em> Windows 11 24H2 and Windows Server 2025, and SCHANNEL defaults
    /// genuinely differ between client and server editions. Measured rather than feared — the
    /// CI runner (26100, Server 2025 Datacenter) disables TLS 1.0 and 1.1 explicitly where a
    /// Windows 11 workstation on 26200 leaves both absent. Folding those under one heading
    /// would produce the exact false consensus this command exists to prevent.
    /// </para>
    ///
    /// <para>
    /// The edition is read from <c>os.registryProductName</c>, the raw string, and not from
    /// <c>os.name</c>: the latter is derived from the build number and prefixes a server with
    /// "Windows 11", which would put the edition it is meant to distinguish behind a label
    /// that denies it.
    /// </para>
    /// </summary>
    private static string BuildOf(ScanResult report)
    {
        var inventory = report.Collectors.FirstOrDefault(collector => collector.Name == "inventory");
        var build = inventory?.Fields.GetValueOrDefault("os.build");
        var edition = inventory?.Fields.GetValueOrDefault("os.registryProductName");

        if (string.IsNullOrWhiteSpace(build))
        {
            return UnknownBuild;
        }

        return string.IsNullOrWhiteSpace(edition) ? build : $"{build} · {edition}";
    }

    private static bool Later(ScanResult candidate, ScanResult kept) =>
        Instant(candidate) > Instant(kept);

    private static DateTimeOffset Instant(ScanResult report) =>
        DateTimeOffset.TryParse(
            report.StartedAtUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at)
            ? at
            : DateTimeOffset.MinValue;
}
