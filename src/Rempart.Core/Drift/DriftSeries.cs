using Rempart.Core.Cli;
using Rempart.Core.Rules;

namespace Rempart.Core.Drift;

/// <summary>One point on the score curve. <c>Overall</c> is null for a machine nobody could score.</summary>
public sealed record ScorePoint(
    DateTimeOffset At, int? Overall, IReadOnlyDictionary<string, int> Domains);

/// <summary>
/// A run of consecutive points evaluated by one catalog. The slope may be drawn inside a
/// segment and never across two.
/// </summary>
public sealed record DriftSegment(string RulesFingerprint, IReadOnlyList<ScorePoint> Trajectory);

/// <summary>A control that passed earlier in the series and fails at the last point.</summary>
public sealed record OpenRegression(
    string RuleId,
    string Title,
    string Domain,
    Severity Severity,

    /// <summary>The first point of the current run of failures.</summary>
    DateTimeOffset Since,

    /// <summary>
    /// Days between <see cref="Since"/> and the last point — the duration actually
    /// observed, never one extrapolated to today. The series knows nothing about what
    /// happened after its last capture, and saying otherwise would put a number on a gap.
    /// </summary>
    int DaysObserved);

/// <summary>A control that fell, was repaired, and fell again.</summary>
public sealed record UnstableControl(
    string RuleId, string Title, int Regressions, IReadOnlyList<DateTimeOffset> At);

/// <summary>Whether the series still describes the machine it is about.</summary>
public sealed record SeriesFreshness(
    DateTimeOffset Last,
    int DaysSinceLast,

    /// <summary>
    /// Median interval between points, in days. Null below three points: two captures
    /// establish one interval, which is a gap and not a rhythm.
    /// </summary>
    double? CadenceDays,

    bool Stale);

/// <summary>What one machine's series of reports amounts to.</summary>
public sealed record DriftReport(
    string Machine,
    int Points,
    DateTimeOffset First,
    DateTimeOffset Last,
    IReadOnlyList<DriftSegment> Segments,
    IReadOnlyList<OpenRegression> OpenRegressions,
    IReadOnlyList<UnstableControl> Unstable,
    SeriesFreshness Freshness,

    /// <summary>
    /// The last scan left controls unevaluable. Carried because it decides the exit code:
    /// a trajectory over a machine half of which could not be measured answers for less
    /// than it appears to.
    /// </summary>
    bool LastPointPartial);

/// <summary>
/// Reads a series of reports of one machine.
///
/// <para>
/// <b>Where <see cref="Diff.ScanDiff"/> stops.</b> Comparing two points is never rewritten
/// here. But an open regression and an unstable control cannot be obtained by chaining
/// pairs, and that is the argument for this engine rather than an exception to it: a
/// control that passes, becomes unreadable, then fails produces no pair classified as a
/// regression — <c>Pass → Unknown</c> is visibility lost, <c>Unknown → Fail</c> is
/// visibility gained, and both are right at their own scale. The fall exists only at the
/// scale of the series. So those two read the sequence of <em>known</em> states of a rule,
/// <c>Unknown</c> and <c>NotApplicable</c> removed.
/// </para>
///
/// <para>
/// Pure, and given the current instant rather than reading a clock: a moment fetched inside
/// would make a stale series untestable on a fixed set of points.
/// </para>
/// </summary>
public static class DriftSeries
{
    /// <summary>
    /// How many times its own cadence a series may fall behind before it is called stale.
    ///
    /// <para>
    /// Three tolerates one skipped interval — a machine off for a week on a weekly rhythm —
    /// without crying. It is a <em>choice and not a measurement</em>, of the same family as
    /// the 180-day data freshness threshold of ADR-002, and it is written here rather than
    /// buried in an expression so that the first real series can recalibrate it.
    /// </para>
    /// </summary>
    public const double StaleFactor = 3.0;

    /// <summary>Two falls make the pattern; one fall followed by a repair is an ordinary cycle.</summary>
    private const int UnstableFrom = 2;

    public static IReadOnlyList<DriftReport> Build(
        IEnumerable<DriftPoint> points, DateTimeOffset now) =>
        [.. points
            .GroupBy(point => point.Machine, StringComparer.Ordinal)
            .OrderBy(series => series.Key, StringComparer.Ordinal)
            .Select(series => Read(series.Key, [.. series.OrderBy(point => point.At)], now))];

    private static DriftReport Read(string machine, IReadOnlyList<DriftPoint> ordered, DateTimeOffset now)
    {
        var last = ordered[^1];
        var known = KnownStates(ordered);

        return new DriftReport(
            Machine: machine,
            Points: ordered.Count,
            First: ordered[0].At,
            Last: last.At,
            Segments: Segments(ordered),
            OpenRegressions: [.. OpenRegressions(known, last)],
            Unstable: [.. Unstable(known)],
            Freshness: Freshness(ordered, now),

            // Read from the one place the scan contract is decided, rather than restated.
            // Only Partial is carried: a last scan that broke or was refused answered 1 or 3
            // at its own time, and re-judging it here would answer for a run this command
            // did not make.
            LastPointPartial: ExitCodes.ForScan(last.Result) == ExitCode.Partial);
    }

    /// <summary>
    /// The trajectory, cut wherever the catalog changes. Percentages produced by two
    /// catalogs are not on the same scale, and a line joining them would draw a climb or a
    /// fall nothing lived through. The points are kept — it is the line that has no meaning.
    /// </summary>
    private static IReadOnlyList<DriftSegment> Segments(IReadOnlyList<DriftPoint> ordered)
    {
        var segments = new List<DriftSegment>();
        var current = new List<ScorePoint>();
        var fingerprint = ordered[0].RulesFingerprint;

        foreach (var point in ordered)
        {
            if (!string.Equals(point.RulesFingerprint, fingerprint, StringComparison.Ordinal))
            {
                segments.Add(new DriftSegment(fingerprint, current));
                current = [];
                fingerprint = point.RulesFingerprint;
            }

            current.Add(new ScorePoint(
                point.At,
                point.Result.Score?.Overall,
                point.Result.Score?.Domains
                    .Where(domain => domain.Score is not null)
                    .ToDictionary(domain => domain.Domain, domain => domain.Score!.Value, StringComparer.Ordinal)
                    ?? new Dictionary<string, int>(StringComparer.Ordinal)));
        }

        segments.Add(new DriftSegment(fingerprint, current));
        return segments;
    }

    /// <summary>
    /// Each rule's sequence of <em>measured</em> postures. <c>Unknown</c> and
    /// <c>NotApplicable</c> are dropped here, once, so that every reading below is spared
    /// deciding again what an unreadable point means: it means nothing was measured, so it
    /// neither dates a fall nor interrupts one.
    /// </summary>
    private static Dictionary<string, List<(DateTimeOffset At, Verdict Verdict)>> KnownStates(
        IReadOnlyList<DriftPoint> ordered)
    {
        var known = new Dictionary<string, List<(DateTimeOffset, Verdict)>>(StringComparer.OrdinalIgnoreCase);

        foreach (var point in ordered)
        {
            foreach (var verdict in point.Result.Verdicts)
            {
                if (verdict.Status is not (VerdictStatus.Pass or VerdictStatus.Fail))
                {
                    continue;
                }

                if (!known.TryGetValue(verdict.RuleId, out var states))
                {
                    known[verdict.RuleId] = states = [];
                }

                states.Add((point.At, verdict));
            }
        }

        return known;
    }

    private static IEnumerable<OpenRegression> OpenRegressions(
        Dictionary<string, List<(DateTimeOffset At, Verdict Verdict)>> known, DriftPoint last)
    {
        foreach (var (ruleId, states) in known.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            // The rule must be failing at the last point, measured there. A rule the last
            // scan did not evaluate — dropped from the catalog, or unreadable — is not
            // reported as still failing: that would be an accusation with no measurement
            // behind it.
            var atLast = last.Result.Verdicts
                .FirstOrDefault(v => string.Equals(v.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));

            if (atLast?.Status != VerdictStatus.Fail)
            {
                continue;
            }

            var since = states.Count - 1;
            while (since > 0 && states[since - 1].Verdict.Status == VerdictStatus.Fail)
            {
                since--;
            }

            // Never seen passing: a control that has always failed is not a fall, and
            // dating one would invent the day it happened.
            if (since == 0)
            {
                continue;
            }

            yield return new OpenRegression(
                ruleId,
                atLast.Title,
                atLast.Domain,
                atLast.Severity,
                states[since].At,
                (int)(last.At - states[since].At).TotalDays);
        }
    }

    private static IEnumerable<UnstableControl> Unstable(
        Dictionary<string, List<(DateTimeOffset At, Verdict Verdict)>> known)
    {
        foreach (var (ruleId, states) in known.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            var falls = new List<DateTimeOffset>();

            for (var i = 1; i < states.Count; i++)
            {
                if (states[i - 1].Verdict.Status == VerdictStatus.Pass
                    && states[i].Verdict.Status == VerdictStatus.Fail)
                {
                    falls.Add(states[i].At);
                }
            }

            if (falls.Count >= UnstableFrom)
            {
                yield return new UnstableControl(ruleId, states[^1].Verdict.Title, falls.Count, falls);
            }
        }
    }

    private static SeriesFreshness Freshness(IReadOnlyList<DriftPoint> ordered, DateTimeOffset now)
    {
        var last = ordered[^1].At;
        var daysSinceLast = (int)(now - last).TotalDays;

        // Two points establish one interval, which is a gap and not a rhythm. Below three,
        // nothing is claimed rather than something guessed.
        if (ordered.Count < 3)
        {
            return new SeriesFreshness(last, daysSinceLast, CadenceDays: null, Stale: false);
        }

        var intervals = new List<double>();
        for (var i = 1; i < ordered.Count; i++)
        {
            intervals.Add((ordered[i].At - ordered[i - 1].At).TotalDays);
        }

        intervals.Sort();
        var middle = intervals.Count / 2;
        var cadence = intervals.Count % 2 == 1
            ? intervals[middle]
            : (intervals[middle - 1] + intervals[middle]) / 2;

        return new SeriesFreshness(
            last,
            daysSinceLast,
            cadence,
            Stale: cadence > 0 && daysSinceLast > cadence * StaleFactor);
    }
}
