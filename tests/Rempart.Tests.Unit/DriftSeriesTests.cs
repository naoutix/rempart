using System.Globalization;
using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Drift;
using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Reading a series rather than a pair.
///
/// What is pinned here is only what a pair cannot answer: the slope and where it may not
/// be drawn, the date a control started failing, a control that keeps falling back, and
/// the series having stopped being fed. Everything a single comparison already says stays
/// in <see cref="ScanDiffTests"/>, and this engine calls that one rather than restating it.
/// </summary>
public sealed class DriftSeriesTests
{
    // ---- the series key ----------------------------------------------------

    /// <summary>
    /// The key a series groups on is the diff's own notion of a machine, so the two can
    /// never disagree about which reports belong to one curve. It survives anonymisation:
    /// <c>Anonymiser.Hash</c> is an unsalted SHA-256 and idempotent, so two captures of one
    /// machine carry the same hashed name. A salt added later would cut every series into
    /// isolated points, and this test is what would say so.
    /// </summary>
    [Fact]
    public void An_anonymised_machine_keeps_one_key_across_captures()
    {
        var january = Scan() with { Collectors = [Inventory(Anonymiser.Hash("POSTE-01"))] };
        var february = Scan() with { Collectors = [Inventory(Anonymiser.Hash("POSTE-01"))] };

        Assert.Equal(ScanDiff.MachineName(january), ScanDiff.MachineName(february));
        Assert.Equal(Anonymiser.Hash("POSTE-01"), Anonymiser.Hash(Anonymiser.Hash("POSTE-01")));
    }

    // ---- what is, and is not, a point --------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("pas une date")]
    public void A_report_without_a_readable_date_is_not_a_series_point(string started)
    {
        Assert.Null(DriftPoint.From(Scan() with { StartedAtUtc = started }));
    }

    [Fact]
    public void A_series_point_carries_the_machine_the_date_and_the_catalog()
    {
        var point = DriftPoint.From(Scan());

        Assert.NotNull(point);
        Assert.Equal("POSTE-01", point.Machine);
        Assert.Equal("82:aaa", point.RulesFingerprint);
        Assert.Equal(At("2026-07-24"), point.At);
    }

    // ---- trajectory --------------------------------------------------------

    /// <summary>
    /// Two fingerprints in one series cut the slope. A percentage produced by one catalog
    /// and a percentage produced by another are not on the same scale, and subtracting them
    /// would draw a climb or a fall nothing lived through. The points are kept: it is the
    /// line between them that has no meaning, not the measurements.
    /// </summary>
    [Fact]
    public void A_catalog_change_cuts_the_slope_and_keeps_the_points()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", score: 60, catalog: "82:aaa"),
            Point("2026-02-01", score: 64, catalog: "82:aaa"),
            Point("2026-03-01", score: 90, catalog: "91:bbb"),
        ], At("2026-03-02")));

        Assert.Equal(2, report.Segments.Count);
        Assert.Equal(["82:aaa", "91:bbb"], report.Segments.Select(s => s.RulesFingerprint));
        Assert.Equal(2, report.Segments[0].Trajectory.Count);
        Assert.Equal(3, report.Points);
    }

    /// <summary>
    /// Two machines in one folder are two series. Nothing in a fleet folder says the
    /// reports belong to the same machine, and drawing one curve through both would invent
    /// a posture no machine ever had.
    /// </summary>
    [Fact]
    public void Two_machines_are_two_series()
    {
        var reports = DriftSeries.Build(
        [
            Point("2026-01-02", machine: "POSTE-02"),
            Point("2026-01-01", machine: "POSTE-01"),
        ], At("2026-01-03"));

        Assert.Equal(2, reports.Count);
        Assert.Equal(["POSTE-01", "POSTE-02"], reports.Select(r => r.Machine));
    }

    /// <summary>
    /// Reports are found in whatever order the file system hands them over, so the series
    /// sorts. A trajectory built in directory order would draw a curve out of a shuffle.
    /// </summary>
    [Fact]
    public void Points_are_ordered_by_date_and_not_by_the_order_they_arrived()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-03-01", score: 90),
            Point("2026-01-01", score: 60),
            Point("2026-02-01", score: 64),
        ], At("2026-03-02")));

        Assert.Equal([60, 64, 90], Assert.Single(report.Segments).Trajectory.Select(p => p.Overall));
        Assert.Equal(At("2026-01-01"), report.First);
        Assert.Equal(At("2026-03-01"), report.Last);
    }

    /// <summary>
    /// A machine nobody could score keeps its place on the curve with no score, rather
    /// than being dropped: an unscored point is not a missing scan, and hiding it would
    /// join the two scores on either side into a slope that skipped it.
    /// </summary>
    [Fact]
    public void An_unscored_point_stays_on_the_curve_without_a_score()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", score: 60),
            Point("2026-02-01", score: null),
            Point("2026-03-01", score: 64),
        ], At("2026-03-02")));

        Assert.Equal([60, null, 64], Assert.Single(report.Segments).Trajectory.Select(p => p.Overall));
    }

    // ---- open regressions --------------------------------------------------

    [Fact]
    public void A_control_that_failed_and_was_fixed_is_not_an_open_regression()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
            Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        ], At("2026-03-02")));

        Assert.Empty(report.OpenRegressions);
    }

    [Fact]
    public void An_open_regression_is_dated_from_the_point_it_started_failing()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
            Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        ], At("2026-03-02")));

        var open = Assert.Single(report.OpenRegressions);
        Assert.Equal("WIN-X-001", open.RuleId);
        Assert.Equal(At("2026-02-01"), open.Since);
        Assert.Equal(28, open.DaysObserved);
    }

    /// <summary>
    /// A control that was never seen passing is not a regression: it is a control that has
    /// always failed, and calling it one would date a fall that never happened.
    /// </summary>
    [Fact]
    public void A_control_failing_since_the_first_point_is_not_a_regression()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        ], At("2026-02-02")));

        Assert.Empty(report.OpenRegressions);
    }

    /// <summary>
    /// The reason this engine exists rather than a chain of pairwise comparisons.
    /// <c>Pass → Unknown</c> is visibility lost and <c>Unknown → Fail</c> is visibility
    /// gained, so no pair here is ever classified as a regression — and yet the control
    /// passed in January and fails in March. The fall exists only at the scale of the
    /// series, which is why the sequence of known states is what gets read.
    /// </summary>
    [Fact]
    public void A_fall_across_an_unreadable_point_is_still_a_fall()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Unknown)]),
            Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        ], At("2026-03-02")));

        Assert.Equal(At("2026-03-01"), Assert.Single(report.OpenRegressions).Since);
    }

    /// <summary>
    /// A rule the last scan did not evaluate at all has no open regression: the catalog
    /// may simply no longer carry it, and reporting a control nobody measured as still
    /// failing would be an accusation with no measurement behind it.
    /// </summary>
    [Fact]
    public void A_rule_absent_from_the_last_point_is_not_reported_as_still_failing()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
            Point("2026-03-01", rules: [("WIN-Y-002", VerdictStatus.Pass)]),
        ], At("2026-03-02")));

        Assert.Empty(report.OpenRegressions);
    }

    // ---- instability -------------------------------------------------------

    /// <summary>
    /// The second fall is what makes the pattern: one fall followed by a repair is an
    /// ordinary cycle, two say the repair does not hold. Said once with its dates, rather
    /// than recounted by every pair that crosses it.
    /// </summary>
    [Fact]
    public void A_control_that_falls_twice_is_named_unstable_once()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
            Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-04-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        ], At("2026-04-02")));

        var unstable = Assert.Single(report.Unstable);
        Assert.Equal(2, unstable.Regressions);
        Assert.Equal([At("2026-02-01"), At("2026-04-01")], unstable.At);
    }

    [Fact]
    public void One_fall_is_not_instability()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        ], At("2026-02-02")));

        Assert.Empty(report.Unstable);
    }

    // ---- freshness ---------------------------------------------------------

    /// <summary>
    /// Below three points no cadence is observable, so nothing is claimed — two scans a
    /// year apart are not a stale series, they are a series nobody can read a rhythm in.
    /// </summary>
    [Fact]
    public void Under_three_points_no_cadence_is_claimed()
    {
        var report = Single(DriftSeries.Build(
            [Point("2026-01-01"), Point("2026-02-01")], At("2026-12-01")));

        Assert.Null(report.Freshness.CadenceDays);
        Assert.False(report.Freshness.Stale);
    }

    /// <summary>
    /// Three times the observed cadence, which tolerates one skipped interval without
    /// crying. The bounds are picked to pin the factor from both sides: on a weekly series
    /// the threshold is 21 days, and 17 then 25 straddle it. A factor of 2 would make the
    /// first assertion fail (17 &gt; 14), a factor of 4 the second (25 &lt; 28) — loose
    /// bounds would have held for any factor at all.
    /// </summary>
    [Fact]
    public void A_series_that_stopped_at_three_times_its_own_cadence_is_stale()
    {
        DriftPoint[] Weekly() =>
            [Point("2026-01-01"), Point("2026-01-08"), Point("2026-01-15")];

        Assert.False(Single(DriftSeries.Build(Weekly(), At("2026-02-01"))).Freshness.Stale);
        Assert.True(Single(DriftSeries.Build(Weekly(), At("2026-02-09"))).Freshness.Stale);
    }

    [Fact]
    public void Freshness_says_how_long_it_has_been_and_at_what_cadence()
    {
        var freshness = Single(DriftSeries.Build(
        [
            Point("2026-01-01"), Point("2026-01-08"), Point("2026-01-15"),
        ], At("2026-01-22"))).Freshness;

        Assert.Equal(At("2026-01-15"), freshness.Last);
        Assert.Equal(7, freshness.DaysSinceLast);
        Assert.Equal(7, freshness.CadenceDays);
    }

    /// <summary>
    /// The last scan having left controls unevaluable is carried by the series, because it
    /// decides the exit code a scheduler reads: a trajectory computed over a machine half
    /// of which could not be measured answers for less than it appears to.
    /// </summary>
    [Fact]
    public void An_unevaluable_last_point_is_carried_to_the_report()
    {
        var report = Single(DriftSeries.Build(
        [
            Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
            Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Unknown)]),
        ], At("2026-02-02")));

        Assert.True(report.LastPointPartial);
    }

    // ---- helpers -----------------------------------------------------------

    private static DateTimeOffset At(string day) =>
        DateTimeOffset.Parse(
            day + "T09:15:00Z", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static DriftPoint Point(
        string day,
        int? score = null,
        string catalog = "82:aaa",
        string machine = "POSTE-01",
        (string Id, VerdictStatus Status)[]? rules = null) =>
        DriftPoint.From(Scan() with
        {
            StartedAtUtc = day + "T09:15:00Z",
            RulesFingerprint = catalog,
            Collectors = [Inventory(machine)],
            Verdicts = [.. (rules ?? []).Select(r => Rule(r.Id, r.Status))],
            Score = score is { } overall ? Card(overall) : null,
        })!;

    private static DriftReport Single(IReadOnlyList<DriftReport> reports) => Assert.Single(reports);

    private static ScanResult Scan() => new(
        ToolVersion: "1.1.0",
        StartedAtUtc: "2026-07-24T09:15:00Z",
        Collectors: [Inventory("POSTE-01")],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "82:aaa",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));

    private static CollectorResult Inventory(string machine) =>
        new("inventory", CollectorStatus.Ok,
            new Dictionary<string, string?> { ["machine.name"] = machine }, []);

    private static Verdict Rule(string id, VerdictStatus status) =>
        new(id, $"Contrôle {id}", Severity.High, "réseau", status, "0", "1");

    private static ScoreCard Card(int overall) =>
        new(overall, [new DomainScore("réseau", 1, 0, 0, 0, overall)], 0);
}
