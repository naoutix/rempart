using Rempart.Core.Drift;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// Series built by hand, for the readers that consume one.
///
/// <para>
/// Shared rather than copied into each test class: two copies of a fixture drift apart,
/// and the copy that stops resembling what <see cref="DriftSeries.Build"/> produces is the
/// one that makes a renderer look correct against a shape no series ever has. Every report
/// here is one <c>Build</c> could return — three points, one segment, a cadence.
/// </para>
/// </summary>
internal static class DriftFixtures
{
    public static DateTimeOffset Day(int day) => new(2026, 1, day, 9, 15, 0, TimeSpan.Zero);

    public static DriftReport Clean(string machine = "POSTE-01") => new(
        Machine: machine,
        Points: 3,
        First: Day(1),
        Last: Day(15),
        Segments:
        [
            new DriftSegment("82:aaa",
            [
                new ScorePoint(Day(1), 60, Domains(60)),
                new ScorePoint(Day(8), 64, Domains(64)),
                new ScorePoint(Day(15), 70, Domains(70)),
            ]),
        ],
        OpenRegressions: [],
        Unstable: [],
        Freshness: new SeriesFreshness(Day(15), 1, 7, Stale: false),
        LastPointPartial: false);

    public static DriftReport Drifted(string title = "Pare-feu du profil Public") =>
        Clean() with
        {
            OpenRegressions =
            [
                new("WIN-FW-001", title, "réseau", Severity.High, Day(8), 7),
            ],
        };

    public static DriftReport Unstable(string title = "Protection en temps réel") =>
        Clean() with
        {
            Unstable = [new("WIN-DEF-002", title, 2, [Day(8), Day(15)])],
        };

    public static DriftReport Stale() => Clean() with
    {
        Freshness = new SeriesFreshness(Day(15), 97, 7, Stale: true),
    };

    public static DriftReport PartialLastPoint() => Clean() with { LastPointPartial = true };

    private static Dictionary<string, int> Domains(int score) =>
        new(StringComparer.Ordinal) { ["réseau"] = score, ["defender"] = score };
}
