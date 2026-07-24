namespace Rempart.Core.Rules;

public sealed record DomainScore(
    string Domain,
    int Passed,
    int Failed,
    int Unknown,
    int NotApplicable,
    /// <summary>Null when nothing could be evaluated — a score of 0 would suggest a failure.</summary>
    int? Score);

public sealed record ScoreCard(
    int? Overall,
    IReadOnlyList<DomainScore> Domains,
    int TotalUnknown)
{
    /// <summary>
    /// A score computed on a machine where many checks could not be read is not
    /// comparable to a complete score. The report must say so.
    /// </summary>
    public bool IsPartial => TotalUnknown > 0;
}

/// <summary>
/// Aggregates verdicts into scores.
///
/// Two deliberate choices. <see cref="VerdictStatus.Unknown"/> verdicts are excluded from
/// the computation instead of being counted as passed: a check that could not be read is
/// not a satisfied check. And a fully unreadable domain scores <c>null</c>, not zero —
/// "I don't know" and "it's bad" call for different actions.
/// </summary>
public static class Scoring
{
    /// <summary>
    /// Weight per severity. Non-linear: ten minor settings do not offset one critical
    /// weakness. <c>Info</c> weighs zero — those rules document without judging.
    /// </summary>
    private static int Weight(Severity severity) => severity switch
    {
        Severity.Critical => 15,
        Severity.High => 7,
        Severity.Medium => 3,
        Severity.Low => 1,
        _ => 0,
    };

    public static ScoreCard Compute(IReadOnlyList<Verdict> verdicts)
    {
        var domains = verdicts
            .GroupBy(v => v.Domain, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => new DomainScore(
                Domain: group.Key,
                Passed: group.Count(v => v.Status == VerdictStatus.Pass),
                Failed: group.Count(v => v.Status == VerdictStatus.Fail),
                Unknown: group.Count(v => v.Status == VerdictStatus.Unknown),
                NotApplicable: group.Count(v => v.Status == VerdictStatus.NotApplicable),
                Score: Percentage(group)))
            .ToList();

        return new ScoreCard(
            Overall: Percentage(verdicts),
            Domains: domains,
            TotalUnknown: verdicts.Count(v => v.Status == VerdictStatus.Unknown));
    }

    private static int? Percentage(IEnumerable<Verdict> verdicts)
    {
        // Unknown is excluded because nothing is known; NotApplicable is excluded because
        // there was nothing to check. Counting the latter as a failure would penalize a
        // machine for a configuration it was never supposed to have.
        var evaluated = verdicts
            .Where(v => v.Status is VerdictStatus.Pass or VerdictStatus.Fail)
            .ToList();

        var possible = evaluated.Sum(v => Weight(v.Severity));
        if (possible == 0)
        {
            // Either nothing could be evaluated, or all rules are informational.
            // In both cases a number would be misleading.
            return null;
        }

        var earned = evaluated.Where(v => v.Status == VerdictStatus.Pass).Sum(v => Weight(v.Severity));
        return (int)Math.Round(100.0 * earned / possible);
    }
}
