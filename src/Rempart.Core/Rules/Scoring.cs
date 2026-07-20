namespace Rempart.Core.Rules;

public sealed record DomainScore(
    string Domain,
    int Passed,
    int Failed,
    int Unknown,
    int NotApplicable,
    /// <summary>Null quand rien n'a pu être évalué — un score de 0 laisserait croire à un échec.</summary>
    int? Score);

public sealed record ScoreCard(
    int? Overall,
    IReadOnlyList<DomainScore> Domains,
    int TotalUnknown)
{
    /// <summary>
    /// Un score calculé sur une machine où beaucoup de contrôles n'ont pas pu être lus
    /// n'est pas comparable à un score complet. Le rapport doit le dire.
    /// </summary>
    public bool IsPartial => TotalUnknown > 0;
}

/// <summary>
/// Agrège des verdicts en scores.
///
/// Deux partis pris. Les verdicts <see cref="VerdictStatus.Unknown"/> sortent du calcul
/// au lieu d'être comptés comme réussis : un contrôle qu'on n'a pas pu lire n'est pas un
/// contrôle satisfait. Et un domaine entièrement illisible vaut <c>null</c>, pas zéro —
/// « je ne sais pas » et « c'est mauvais » appellent des actions différentes.
/// </summary>
public static class Scoring
{
    /// <summary>
    /// Pondération par sévérité. Non linéaire : dix réglages mineurs ne compensent pas
    /// une faiblesse critique. <c>Info</c> pèse zéro — ces règles documentent sans juger.
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
        // Unknown sort du calcul faute de savoir ; NotApplicable en sort parce qu'il
        // n'y avait rien à vérifier. Compter ce dernier comme un échec pénaliserait une
        // machine pour ne pas être ce qu'elle n'a jamais eu à être.
        var evaluated = verdicts
            .Where(v => v.Status is VerdictStatus.Pass or VerdictStatus.Fail)
            .ToList();

        var possible = evaluated.Sum(v => Weight(v.Severity));
        if (possible == 0)
        {
            // Soit rien n'a pu être évalué, soit toutes les règles sont informatives.
            // Dans les deux cas, un chiffre serait trompeur.
            return null;
        }

        var earned = evaluated.Where(v => v.Status == VerdictStatus.Pass).Sum(v => Weight(v.Severity));
        return (int)Math.Round(100.0 * earned / possible);
    }
}
