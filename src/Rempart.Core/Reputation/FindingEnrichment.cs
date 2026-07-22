using Rempart.Core.Findings;

namespace Rempart.Core.Reputation;

/// <summary>La réputation d'une empreinte auprès d'un service tiers.</summary>
public sealed record HashReputation(int Malicious, int Total);

/// <summary>
/// Ce qu'une consultation a rendu : une réputation quand le service connaît l'empreinte,
/// et toujours un résumé lisible — « 0/72 », « inconnu », « clé refusée ».
///
/// <see cref="Reputation"/> nul ne veut pas dire « sûr » : le fichier peut être inconnu
/// du service, ou la consultation avoir échoué. Le résumé dit lequel.
/// </summary>
public sealed record ReputationResult(HashReputation? Reputation, string Summary);

/// <summary>
/// Consulte la réputation d'une empreinte. Abstrait pour que l'enrichissement se teste
/// sans réseau ni clé d'API (ADR-001, D5) : une source factice rend des verdicts connus.
/// </summary>
public interface IReputationSource
{
    ReputationResult Lookup(string sha256);
}

/// <summary>
/// Enrichit les constats de la réputation de leur binaire — le seul enrichissement qui
/// sorte sur le réseau, et uniquement quand l'utilisateur le demande (ADR-001, D9).
///
/// <para>
/// Seuls les constats déjà signalés et porteurs d'une empreinte sont consultés. Un
/// binaire bénin et signé ne l'est pas : sa signature atteste déjà de son origine, et
/// interroger des centaines de fichiers sains épuiserait le quota d'API sans rien
/// apprendre. C'est un complément aux constats, pas une seconde passe d'analyse.
/// </para>
/// </summary>
public static class FindingEnrichment
{
    public static IReadOnlyList<Finding> WithReputation(
        IReadOnlyList<Finding> findings, IReputationSource source) =>
        [.. findings.Select(finding => Enrich(finding, source))];

    private static Finding Enrich(Finding finding, IReputationSource source)
    {
        if (finding.Severity == FindingSeverity.Benign
            || !finding.Details.TryGetValue("sha256", out var sha256)
            || sha256.Length == 0)
        {
            return finding;
        }

        var result = source.Lookup(sha256);

        var details = finding.Details.ToDictionary(
            entry => entry.Key, entry => entry.Value, StringComparer.Ordinal);
        details["virustotal"] = result.Summary;

        // Une détection confirme un soupçon : on hisse à suspect et on le dit en tête des
        // raisons. Une empreinte inconnue ou une consultation en échec n'abaisse rien —
        // « inconnu de VirusTotal » n'est pas « sain ».
        if (result.Reputation is { Malicious: > 0 } reputation)
        {
            return finding with
            {
                Severity = FindingSeverity.Suspicious,
                Reasons =
                [
                    $"Signalé malveillant par {reputation.Malicious} moteur(s) sur "
                    + $"{reputation.Total} (VirusTotal).",
                    .. finding.Reasons,
                ],
                Details = details,
            };
        }

        return finding with { Details = details };
    }
}
