using Rempart.Core.Findings;

namespace Rempart.Core.Dns;

/// <summary>
/// L'avis rendu par le test actif : les mesures brutes, et le résolveur chiffré le plus
/// rapide joignable — ou aucun. Hors du score : c'est une recommandation, pas un verdict.
/// </summary>
public sealed record DnsProbeReport(
    IReadOnlyList<DnsProbeResult> Results,
    string? RecommendedResolver,
    DnsProbeProtocol? RecommendedProtocol,
    int? RecommendedLatencyMs);

/// <summary>
/// Transforme les résultats de sonde en un avis (le plus rapide) et en constats de
/// sécurité (le DNS chiffré est-il bloqué ?). Pur, testable sans réseau.
///
/// <para>
/// La séparation est délibérée : l'observation « DNS chiffré bloqué » est un constat, elle
/// entre dans les findings ; le classement par latence est un avis, il reste hors du score
/// et ne se déguise pas en verdict.
/// </para>
/// </summary>
public static class DnsProbeAnalysis
{
    public static (DnsProbeReport Report, IReadOnlyList<Finding> Findings) Analyse(
        IReadOnlyList<DnsProbeResult> results)
    {
        var fastest = results
            .Where(result => result.Reachable && result.LatencyMs is not null)
            .OrderBy(result => result.LatencyMs)
            .FirstOrDefault();

        var report = new DnsProbeReport(
            results, fastest?.Resolver, fastest?.Protocol, fastest?.LatencyMs);

        var findings = new List<Finding>();

        if (!results.Any(result => result.Reachable))
        {
            // Rien de chiffré ne passe : le réseau force le DNS en clair.
            findings.Add(new Finding("dns-encrypted", "réseau", "DNS chiffré",
                FindingSeverity.Suspicious,
                ["Aucun résolveur DNS chiffré (DoH ni DoT) n'est joignable — la résolution "
                 + "de noms passe en clair, interceptable et falsifiable sur ce réseau."],
                Details(results)));
        }
        else
        {
            // Un protocole entièrement filtré alors que l'autre passe.
            foreach (var protocol in new[] { DnsProbeProtocol.DoH, DnsProbeProtocol.DoT })
            {
                var probes = results.Where(result => result.Protocol == protocol).ToList();
                if (probes.Count > 0 && probes.TrueForAll(result => !result.Reachable))
                {
                    findings.Add(new Finding("dns-encrypted", "réseau", protocol.ToString(),
                        FindingSeverity.Notable,
                        [$"Aucun résolveur n'est joignable en {protocol} — ce protocole "
                         + "chiffré est vraisemblablement filtré sur ce réseau."],
                        Details(probes)));
                }
            }
        }

        return (report, findings);
    }

    private static Dictionary<string, string> Details(IReadOnlyList<DnsProbeResult> results) =>
        new(StringComparer.Ordinal)
        {
            ["sondes"] = string.Join(", ", results.Select(result =>
                $"{result.Resolver}/{result.Protocol} : "
                + (result.Reachable ? $"{result.LatencyMs} ms" : "bloqué"))),
        };
}
