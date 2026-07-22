using Rempart.Core.Findings;

namespace Rempart.Core.Pac;

/// <summary>
/// Enrichit les constats proxy du routage réel de leur script PAC — un appel réseau, et
/// uniquement quand l'utilisateur le demande (ADR-001, D9), jamais en rejeu.
///
/// <para>
/// Seuls les constats déjà signalés et porteurs d'une URL de PAC sont récupérés. Un proxy
/// imposé par stratégie de groupe (bénin) ne l'est pas : son PAC d'entreprise route
/// légitimement vers un proxy interne, et le récupérer ne ferait que confirmer l'attendu.
/// C'est un complément aux constats, pas une seconde passe d'analyse.
/// </para>
/// </summary>
public static class PacEnrichment
{
    public static IReadOnlyList<Finding> WithRouting(
        IReadOnlyList<Finding> findings, IPacFetcher fetcher) =>
        [.. findings.Select(finding => Enrich(finding, fetcher))];

    private static Finding Enrich(Finding finding, IPacFetcher fetcher)
    {
        if (finding.Severity == FindingSeverity.Benign
            || !finding.Details.TryGetValue("pac", out var pacUrl)
            || pacUrl.Length == 0)
        {
            return finding;
        }

        var analysis = fetcher.Fetch(pacUrl);

        var details = finding.Details.ToDictionary(
            entry => entry.Key, entry => entry.Value, StringComparer.Ordinal);
        details["pac-route"] = analysis.Summary;

        // Un PAC qui route vers un hôte externe reçoit le trafic de la machine : le soupçon
        // se confirme, on hisse à suspect. Une route locale, ou une récupération en échec,
        // n'aggrave rien — « injoignable » n'est pas « inoffensif ».
        var external = analysis.Proxies.Where(IsExternal).ToList();
        if (external.Count > 0 && finding.Severity < FindingSeverity.Suspicious)
        {
            return finding with
            {
                Severity = FindingSeverity.Suspicious,
                Reasons =
                [
                    $"Le script PAC route le trafic vers {string.Join(", ", external)} — "
                    + "un proxy externe qui reçoit tout le trafic de la machine.",
                    .. finding.Reasons,
                ],
                Details = details,
            };
        }

        return finding with { Details = details };
    }

    private static bool IsExternal(string endpoint)
    {
        var host = endpoint.Contains(':') ? endpoint[..endpoint.LastIndexOf(':')] : endpoint;
        return host.Length > 0
            && !host.StartsWith("127.", StringComparison.Ordinal)
            && !host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            && host is not ("::1" or "[::1]");
    }
}
