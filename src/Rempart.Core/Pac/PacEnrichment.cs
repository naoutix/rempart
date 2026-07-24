using Rempart.Core.Findings;

namespace Rempart.Core.Pac;

/// <summary>
/// Enriches proxy findings with the actual routing of their PAC script — a network call,
/// and only when the user asks for it (ADR-001, D9), never during replay.
///
/// <para>
/// Only findings already flagged and carrying a PAC URL are fetched. A proxy imposed by
/// group policy (benign) is not: its corporate PAC legitimately routes to an internal
/// proxy, and fetching it would only confirm the expected. This is a complement to the
/// findings, not a second analysis pass.
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

        // A PAC routing to an external host receives the machine's traffic: the suspicion
        // is confirmed, so the finding is raised to suspicious. A local route, or a failed
        // fetch, aggravates nothing — "unreachable" is not "harmless".
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
