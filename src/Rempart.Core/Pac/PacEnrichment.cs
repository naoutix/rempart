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
///
/// <para>
/// This runs on a finished scan, one step before it is serialised, which is what makes
/// <see cref="Fetched"/> necessary: a <c>file://</c> AutoConfigURL made the live fetcher
/// throw, the exception crossed this method untouched, and the whole audit was lost over
/// a proxy URL. The guard sits here rather than only in that fetcher, so the invariant
/// holds for whichever <see cref="IPacFetcher"/> is plugged in — a failed fetch is a line
/// in the report, never a scan thrown away.
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

        var analysis = Fetched(fetcher, pacUrl);

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

    /// <summary>
    /// The fetch, and whatever it throws turned into the reading it should have been.
    /// Untyped on purpose: the exception that destroyed a scan here was one absent from a
    /// hand-kept list of exception types, and any list would be one more thing to keep
    /// right. Nothing about a PAC that could not be read is worth an audit.
    /// </summary>
    private static PacAnalysis Fetched(IPacFetcher fetcher, string pacUrl)
    {
        try
        {
            return fetcher.Fetch(pacUrl);
        }
        catch (Exception ex)
        {
            return new([], $"PAC injoignable : {ex.Message}");
        }
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
