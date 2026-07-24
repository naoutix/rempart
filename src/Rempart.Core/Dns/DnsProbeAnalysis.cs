using Rempart.Core.Findings;

namespace Rempart.Core.Dns;

/// <summary>
/// What the active test returned: the raw measurements, and the fastest reachable
/// encrypted resolver — or none. Kept out of the score: a recommendation, not a verdict.
/// </summary>
public sealed record DnsProbeReport(
    IReadOnlyList<DnsProbeResult> Results,
    string? RecommendedResolver,
    DnsProbeProtocol? RecommendedProtocol,
    int? RecommendedLatencyMs);

/// <summary>
/// Turns probe results into advice (the fastest resolver) and into security findings
/// (is encrypted DNS blocked?). Pure, testable without network access.
///
/// <para>
/// The separation is deliberate: the observation "encrypted DNS is blocked" is a fact and
/// belongs in the findings; the latency ranking is advice — it stays out of the score and
/// does not masquerade as a verdict.
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
            // Nothing encrypted gets through: the network forces DNS into the clear.
            findings.Add(new Finding("dns-encrypted", "réseau", "DNS chiffré",
                FindingSeverity.Suspicious,
                ["Aucun résolveur DNS chiffré (DoH ni DoT) n'est joignable — la résolution "
                 + "de noms passe en clair, interceptable et falsifiable sur ce réseau."],
                Details(results)));
        }
        else
        {
            // One protocol entirely filtered while the other gets through.
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
