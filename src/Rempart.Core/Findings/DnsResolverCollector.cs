using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Résolveurs DNS configurés, par interface.
///
/// <para>
/// Un résolveur reçu du DHCP est celui du réseau : on l'inventorie sans le juger. Un
/// résolveur posé statiquement est un choix — et le détournement DNS opère là, en
/// écrivant un serveur qu'il contrôle par-dessus celui du réseau. On relève donc les
/// résolveurs statiques que l'on ne reconnaît pas ; ceux d'un résolveur public connu, ou
/// d'un résolveur local (la boucle, un filtre installé exprès), restent bénins — c'est une
/// configuration délibérée courante sur une machine durcie.
/// </para>
/// </summary>
public sealed class DnsResolverCollector : IFindingCollector
{
    public string Name => "dns-resolver";

    /// <summary>
    /// Résolveurs publics dont l'usage délibéré est répandu. Un résolveur statique qui n'en
    /// est pas mérite un regard ; la liste ne prétend pas à l'exhaustivité, seulement à
    /// couvrir les choix légitimes les plus fréquents.
    /// </summary>
    private static readonly HashSet<string> WellKnownResolvers = new(StringComparer.Ordinal)
    {
        "1.1.1.1", "1.0.0.1",              // Cloudflare
        "8.8.8.8", "8.8.4.4",              // Google
        "9.9.9.9", "149.112.112.112",      // Quad9
        "208.67.222.222", "208.67.220.220", // OpenDNS
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
    };

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var iface in providers.Dns.Read())
        {
            if (iface.StaticServers.Count > 0)
            {
                findings.Add(JudgeStatic(iface));
            }
            else if (iface.DhcpServers.Count > 0)
            {
                findings.Add(new Finding("dns-resolver", iface.Id,
                    string.Join(", ", iface.DhcpServers), FindingSeverity.Benign, [],
                    Details("DHCP", iface.DhcpServers)));
            }
        }

        return findings;
    }

    private static Finding JudgeStatic(DnsInterface iface)
    {
        var unrecognised = iface.StaticServers
            .Where(server => !WellKnownResolvers.Contains(server) && !IsLocal(server))
            .ToList();

        var details = Details("statique", iface.StaticServers);

        if (unrecognised.Count == 0)
        {
            return new Finding("dns-resolver", iface.Id,
                string.Join(", ", iface.StaticServers), FindingSeverity.Benign, [], details);
        }

        return new Finding("dns-resolver", iface.Id,
            string.Join(", ", iface.StaticServers), FindingSeverity.Notable,
            [$"Résolveur DNS statique non reconnu ({string.Join(", ", unrecognised)}) — un "
             + "serveur posé par-dessus celui du réseau est le levier d'un détournement DNS."],
            details);
    }

    private static bool IsLocal(string server) =>
        server.StartsWith("127.", StringComparison.Ordinal) || server is "::1";

    private static Dictionary<string, string> Details(string origin, IReadOnlyList<string> servers) =>
        new(StringComparer.Ordinal)
        {
            ["origine"] = origin,
            ["résolveurs"] = string.Join(", ", servers),
        };
}
