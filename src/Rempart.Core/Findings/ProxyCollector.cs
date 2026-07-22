using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Configuration proxy et PAC de la machine, par portée.
///
/// <para>
/// Un proxy imposé par stratégie de groupe est le cas d'entreprise attendu : inventorié,
/// pas alarmé. Un proxy posé sans contrainte intercepte le trafic ; un AutoConfigURL (PAC)
/// réécrit tout le routage, et un PAC http hébergé hors du contrôle de la machine est la
/// forme même d'un détournement. Aucun appel réseau : seule l'URL est jugée, jamais son
/// contenu (ce sera un enrichissement opt-in, cf. PR-B).
/// </para>
/// </summary>
public sealed class ProxyCollector : IFindingCollector
{
    public string Name => "proxy";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var config = providers.Proxy.Read();
        var findings = new List<Finding>();

        Judge(findings, "WinINET", config.WinInet, config.PolicyImposed);
        Judge(findings, "WinHTTP", config.WinHttp, config.PolicyImposed);

        return findings;
    }

    private static void Judge(
        List<Finding> findings, string scope, ProxyScope proxy, bool policyImposed)
    {
        var hasServer = proxy.Enabled && !string.IsNullOrWhiteSpace(proxy.Server);
        var hasPac = !string.IsNullOrWhiteSpace(proxy.AutoConfigUrl);

        if (!hasServer && !hasPac)
        {
            return;
        }

        var severity = FindingSeverity.Benign;
        var reasons = new List<string>();

        if (hasServer && !ServerIsLocal(proxy.Server!) && !policyImposed)
        {
            severity = FindingSeverity.Notable;
            reasons.Add(
                $"Proxy {proxy.Server} non imposé par stratégie — un serveur posé sans "
                + "contrainte intercepte le trafic.");
        }

        if (hasPac)
        {
            var pacSeverity = JudgePac(proxy.AutoConfigUrl!, policyImposed);
            if (pacSeverity > severity)
            {
                severity = pacSeverity;
            }

            if (pacSeverity == FindingSeverity.Suspicious)
            {
                reasons.Add(
                    $"PAC {proxy.AutoConfigUrl} en http externe non imposé — un script de "
                    + "configuration en clair, altérable et hébergé hors du contrôle de la "
                    + "machine, peut réécrire tout le routage.");
            }
            else if (pacSeverity == FindingSeverity.Notable)
            {
                reasons.Add(
                    $"PAC {proxy.AutoConfigUrl} — un script de configuration réécrit le "
                    + "routage ; à connaître.");
            }
        }

        var origin = policyImposed ? "imposé GPO"
            : hasServer && ServerIsLocal(proxy.Server!) ? "local"
            : "utilisateur";

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["portée"] = scope,
            ["origine"] = origin,
        };
        if (hasServer)
        {
            details["serveur"] = proxy.Server!;
        }
        if (hasPac)
        {
            details["pac"] = proxy.AutoConfigUrl!;
        }
        if (proxy.Bypass.Count > 0)
        {
            details["exclusions"] = string.Join(", ", proxy.Bypass);
        }

        findings.Add(new Finding(
            "proxy", scope, proxy.AutoConfigUrl ?? proxy.Server ?? scope, severity, reasons, details));
    }

    private static bool ServerIsLocal(string server) =>
        server.Contains("127.0.0.1", StringComparison.Ordinal)
        || server.Contains("localhost", StringComparison.OrdinalIgnoreCase)
        || server.Contains("[::1]", StringComparison.Ordinal);

    private static FindingSeverity JudgePac(string url, bool policyImposed)
    {
        // Un PAC imposé par stratégie est le cas d'entreprise attendu.
        if (policyImposed)
        {
            return FindingSeverity.Benign;
        }

        // http en clair vers un hôte externe : altérable en transit, hors du contrôle de
        // la machine — la forme d'un détournement. https, ou un PAC local/file, reste à
        // signaler sans être suspect.
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            && !IsLocalHost(uri.Host))
        {
            return FindingSeverity.Suspicious;
        }

        return FindingSeverity.Notable;
    }

    private static bool IsLocalHost(string host) =>
        host.Length == 0
        || host.StartsWith("127.", StringComparison.Ordinal)
        || host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        || host is "::1";
}
