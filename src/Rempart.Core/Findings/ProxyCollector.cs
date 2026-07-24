using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Proxy and PAC configuration of the machine, per scope.
///
/// <para>
/// A proxy imposed by group policy is the expected enterprise case: inventoried, not
/// alarmed on. A proxy set without such a constraint intercepts traffic; an AutoConfigURL
/// (PAC) rewrites all routing, and an http PAC hosted outside the machine's control is
/// the very shape of a hijack. No network call: only the URL is judged, never its
/// content (that will be an opt-in enrichment, cf. PR-B).
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
        // A PAC imposed by policy is the expected enterprise case.
        if (policyImposed)
        {
            return FindingSeverity.Benign;
        }

        // Cleartext http to an external host: alterable in transit, outside the machine's
        // control — the shape of a hijack. https, or a local/file PAC, is still worth
        // reporting without being suspicious.
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
