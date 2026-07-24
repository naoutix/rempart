using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Mappings in the <c>hosts</c> file.
///
/// <para>
/// The <c>hosts</c> file comes before DNS: whatever it declares wins. Two opposite
/// gestures can be read there. A <b>redirection</b> — a domain pointed at a routable
/// address — short-circuits resolution towards a chosen machine; aimed at an update or
/// an authentication, it is a hijack. A <b>block</b> — a domain pointed at a null
/// address — neutralises the domain; that is an ad blocker's gesture, harmless, unless
/// what it neutralises happens to be an update or a protection.
/// </para>
///
/// <para>
/// Redirections are rare and reported one by one. Blocks number in the thousands in an
/// ad-blocking list: enumerating them would drown the report, so they are aggregated
/// into a single finding — unless a critical domain is hit, which reopens the count.
/// </para>
/// </summary>
public sealed class HostsFileCollector : IFindingCollector
{
    public string Name => "hosts-entry";

    private static readonly string[] NullRoutes = ["0.0.0.0", "127.0.0.1", "::1", "::"];

    /// <summary>
    /// Fragments of domains whose neutralisation or hijacking has consequences: Windows
    /// updates, protection, activation, authentication. Blocking an update prevents a
    /// flaw from being fixed; redirecting an authentication captures it.
    /// </summary>
    private static readonly string[] CriticalFragments =
    [
        "windowsupdate", "update.microsoft", "download.windowsupdate", "defender",
        "smartscreen", "wdcp", "login.live", "login.microsoftonline", "activation",
    ];

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();
        var blocked = new List<string>();
        var blockedCriticals = new List<string>();

        foreach (var (ip, host) in Parse(providers.HostsFile.ReadLines()))
        {
            var critical = CriticalFragments.Any(
                fragment => host.Contains(fragment, StringComparison.OrdinalIgnoreCase));

            if (NullRoutes.Contains(ip))
            {
                blocked.Add(host);
                if (critical)
                {
                    blockedCriticals.Add(host);
                }

                continue;
            }

            // Redirection to a routable address: the gesture that hijacks.
            findings.Add(new Finding("hosts-entry", "hosts", $"{host} → {ip}",
                critical ? FindingSeverity.Suspicious : FindingSeverity.Notable,
                [critical
                    ? $"Le fichier hosts redirige un domaine sensible ({host}) vers {ip} — "
                      + "court-circuite la résolution DNS avant tout serveur de noms."
                    : $"Le fichier hosts redirige {host} vers {ip}, en amont de toute "
                      + "résolution DNS."],
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["domaine"] = host,
                    ["adresse"] = ip,
                    ["type"] = "redirection",
                }));
        }

        if (blocked.Count > 0)
        {
            findings.Add(Aggregate(blocked, blockedCriticals));
        }

        return findings;
    }

    private static Finding Aggregate(List<string> blocked, List<string> criticals)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["type"] = "blocage",
            ["domaines"] = blocked.Count.ToString(),
            ["exemples"] = string.Join(", ", blocked.Take(5)),
        };

        if (criticals.Count > 0)
        {
            return new Finding("hosts-entry", "hosts",
                $"{blocked.Count} domaine(s) neutralisé(s)", FindingSeverity.Suspicious,
                [$"Le fichier hosts neutralise une mise à jour ou une protection "
                 + $"({string.Join(", ", criticals.Take(5))}) — empêcher un correctif est "
                 + "une manœuvre, pas un réglage."],
                details);
        }

        return new Finding("hosts-entry", "hosts",
            $"{blocked.Count} domaine(s) neutralisé(s)", FindingSeverity.Notable,
            [$"Le fichier hosts neutralise {blocked.Count} domaine(s) vers une adresse nulle "
             + "— geste courant d'un bloqueur de publicités, à confirmer comme voulu."],
            details);
    }

    /// <summary>
    /// A useful line is "address host [host…]", anything after a hash sign being a
    /// comment. A single line can map several hosts to one address.
    /// </summary>
    private static IEnumerable<(string Ip, string Host)> Parse(IReadOnlyList<string> lines)
    {
        foreach (var raw in lines)
        {
            var line = raw;
            var comment = line.IndexOf('#');
            if (comment >= 0)
            {
                line = line[..comment];
            }

            var tokens = line.Split(
                (char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tokens.Length < 2)
            {
                continue;
            }

            for (var i = 1; i < tokens.Length; i++)
            {
                yield return (tokens[0], tokens[i]);
            }
        }
    }
}
