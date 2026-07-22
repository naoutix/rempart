using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Correspondances du fichier <c>hosts</c>.
///
/// <para>
/// Le fichier <c>hosts</c> passe avant le DNS : ce qu'il déclare l'emporte. Deux gestes
/// s'y lisent, opposés. Une <b>redirection</b> — un domaine pointé vers une adresse
/// routable — court-circuite la résolution vers une machine choisie ; visant une mise à
/// jour ou une authentification, c'est un détournement. Un <b>blocage</b> — un domaine
/// pointé vers une adresse nulle — neutralise le domaine ; c'est le geste d'un bloqueur de
/// publicités, anodin, sauf s'il neutralise justement une mise à jour ou une protection.
/// </para>
///
/// <para>
/// Les redirections sont rares et relevées une à une. Les blocages se comptent par
/// milliers dans une liste anti-publicité : les énumérer noierait le rapport, on les
/// agrège en un seul constat — sauf à toucher un domaine critique, qui rouvre le compte.
/// </para>
/// </summary>
public sealed class HostsFileCollector : IFindingCollector
{
    public string Name => "hosts-entry";

    private static readonly string[] NullRoutes = ["0.0.0.0", "127.0.0.1", "::1", "::"];

    /// <summary>
    /// Fragments de domaines dont la neutralisation ou le détournement porte à conséquence :
    /// mise à jour de Windows, protection, activation, authentification. Bloquer une mise à
    /// jour empêche de corriger une faille ; rediriger une authentification la capte.
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

            // Redirection vers une adresse routable : le geste qui détourne.
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
    /// Une ligne utile est « adresse hôte [hôte…] », le reste après un dièse étant un
    /// commentaire. Une même ligne peut viser plusieurs hôtes vers une seule adresse.
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
