using System.Text.RegularExpressions;

namespace Rempart.Core.Pac;

/// <summary>
/// Extrait les proxys vers lesquels un script PAC route, par lecture statique — jamais par
/// exécution.
///
/// <para>
/// Un PAC est du JavaScript (<c>FindProxyForURL</c>) qui rend des chaînes du type
/// <c>"PROXY host:port"</c>, <c>"SOCKS host:port"</c>, <c>"HTTPS host:port"</c> ou
/// <c>"DIRECT"</c>. On n'exécute pas le script — ce serait embarquer un moteur JS et lui
/// donner un script hostile à évaluer. On relève les points de terminaison qu'il nomme :
/// c'est déjà l'information qui compte, vers où le trafic peut partir.
/// </para>
/// </summary>
public static partial class PacDirectiveExtractor
{
    // Un mot-clé de routage, un espace, puis « hôte:port ». « https:// » n'a pas d'espace
    // avant l'hôte : il ne matche pas, un lien en commentaire n'est donc pas pris pour une
    // directive.
    [GeneratedRegex(
        @"\b(?:PROXY|HTTPS|SOCKS5|SOCKS)\s+([A-Za-z0-9.\-_]+:\d{1,5})",
        RegexOptions.IgnoreCase)]
    private static partial Regex Directive();

    public static IReadOnlyList<string> ExtractProxies(string? script)
    {
        var proxies = new List<string>();
        if (string.IsNullOrEmpty(script))
        {
            return proxies;
        }

        foreach (Match match in Directive().Matches(script))
        {
            var endpoint = match.Groups[1].Value;
            if (!proxies.Contains(endpoint, StringComparer.OrdinalIgnoreCase))
            {
                proxies.Add(endpoint);
            }
        }

        return proxies;
    }
}
