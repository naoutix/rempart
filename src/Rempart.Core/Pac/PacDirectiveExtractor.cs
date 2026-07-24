using System.Text.RegularExpressions;

namespace Rempart.Core.Pac;

/// <summary>
/// Extracts the proxies a PAC script routes to, by static reading — never by
/// execution.
///
/// <para>
/// A PAC is JavaScript (<c>FindProxyForURL</c>) returning strings of the form
/// <c>"PROXY host:port"</c>, <c>"SOCKS host:port"</c>, <c>"HTTPS host:port"</c> or
/// <c>"DIRECT"</c>. The script is not executed — that would mean embedding a JS engine
/// and handing it a hostile script to evaluate. The endpoints it names are collected:
/// that is already the information that matters, where the traffic can go.
/// </para>
/// </summary>
public static partial class PacDirectiveExtractor
{
    // A routing keyword, a space, then "host:port". "https://" has no space before the
    // host: it does not match, so a link inside a comment is not mistaken for a
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
