using System.Net.Http;

namespace Rempart.Core.Pac;

/// <summary>
/// Fetches a PAC script over HTTP and extracts its routing.
///
/// <para>
/// Native AOT compatible — <c>HttpClient</c> requires no reflection, like
/// <c>VirusTotalReputation</c>. Every outcome has its own reading and none masquerades
/// as "harmless": a 404 says the PAC is absent, a timeout that it is unreachable — not
/// that it is clean. The script is never executed — only its text is read.
/// </para>
///
/// <para>
/// The URL comes from the machine under audit, so it is hostile input and is bounded
/// twice. Its scheme is settled before <c>HttpClient</c> ever sees it:
/// <c>AutoConfigURL = file://C:\ProgramData\proxy.pac</c> is a perfectly legitimate
/// WinINET value, and <c>HttpClient</c> answered it with a <c>NotSupportedException</c>
/// that the <c>catch</c> filter did not list — which threw away an already complete scan
/// one step before it was serialised, over a proxy URL. And the response is capped at
/// <see cref="MaxScriptBytes"/>, where the 15 s timeout used to be the only bound on a
/// 2 GiB default buffer.
/// </para>
///
/// <para>
/// The <c>catch</c> below is deliberately untyped. A list of exception types is a list to
/// keep up to date, and this one was already wrong twice — <c>NotSupportedException</c> on
/// a <c>file://</c> URL, <c>ArgumentOutOfRangeException</c> on a redirect towards one.
/// Fetching a PAC enriches a scan that is already complete: every failure of it is a line
/// to record, never a reason to lose the audit that carries it.
/// </para>
/// </summary>
public sealed class LivePacFetcher : IPacFetcher, IDisposable
{
    /// <summary>
    /// A PAC script is a few kilobytes of JavaScript. One mebibyte leaves room for the
    /// verbose ones and refuses to buffer whatever a hostile URL answers instead.
    /// </summary>
    private const long MaxScriptBytes = 1024 * 1024;

    private readonly HttpClient client;

    public LivePacFetcher(TimeSpan? timeout = null)
        : this(new HttpClientHandler(), timeout)
    {
    }

    /// <summary>
    /// Test seam (ADR-001, D5): the size cap is enforced by <c>HttpClient</c> itself, so
    /// exercising it takes a handler rather than a server.
    /// </summary>
    internal LivePacFetcher(HttpMessageHandler handler, TimeSpan? timeout = null)
    {
        client = new HttpClient(handler)
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(15),
            MaxResponseContentBufferSize = MaxScriptBytes,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rempart/1.0");
    }

    public PacAnalysis Fetch(string pacUrl)
    {
        if (Unfetchable(pacUrl) is { } refusal)
        {
            return new([], refusal);
        }

        try
        {
            using var response = client.GetAsync(pacUrl).GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
            {
                return new([], $"PAC HTTP {(int)response.StatusCode}");
            }

            var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var proxies = PacDirectiveExtractor.ExtractProxies(body);

            return new(proxies, proxies.Count == 0
                ? "aucune directive PROXY dans le script"
                : "route vers " + string.Join(", ", proxies));
        }
        catch (Exception ex)
        {
            return new([], $"PAC injoignable : {ex.Message}");
        }
    }

    /// <summary>
    /// Why this URL will not be requested, or <c>null</c> to go ahead. The feature is
    /// "download the script over HTTP" and nothing else, so anything that is not
    /// <c>http</c> or <c>https</c> is answered here, as a reading, rather than from deep
    /// inside <c>HttpClient</c>, as an exception.
    /// </summary>
    private static string? Unfetchable(string pacUrl)
    {
        if (!Uri.TryCreate(pacUrl, UriKind.Absolute, out var url))
        {
            return "PAC injoignable : URL illisible";
        }

        return string.Equals(url.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            || string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
                ? null
                : $"PAC injoignable : schéma « {url.Scheme} » non pris en charge";
    }

    public void Dispose() => client.Dispose();
}
