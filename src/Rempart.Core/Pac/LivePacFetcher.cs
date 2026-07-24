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
/// </summary>
public sealed class LivePacFetcher : IPacFetcher, IDisposable
{
    private readonly HttpClient client;

    public LivePacFetcher(TimeSpan? timeout = null)
    {
        client = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(15) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rempart/1.0");
    }

    public PacAnalysis Fetch(string pacUrl)
    {
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
            when (ex is HttpRequestException or TaskCanceledException
                or InvalidOperationException or UriFormatException)
        {
            return new([], $"PAC injoignable : {ex.Message}");
        }
    }

    public void Dispose() => client.Dispose();
}
