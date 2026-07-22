using System.Net.Http;

namespace Rempart.Core.Pac;

/// <summary>
/// Récupère un script PAC par HTTP et en extrait le routage.
///
/// <para>
/// Compatible Native AOT — <c>HttpClient</c> ne demande pas de réflexion, comme
/// <c>VirusTotalReputation</c>. Chaque issue a sa lecture et aucune ne se déguise en
/// « inoffensif » : un 404 dit que le PAC est absent, un timeout qu'il est injoignable,
/// pas qu'il est sain. Le script n'est jamais exécuté — seul son texte est lu.
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
