using System.Net.Http;

namespace Rempart.Core.Updates;

/// <summary>
/// Transport HTTP réel, bâti sur <see cref="HttpClient"/>.
///
/// <para>
/// Compatible Native AOT — <c>SocketsHttpHandler</c> ne demande pas de réflexion. Le
/// tampon de réponse est plafonné : un serveur hostile ne doit pas pouvoir épuiser la
/// mémoire en servant un fichier sans fin. Le plafond est large devant les données
/// réelles (un manifeste fait moins d'un kilo-octet, la liste LOLDrivers quelques
/// centaines).
/// </para>
///
/// <para>
/// Aucune confiance n'est placée dans le transport : les redirections sont suivies sans
/// crainte, car un manifeste redirigé vers un contenu falsifié échouera de toute façon
/// à la vérification de signature. C'est elle qui protège, pas le canal.
/// </para>
/// </summary>
public sealed class HttpTransport : IUpdateTransport, IDisposable
{
    private const long MaxResponseBytes = 64 * 1024 * 1024;

    private readonly HttpClient client;

    public HttpTransport(TimeSpan? timeout = null)
    {
        client = new HttpClient
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = MaxResponseBytes,
        };

        // Un en-tête d'agent honnête : rien à cacher, et certains hébergeurs refusent
        // une requête sans agent.
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rempart-update/1.0");
    }

    public byte[]? Get(string url, out string? error)
    {
        try
        {
            using var response = client.GetAsync(url).GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
            {
                error = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}";
                return null;
            }

            error = null;
            return response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            // Injoignable, expiré, URL mal formée : un échec de transport, jamais un
            // verdict de confiance. Le message brut suffit à orienter l'utilisateur.
            error = ex.Message;
            return null;
        }
    }

    public void Dispose() => client.Dispose();
}
