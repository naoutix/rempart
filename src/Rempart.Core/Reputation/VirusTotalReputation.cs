using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace Rempart.Core.Reputation;

/// <summary>
/// Consulte VirusTotal (API v3) pour la réputation d'une empreinte.
///
/// <para>
/// Compatible Native AOT — <c>HttpClient</c> et <c>JsonDocument</c> ne demandent pas de
/// réflexion. La clé d'API voyage dans l'en-tête <c>x-apikey</c>, jamais dans l'URL : une
/// URL se retrouve dans les journaux, un en-tête beaucoup moins.
/// </para>
///
/// <para>
/// Chaque code de réponse a sa lecture, et aucune ne se déguise en « sain » : 404 dit que
/// le fichier est inconnu du service (pas qu'il est propre), 401 une clé refusée, 429 le
/// quota atteint. Confondre l'un avec « rien à signaler » serait le défaut que ce projet
/// traque partout.
/// </para>
/// </summary>
public sealed class VirusTotalReputation : IReputationSource, IDisposable
{
    private readonly HttpClient client;

    public VirusTotalReputation(string apiKey, TimeSpan? timeout = null)
    {
        client = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(20) };
        client.DefaultRequestHeaders.Add("x-apikey", apiKey);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rempart/1.0");
    }

    public ReputationResult Lookup(string sha256)
    {
        try
        {
            using var response = client
                .GetAsync($"https://www.virustotal.com/api/v3/files/{sha256}")
                .GetAwaiter().GetResult();

            return response.StatusCode switch
            {
                HttpStatusCode.NotFound => new(null, "inconnu de VirusTotal"),
                HttpStatusCode.Unauthorized => new(null, "clé VirusTotal refusée"),
                HttpStatusCode.TooManyRequests => new(null, "quota VirusTotal atteint"),
                _ when !response.IsSuccessStatusCode =>
                    new(null, $"VirusTotal HTTP {(int)response.StatusCode}"),
                _ => Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult()),
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new(null, $"VirusTotal injoignable : {ex.Message}");
        }
    }

    /// <summary>
    /// Lit <c>last_analysis_stats</c>. Le total est la somme de tous les compteurs —
    /// détecté, propre, non détecté, en échec — sans en présumer les noms : un compteur
    /// ajouté par VirusTotal compte, il n'est pas ignoré.
    /// </summary>
    internal static ReputationResult Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var stats = document.RootElement
                .GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");

            var malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;

            var total = 0;
            foreach (var counter in stats.EnumerateObject())
            {
                if (counter.Value.ValueKind == JsonValueKind.Number)
                {
                    total += counter.Value.GetInt32();
                }
            }

            var summary = malicious > 0
                ? $"{malicious}/{total} détections"
                : $"0/{total} — aucun moteur ne le signale";

            return new ReputationResult(new HashReputation(malicious, total), summary);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return new(null, "réponse VirusTotal illisible");
        }
    }

    public void Dispose() => client.Dispose();
}
