using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace Rempart.Core.Reputation;

/// <summary>
/// Queries VirusTotal (API v3) for the reputation of a hash.
///
/// <para>
/// Native AOT compatible — <c>HttpClient</c> and <c>JsonDocument</c> require no
/// reflection. The API key travels in the <c>x-apikey</c> header, never in the URL: a
/// URL ends up in logs, a header far less so.
/// </para>
///
/// <para>
/// Every response code has its own reading, and none masquerades as "clean": 404 says
/// the file is unknown to the service (not that it is clean), 401 a rejected key, 429 an
/// exhausted quota. Mistaking any of these for "nothing to report" would be the very
/// flaw this project hunts everywhere.
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
    /// Reads <c>last_analysis_stats</c>. The total is the sum of every counter —
    /// detected, clean, undetected, failed — without assuming their names: a counter
    /// added by VirusTotal counts, it is not ignored.
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
