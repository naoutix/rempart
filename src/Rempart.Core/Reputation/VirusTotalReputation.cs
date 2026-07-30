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
///
/// <para>
/// Every <c>catch</c> below is deliberately untyped. They used to name the failures
/// foreseen — two transport types here, three reader types in <see cref="Parse"/> — and
/// what escaped them ended a scan that was already complete: <see cref="Parse"/> sums
/// counters whose names it does not know, on purpose, so one that is not an <c>Int32</c>
/// raises a <c>FormatException</c> that crossed the reader's filter, then the lookup's,
/// then the enrichment. A list of exception types is a list to keep up to date against a
/// service nobody here controls, and no answer from it is worth an audit.
/// </para>
///
/// <para>
/// The same holds one step earlier, where no guard downstream can reach: the key is user
/// input, and installing it as a header validates it. A key carrying a newline or a NUL —
/// what <c>Get-Content key.txt -Raw</c> or a CI secret file leaves behind — used to raise
/// a <c>FormatException</c> from the constructor, before the enrichment had anything to
/// catch. Construction now always yields a usable object, and the key that cannot travel
/// becomes a reading like any other.
/// </para>
/// </summary>
public sealed class VirusTotalReputation : IReputationSource, IDisposable
{
    /// <summary>
    /// What a key that cannot be sent reads as. Distinct from « clé VirusTotal refusée »,
    /// which is the service's own answer to a key it read (401): this one never left the
    /// process. And it quotes nothing of the key — the summary lands in the report, and a
    /// report is meant to be shared.
    /// </summary>
    internal const string UnsendableKey =
        "clé VirusTotal inutilisable : elle ne peut pas voyager dans un en-tête HTTP";

    private readonly HttpClient client;
    private readonly bool keyInstalled;

    public VirusTotalReputation(string apiKey, TimeSpan? timeout = null)
        : this(new HttpClientHandler(), apiKey, timeout)
    {
    }

    /// <summary>
    /// Test seam (ADR-001, D5): every reading below is decided from the response, so
    /// proving that none of them masquerades as "clean" takes a handler rather than a key
    /// and a network.
    /// </summary>
    internal VirusTotalReputation(HttpMessageHandler handler, string apiKey, TimeSpan? timeout = null)
    {
        client = new HttpClient(handler) { Timeout = timeout ?? TimeSpan.FromSeconds(20) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rempart/1.0");

        try
        {
            client.DefaultRequestHeaders.Add("x-apikey", apiKey);
            keyInstalled = true;
        }
        catch (Exception)
        {
            keyInstalled = false;
        }
    }

    public ReputationResult Lookup(string sha256)
    {
        // Without the header the request would go out unauthenticated and come back 401,
        // which reads as « clé VirusTotal refusée » — a key never sent turned into a key
        // the service rejected. Nothing is sent instead.
        if (!keyInstalled)
        {
            return new(null, UnsendableKey);
        }

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
        catch (Exception ex)
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
        catch (Exception)
        {
            return new(null, "réponse VirusTotal illisible");
        }
    }

    public void Dispose() => client.Dispose();
}
