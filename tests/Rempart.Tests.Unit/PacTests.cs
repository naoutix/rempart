using System.Net;
using Rempart.Core.Findings;
using Rempart.Core.Pac;

namespace Rempart.Tests.Unit;

public class PacDirectiveExtractorTests
{
    [Fact]
    public void Extracts_a_proxy_directive()
    {
        var proxies = PacDirectiveExtractor.ExtractProxies(
            "function FindProxyForURL(url, host) { return \"PROXY p.evil.example:8080; DIRECT\"; }");

        Assert.Equal(["p.evil.example:8080"], proxies);
    }

    [Fact]
    public void Direct_only_yields_nothing() =>
        Assert.Empty(PacDirectiveExtractor.ExtractProxies("return \"DIRECT\";"));

    [Fact]
    public void Extracts_socks_and_https_endpoints()
    {
        var proxies = PacDirectiveExtractor.ExtractProxies(
            "if (x) return \"SOCKS5 socks.example:1080\"; else return \"HTTPS secure.example:443\";");

        Assert.Equal(["socks.example:1080", "secure.example:443"], proxies);
    }

    [Fact]
    public void Repeated_endpoints_are_deduplicated()
    {
        var proxies = PacDirectiveExtractor.ExtractProxies(
            "return \"PROXY a.example:8080\"; return \"PROXY a.example:8080\";");

        Assert.Equal(["a.example:8080"], proxies);
    }

    [Fact]
    public void A_url_in_a_comment_is_not_a_directive() =>
        // "https://" is not "HTTPS host:port": no space, hence no directive.
        Assert.Empty(PacDirectiveExtractor.ExtractProxies("// see https://docs.example/pac\nreturn \"DIRECT\";"));

    [Fact]
    public void Null_or_empty_yields_nothing() =>
        Assert.Empty(PacDirectiveExtractor.ExtractProxies(null));
}

/// <summary>Fake PAC fetcher: returns a fixed analysis, no network involved.</summary>
internal sealed class FakePacFetcher(PacAnalysis analysis) : IPacFetcher
{
    public PacAnalysis Fetch(string pacUrl) => analysis;
}

/// <summary>Fetcher that fails the way a live one does: by throwing.</summary>
internal sealed class ThrowingPacFetcher(Exception failure) : IPacFetcher
{
    public PacAnalysis Fetch(string pacUrl) => throw failure;
}

/// <summary>
/// Answers every request with a freshly built response, so the real <c>LivePacFetcher</c>
/// can be driven without a server — its size cap is enforced by <c>HttpClient</c> above
/// the handler, and is therefore exercised for real here.
/// </summary>
internal sealed class StubHttpHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken) =>
        Task.FromResult(respond());
}

public class PacEnrichmentTests
{
    private static Finding ProxyFinding(FindingSeverity severity, string? pac) =>
        new("proxy", "WinINET", pac ?? "srv:8080", severity,
            ["PAC présent."],
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["portée"] = "WinINET",
                ["pac"] = pac ?? "",
            });

    private static IReadOnlyList<Finding> Enrich(Finding finding, PacAnalysis analysis) =>
        PacEnrichment.WithRouting([finding], new FakePacFetcher(analysis));

    [Fact]
    public void An_external_route_escalates_a_notable_pac_to_suspicious()
    {
        var enriched = Assert.Single(Enrich(
            ProxyFinding(FindingSeverity.Notable, "https://wpad.example/p.pac"),
            new PacAnalysis(["proxy.evil.example:8080"], "route vers proxy.evil.example:8080")));

        Assert.Equal(FindingSeverity.Suspicious, enriched.Severity);
        Assert.Contains("proxy.evil.example", string.Join(" ", enriched.Reasons));
        Assert.Equal("route vers proxy.evil.example:8080", enriched.Details["pac-route"]);
    }

    [Fact]
    public void A_benign_finding_is_never_fetched()
    {
        var enriched = Assert.Single(Enrich(
            ProxyFinding(FindingSeverity.Benign, "http://wpad.corp/p.pac"),
            new PacAnalysis(["proxy.evil:8080"], "route vers proxy.evil:8080")));

        // Benign (proxy imposed by GPO): we do not fetch, hence no enrichment.
        Assert.Equal(FindingSeverity.Benign, enriched.Severity);
        Assert.False(enriched.Details.ContainsKey("pac-route"));
    }

    [Fact]
    public void A_local_route_records_the_summary_without_escalating()
    {
        var enriched = Assert.Single(Enrich(
            ProxyFinding(FindingSeverity.Notable, "http://localhost/p.pac"),
            new PacAnalysis(["127.0.0.1:8888"], "route vers 127.0.0.1:8888")));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Equal("route vers 127.0.0.1:8888", enriched.Details["pac-route"]);
    }

    [Fact]
    public void An_unreachable_pac_records_the_reason_without_escalating()
    {
        var enriched = Assert.Single(Enrich(
            ProxyFinding(FindingSeverity.Notable, "http://gone.example/p.pac"),
            new PacAnalysis([], "PAC injoignable : hôte introuvable")));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Equal("PAC injoignable : hôte introuvable", enriched.Details["pac-route"]);
    }

    [Fact]
    public void A_finding_without_a_pac_detail_is_untouched()
    {
        var finding = new Finding("proxy", "WinHTTP", "srv:3128", FindingSeverity.Notable,
            ["Proxy externe."], new Dictionary<string, string>(StringComparer.Ordinal));

        var enriched = Assert.Single(
            PacEnrichment.WithRouting([finding], new FakePacFetcher(new PacAnalysis(["x:1"], "x"))));

        Assert.Same(finding, enriched);
    }

    /// <summary>
    /// The enrichment runs on a finished scan, one step before it is serialised: a
    /// fetcher that throws used to take the whole audit with it. The failure is now
    /// recorded like any other unreachable PAC, and every finding survives — including
    /// the ones the enrichment never touches.
    /// </summary>
    [Fact]
    public void A_fetcher_that_throws_does_not_destroy_the_scan()
    {
        var untouched = new Finding("autorun", "Run", "x.exe", FindingSeverity.Suspicious,
            ["Persistance."], new Dictionary<string, string>(StringComparer.Ordinal));

        var enriched = PacEnrichment.WithRouting(
            [ProxyFinding(FindingSeverity.Notable, @"file://C:\ProgramData\proxy.pac"), untouched],
            new ThrowingPacFetcher(new NotSupportedException("Le schéma 'file' n'est pas géré.")));

        Assert.Equal(2, enriched.Count);
        Assert.Equal(FindingSeverity.Notable, enriched[0].Severity);
        Assert.Contains("injoignable", enriched[0].Details["pac-route"]);
        Assert.Same(untouched, enriched[1]);
    }

    /// <summary>
    /// Not a list of the failures foreseen: any failure at all. The one that reached
    /// production was, precisely, absent from a hand-kept list of exception types.
    /// </summary>
    [Fact]
    public void An_unforeseen_failure_is_recorded_like_the_others()
    {
        var enriched = Assert.Single(PacEnrichment.WithRouting(
            [ProxyFinding(FindingSeverity.Notable, "http://wpad.example/p.pac")],
            new ThrowingPacFetcher(new InvalidTimeZoneException("rien à voir avec le réseau"))));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Contains("rien à voir avec le réseau", enriched.Details["pac-route"]);
    }
}

public class LivePacFetcherTests
{
    /// <summary>
    /// <c>AutoConfigURL = file://…</c> is a legitimate WinINET value, read verbatim by
    /// the proxy provider. <c>HttpClient</c> answers such a scheme with
    /// <c>NotSupportedException</c>, which no <c>catch</c> filter listed: with
    /// <c>--fetch-pac</c>, an already complete scan was destroyed before serialisation.
    /// Nothing here touches the network — the scheme is refused before the request.
    /// </summary>
    [Theory]
    [InlineData(@"file://C:\ProgramData\proxy.pac", "file")]
    [InlineData("file://localhost/proxy.pac", "file")]
    [InlineData("ftp://wpad.example/proxy.pac", "ftp")]
    [InlineData("mailto:admin@example", "mailto")]
    public void A_non_http_url_is_a_reading_not_an_exception(string pacUrl, string scheme)
    {
        using var fetcher = new LivePacFetcher(TimeSpan.FromSeconds(2));

        var analysis = fetcher.Fetch(pacUrl);

        Assert.Empty(analysis.Proxies);

        // The wording is asserted, not just the absence of a throw: relaying what
        // HttpClient says would put an English sentence in a French report, and would
        // mean the request had been attempted after all.
        Assert.Equal($"PAC injoignable : schéma « {scheme} » non pris en charge", analysis.Summary);
    }

    /// <summary>
    /// Same rule for a URL that does not parse at all: the value comes from the machine
    /// under audit, so nothing guarantees it is a URL in the first place.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("wpad.example/proxy.pac")]
    public void An_unusable_url_is_a_reading_not_an_exception(string pacUrl)
    {
        using var fetcher = new LivePacFetcher(TimeSpan.FromSeconds(2));

        var analysis = fetcher.Fetch(pacUrl);

        Assert.Empty(analysis.Proxies);
        Assert.Equal("PAC injoignable : URL illisible", analysis.Summary);
    }

    /// <summary>
    /// The refusal is about the scheme, not about being strict: an http(s) URL is still
    /// fetched and read exactly as before.
    /// </summary>
    [Fact]
    public void An_https_script_is_still_fetched_and_read()
    {
        using var fetcher = new LivePacFetcher(
            new StubHttpHandler(() => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "function FindProxyForURL(u, h) { return \"PROXY p.example:8080\"; }"),
            }),
            TimeSpan.FromSeconds(5));

        var analysis = fetcher.Fetch("https://wpad.example/p.pac");

        Assert.Equal(["p.example:8080"], analysis.Proxies);
        Assert.Equal("route vers p.example:8080", analysis.Summary);
    }

    /// <summary>
    /// What answers the URL is not necessarily a PAC script. Until the cap, the only
    /// bound on what <c>--fetch-pac</c> would buffer was the 15 s timeout, over a default
    /// of 2 GiB.
    /// </summary>
    [Fact]
    public void An_oversized_response_is_refused_rather_than_buffered()
    {
        using var fetcher = new LivePacFetcher(
            new StubHttpHandler(() => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(new string('a', 4 * 1024 * 1024)),
            }),
            TimeSpan.FromSeconds(5));

        var analysis = fetcher.Fetch("http://wpad.example/p.pac");

        Assert.Empty(analysis.Proxies);
        Assert.Contains("injoignable", analysis.Summary);
    }
}
