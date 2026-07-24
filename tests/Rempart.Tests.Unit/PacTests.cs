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
}
