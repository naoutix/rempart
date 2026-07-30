using System.Net;
using Rempart.Core.Findings;
using Rempart.Core.Reputation;

namespace Rempart.Tests.Unit;

/// <summary>Fake reputation source: returns a verdict fixed per hash.</summary>
internal sealed class FakeReputation(Dictionary<string, ReputationResult> byHash) : IReputationSource
{
    public ReputationResult Lookup(string sha256) =>
        byHash.TryGetValue(sha256, out var r) ? r : new(null, "inconnu de VirusTotal");
}

/// <summary>Source that fails the way a live one does: by throwing.</summary>
internal sealed class ThrowingReputation(Exception failure) : IReputationSource
{
    public ReputationResult Lookup(string sha256) => throw failure;
}

public class VirusTotalTests
{
    /// <summary>A counter VirusTotal could add that is a ratio rather than a tally.</summary>
    private const string FractionalCounter = """
        {"data":{"attributes":{"last_analysis_stats":
          {"malicious":8,"undetected":50,"confidence":0.93}}}}
        """;

    /// <summary>And one whose value simply does not fit the type the reader assumes.</summary>
    private const string CounterPastInt32 = """
        {"data":{"attributes":{"last_analysis_stats":
          {"malicious":99999999999,"undetected":50}}}}
        """;

    private static Finding Flagged(string sha256) =>
        new("process", "x.exe", @"C:\x.exe", FindingSeverity.Notable,
            ["Binaire non signé."],
            new Dictionary<string, string>(StringComparer.Ordinal) { ["sha256"] = sha256 });

    /// <summary>
    /// A VirusTotal detection confirms a suspicion: the finding escalates to
    /// suspicious and the reason goes first. An enrichment that aggravates,
    /// never one that reassures.
    /// </summary>
    [Fact]
    public void A_detection_escalates_the_finding_to_suspicious()
    {
        var source = new FakeReputation(new()
        {
            ["aa"] = new(new HashReputation(12, 70), "12/70 détections"),
        });

        var enriched = Assert.Single(
            FindingEnrichment.WithReputation([Flagged("aa")], source));

        Assert.Equal(FindingSeverity.Suspicious, enriched.Severity);
        Assert.Equal("12/70 détections", enriched.Details["virustotal"]);
        Assert.Contains("VirusTotal", string.Join(" ", enriched.Reasons));
    }

    /// <summary>
    /// A clean hash is noted, but does not lower the finding: an unsigned binary
    /// that no engine knows about is still unsigned.
    /// </summary>
    [Fact]
    public void A_clean_hash_annotates_without_lowering_severity()
    {
        var source = new FakeReputation(new()
        {
            ["bb"] = new(new HashReputation(0, 72), "0/72 — aucun moteur ne le signale"),
        });

        var enriched = Assert.Single(
            FindingEnrichment.WithReputation([Flagged("bb")], source));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Contains("0/72", enriched.Details["virustotal"]);
    }

    /// <summary>
    /// « Inconnu de VirusTotal » is not "clean": it is noted as such, changing
    /// nothing about the severity. Mistaking missing data for an absent threat
    /// would be the very flaw this project hunts.
    /// </summary>
    [Fact]
    public void An_unknown_hash_is_noted_as_unknown_not_clean()
    {
        var enriched = Assert.Single(
            FindingEnrichment.WithReputation([Flagged("cc")], new FakeReputation(new())));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Equal("inconnu de VirusTotal", enriched.Details["virustotal"]);
    }

    /// <summary>
    /// A benign, signed finding is not looked up: its signature already vouches
    /// for its origin, and querying the whole fleet would exhaust the API quota.
    /// </summary>
    [Fact]
    public void Benign_findings_are_not_looked_up()
    {
        var benign = new Finding("process", "ok.exe", @"C:\ok.exe", FindingSeverity.Benign, [],
            new Dictionary<string, string>(StringComparer.Ordinal) { ["sha256"] = "dd" });

        // A source that would show up in Details if it were consulted: proof it is not.
        var throwing = new FakeReputation(new());

        var enriched = Assert.Single(FindingEnrichment.WithReputation([benign], throwing));

        Assert.False(enriched.Details.ContainsKey("virustotal"));
    }

    /// <summary>
    /// The VirusTotal v3 response is read by JSON navigation. The total is the sum
    /// of all counters, without presuming their names.
    /// </summary>
    [Fact]
    public void The_v3_response_is_parsed_into_malicious_and_total()
    {
        const string Json = """
            {"data":{"attributes":{"last_analysis_stats":
              {"malicious":8,"suspicious":1,"undetected":50,"harmless":0,"timeout":1}}}}
            """;

        var result = VirusTotalReputation.Parse(Json);

        Assert.Equal(8, result.Reputation!.Malicious);
        Assert.Equal(60, result.Reputation.Total);
    }

    [Fact]
    public void A_malformed_response_is_reported_not_crashing()
    {
        var result = VirusTotalReputation.Parse("{\"data\":{}}");

        Assert.Null(result.Reputation);
        Assert.Contains("illisible", result.Summary);
    }

    /// <summary>
    /// The total deliberately sums counters the reader does not know the names of, so that
    /// one added by VirusTotal counts instead of being ignored. That same openness is what
    /// made a counter which is not an <c>Int32</c> — a ratio, a value past
    /// <c>int.MaxValue</c> — throw a <c>FormatException</c> that no <c>catch</c> filter on
    /// the way out listed, all the way up to the top of the process.
    /// </summary>
    [Theory]
    [InlineData(FractionalCounter)]
    [InlineData(CounterPastInt32)]
    public void A_counter_that_is_not_an_int32_is_a_reading_not_an_exception(string json)
    {
        var result = VirusTotalReputation.Parse(json);

        Assert.Null(result.Reputation);
        Assert.Equal("réponse VirusTotal illisible", result.Summary);
    }

    /// <summary>
    /// The enrichment runs on a finished scan, one step before it is serialised: a source
    /// that throws used to take the whole audit with it, because the only thing standing
    /// between the two was the <c>catch</c> filters of whichever source was plugged in.
    /// The failure is now recorded like any other, and every finding survives — including
    /// the ones the enrichment never touches.
    /// </summary>
    [Fact]
    public void A_source_that_throws_does_not_destroy_the_scan()
    {
        var untouched = new Finding("autorun", "Run", "x.exe", FindingSeverity.Suspicious,
            ["Persistance."], new Dictionary<string, string>(StringComparer.Ordinal));

        var enriched = FindingEnrichment.WithReputation(
            [Flagged("aa"), untouched],
            new ThrowingReputation(new FormatException("compteur hors bornes")));

        Assert.Equal(2, enriched.Count);
        Assert.Equal(FindingSeverity.Notable, enriched[0].Severity);
        Assert.Contains("compteur hors bornes", enriched[0].Details["virustotal"]);
        Assert.Same(untouched, enriched[1]);
    }

    /// <summary>
    /// Not a list of the failures foreseen: any failure at all. The ones that reach a real
    /// run are, precisely, those absent from a hand-kept list of exception types.
    /// </summary>
    [Fact]
    public void An_unforeseen_failure_is_recorded_like_the_others()
    {
        var enriched = Assert.Single(FindingEnrichment.WithReputation(
            [Flagged("aa")],
            new ThrowingReputation(new InvalidTimeZoneException("rien à voir avec le réseau"))));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Contains("rien à voir avec le réseau", enriched.Details["virustotal"]);
    }

    /// <summary>
    /// A lookup that failed is not a lookup that came back empty. « Inconnu de VirusTotal »
    /// is a verdict of the service, and reusing it here would turn a failure into a
    /// reading — the very confusion this project refuses everywhere else.
    /// </summary>
    [Fact]
    public void A_failed_lookup_does_not_read_as_a_hash_the_service_does_not_know()
    {
        var enriched = Assert.Single(FindingEnrichment.WithReputation(
            [Flagged("aa")], new ThrowingReputation(new IOException("connexion coupée"))));

        Assert.DoesNotContain("inconnu", enriched.Details["virustotal"]);
        Assert.Equal("réputation indisponible : connexion coupée", enriched.Details["virustotal"]);
    }

    /// <summary>
    /// A source that throws must not escalate either: nothing was learnt, so the severity
    /// the scan had established stands, and no reason is added to it.
    /// </summary>
    [Fact]
    public void A_failed_lookup_changes_neither_severity_nor_reasons()
    {
        var enriched = Assert.Single(FindingEnrichment.WithReputation(
            [Flagged("aa")], new ThrowingReputation(new HttpRequestException("hôte injoignable"))));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Equal(["Binaire non signé."], enriched.Reasons);
    }
}

/// <summary>
/// The readings <see cref="VirusTotalReputation"/> makes of a response, driven through a
/// stub handler: no key, no network, and every branch of the status switch exercised for
/// real rather than by inspection.
/// </summary>
public class VirusTotalResponseTests
{
    private const string Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private static VirusTotalReputation Answering(Func<HttpResponseMessage> respond) =>
        new(new StubHttpHandler(respond), "test-key", TimeSpan.FromSeconds(5));

    private static HttpResponseMessage Status(HttpStatusCode code) =>
        new(code) { Content = new StringContent("{}") };

    /// <summary>
    /// None of these masquerades as "clean": a file the service has never seen, a rejected
    /// key and an exhausted quota are three different things, and none of them is
    /// « aucun moteur ne le signale ». Each leaves <c>Reputation</c> null, which is what
    /// keeps the finding's severity where the scan put it.
    /// </summary>
    [Theory]
    [InlineData(HttpStatusCode.NotFound, "inconnu de VirusTotal")]
    [InlineData(HttpStatusCode.Unauthorized, "clé VirusTotal refusée")]
    [InlineData(HttpStatusCode.TooManyRequests, "quota VirusTotal atteint")]
    [InlineData(HttpStatusCode.ServiceUnavailable, "VirusTotal HTTP 503")]
    [InlineData(HttpStatusCode.InternalServerError, "VirusTotal HTTP 500")]
    public void Every_off_nominal_status_has_its_own_reading(HttpStatusCode code, string summary)
    {
        using var source = Answering(() => Status(code));

        var result = source.Lookup(Sha256);

        Assert.Null(result.Reputation);
        Assert.Equal(summary, result.Summary);
    }

    /// <summary>A nominal answer is still read exactly as before.</summary>
    [Fact]
    public void A_successful_response_is_read_into_malicious_and_total()
    {
        using var source = Answering(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """
                {"data":{"attributes":{"last_analysis_stats":
                  {"malicious":3,"undetected":69}}}}
                """),
        });

        var result = source.Lookup(Sha256);

        Assert.Equal(3, result.Reputation!.Malicious);
        Assert.Equal(72, result.Reputation.Total);
    }

    /// <summary>
    /// A 200 whose body the reader cannot face crosses both hand-kept <c>catch</c> filters
    /// — the parser's and the lookup's — and used to leave the process on the way out.
    /// It is a reading, and the lookup returns.
    /// </summary>
    [Fact]
    public void A_body_the_reader_cannot_face_is_a_reading_not_an_exception()
    {
        using var source = Answering(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"data":{"attributes":{"last_analysis_stats":{"malicious":0.5}}}}"""),
        });

        var result = source.Lookup(Sha256);

        Assert.Null(result.Reputation);
        Assert.Equal("réponse VirusTotal illisible", result.Summary);
    }

    /// <summary>
    /// Whatever the transport throws is a reading too, not just the two types the filter
    /// used to name. Nothing distinguishes the failures foreseen from the others once the
    /// scan they would cost is already complete.
    /// </summary>
    [Fact]
    public void A_transport_failure_of_any_kind_is_a_reading()
    {
        using var source = Answering(
            () => throw new InvalidTimeZoneException("rien à voir avec le réseau"));

        var result = source.Lookup(Sha256);

        Assert.Null(result.Reputation);
        Assert.Equal("VirusTotal injoignable : rien à voir avec le réseau", result.Summary);
    }
}

/// <summary>Records whether anything was ever sent, and answers 401 if it was.</summary>
internal sealed class CountingHttpHandler : HttpMessageHandler
{
    public int Sent { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Sent++;
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("{}"),
        });
    }
}

/// <summary>
/// The key is user input, and it reaches an HTTP header — the one step of the enrichment
/// that happens before <see cref="FindingEnrichment"/> has anything to guard.
/// </summary>
public class VirusTotalKeyTests
{
    private const string Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// <summary>What a key file or a CI secret leaves behind, and what a header refuses.</summary>
    public static TheoryData<string> UnsendableKeys() =>
        ["cle-avec-\n-saut", "cle-avec-\r-retour", "cle-terminee-par-un-saut\r\n", "cle\0nul"];

    private static Finding Flagged() =>
        new("process", "x.exe", @"C:\x.exe", FindingSeverity.Notable,
            ["Binaire non signé."],
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["sha256"] = Sha256,
            });

    /// <summary>
    /// Building the source is part of the enrichment, and it ran a line above the guard:
    /// <c>DefaultRequestHeaders.Add</c> validates, so a key holding a newline or a NUL threw
    /// out of the constructor, past <see cref="FindingEnrichment"/>, past <c>ScanCommand</c>
    /// and out of the process — a finished audit lost to an optional lookup, the very thing
    /// the guard below it was written to stop.
    /// </summary>
    [Theory]
    [MemberData(nameof(UnsendableKeys))]
    public void A_key_no_header_accepts_does_not_destroy_the_scan(string key)
    {
        var handler = new CountingHttpHandler();

        using var source = new VirusTotalReputation(handler, key, TimeSpan.FromSeconds(5));

        var result = source.Lookup(Sha256);

        Assert.Null(result.Reputation);
        Assert.Equal(
            "clé VirusTotal inutilisable : elle ne peut pas voyager dans un en-tête HTTP",
            result.Summary);
    }

    /// <summary>
    /// And nothing goes out. A request without the header comes back 401, which this class
    /// reads as « clé VirusTotal refusée » — a key that never left turned into a key the
    /// service examined and rejected. Two different facts.
    /// </summary>
    [Fact]
    public void A_key_that_was_never_sent_is_not_a_key_the_service_refused()
    {
        var handler = new CountingHttpHandler();

        using var source = new VirusTotalReputation(
            handler, "cle-avec-\n-saut", TimeSpan.FromSeconds(5));

        var result = source.Lookup(Sha256);

        Assert.Equal(0, handler.Sent);
        Assert.DoesNotContain("refusée", result.Summary);
        Assert.DoesNotContain("inconnu", result.Summary);
    }

    /// <summary>
    /// The summary is written into <c>Details["virustotal"]</c>, which is serialised into
    /// the JSON report and rendered into the HTML and Markdown ones. A key is a secret: the
    /// reading names the failure without quoting what failed.
    /// </summary>
    [Fact]
    public void An_unsendable_key_is_never_quoted_in_what_the_report_carries()
    {
        var handler = new CountingHttpHandler();

        using var source = new VirusTotalReputation(
            handler, "s3cret-vt-key\n", TimeSpan.FromSeconds(5));

        Assert.DoesNotContain("s3cret", source.Lookup(Sha256).Summary);
    }

    /// <summary>
    /// End to end in the shape <c>ScanCommand</c> runs: the real source, built from the key
    /// as the command builds it, driving a finished scan through the enrichment. Every
    /// finding comes out, at the severity the scan established.
    /// </summary>
    [Fact]
    public void A_scan_survives_an_unsendable_key_all_the_way_through_the_enrichment()
    {
        using var source = new VirusTotalReputation(
            new CountingHttpHandler(), "cle-terminee-par-un-saut\r\n", TimeSpan.FromSeconds(5));

        var enriched = Assert.Single(FindingEnrichment.WithReputation([Flagged()], source));

        Assert.Equal(FindingSeverity.Notable, enriched.Severity);
        Assert.Equal(["Binaire non signé."], enriched.Reasons);
        Assert.Equal(
            "clé VirusTotal inutilisable : elle ne peut pas voyager dans un en-tête HTTP",
            enriched.Details["virustotal"]);
    }

    /// <summary>A key a header does accept still goes out, header and all.</summary>
    [Fact]
    public void A_key_a_header_accepts_is_still_sent()
    {
        var handler = new CountingHttpHandler();

        using var source = new VirusTotalReputation(handler, "test-key", TimeSpan.FromSeconds(5));

        var result = source.Lookup(Sha256);

        Assert.Equal(1, handler.Sent);
        Assert.Equal("clé VirusTotal refusée", result.Summary);
    }
}
