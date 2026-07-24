using Rempart.Core.Findings;
using Rempart.Core.Reputation;

namespace Rempart.Tests.Unit;

/// <summary>Fake reputation source: returns a verdict fixed per hash.</summary>
internal sealed class FakeReputation(Dictionary<string, ReputationResult> byHash) : IReputationSource
{
    public ReputationResult Lookup(string sha256) =>
        byHash.TryGetValue(sha256, out var r) ? r : new(null, "inconnu de VirusTotal");
}

public class VirusTotalTests
{
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
}
