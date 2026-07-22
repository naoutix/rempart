using Rempart.Core.Findings;
using Rempart.Core.Reputation;

namespace Rempart.Tests.Unit;

/// <summary>Source de réputation factice : rend un verdict fixé par empreinte.</summary>
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
    /// Une détection VirusTotal confirme un soupçon : le constat passe à suspect et le
    /// motif s'inscrit en tête. C'est un complément qui aggrave, jamais qui rassure.
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
    /// Une empreinte propre est notée, mais n'abaisse pas le constat : un binaire non
    /// signé qu'aucun moteur ne connaît reste non signé.
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
    /// « Inconnu de VirusTotal » n'est pas « sain » : c'est noté tel quel, sans rien
    /// changer à la gravité. Confondre l'absence de donnée avec l'absence de menace serait
    /// le défaut que ce projet traque.
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
    /// Un constat bénin et signé n'est pas consulté : sa signature atteste déjà de son
    /// origine, et interroger tout le parc épuiserait le quota d'API.
    /// </summary>
    [Fact]
    public void Benign_findings_are_not_looked_up()
    {
        var benign = new Finding("process", "ok.exe", @"C:\ok.exe", FindingSeverity.Benign, [],
            new Dictionary<string, string>(StringComparer.Ordinal) { ["sha256"] = "dd" });

        // Une source qui lèverait si on l'appelait : la preuve qu'on ne l'appelle pas.
        var throwing = new FakeReputation(new());

        var enriched = Assert.Single(FindingEnrichment.WithReputation([benign], throwing));

        Assert.False(enriched.Details.ContainsKey("virustotal"));
    }

    /// <summary>
    /// La réponse VirusTotal v3 est lue par navigation JSON. Le total est la somme de tous
    /// les compteurs, sans en présumer les noms.
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
