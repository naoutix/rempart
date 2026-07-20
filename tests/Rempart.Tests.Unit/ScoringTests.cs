using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

public sealed class ScoringTests
{
    [Fact]
    public void Unknown_verdicts_are_excluded_never_counted_as_passing()
    {
        // Un contrôle qu'on n'a pas pu lire n'est pas un contrôle satisfait.
        // L'inverse gonflerait le score des machines les moins auditables.
        var card = Scoring.Compute([
            Verdict("a", Severity.High, VerdictStatus.Pass),
            Verdict("b", Severity.High, VerdictStatus.Unknown),
        ]);

        Assert.Equal(100, card.Overall);
        Assert.Equal(1, card.TotalUnknown);
        Assert.True(card.IsPartial);
    }

    [Fact]
    public void A_fully_unreadable_domain_scores_null_not_zero()
    {
        // « Je ne sais pas » et « c'est mauvais » appellent des actions differentes :
        // relancer en administrateur, ou corriger la configuration.
        var card = Scoring.Compute([Verdict("a", Severity.High, VerdictStatus.Unknown)]);

        Assert.Null(card.Overall);
        Assert.Null(Assert.Single(card.Domains).Score);
    }

    [Fact]
    public void Severity_weighting_is_not_linear()
    {
        // Dix réglages mineurs ne compensent pas une faiblesse critique.
        var oneCriticalFailure = Scoring.Compute([
            Verdict("a", Severity.Critical, VerdictStatus.Fail),
            .. Enumerable.Range(0, 10).Select(i => Verdict($"l{i}", Severity.Low, VerdictStatus.Pass)),
        ]);

        Assert.True(oneCriticalFailure.Overall < 50,
            $"un échec critique devrait dominer dix réussites mineures, score = {oneCriticalFailure.Overall}");
    }

    [Fact]
    public void Informational_rules_do_not_move_the_score()
    {
        var withoutInfo = Scoring.Compute([Verdict("a", Severity.High, VerdictStatus.Pass)]);
        var withInfo = Scoring.Compute([
            Verdict("a", Severity.High, VerdictStatus.Pass),
            Verdict("b", Severity.Info, VerdictStatus.Fail),
        ]);

        Assert.Equal(withoutInfo.Overall, withInfo.Overall);
    }

    [Fact]
    public void Scores_are_reported_per_domain()
    {
        var card = Scoring.Compute([
            Verdict("a", Severity.High, VerdictStatus.Pass, "credentials"),
            Verdict("b", Severity.High, VerdictStatus.Fail, "legacy"),
        ]);

        Assert.Equal(2, card.Domains.Count);
        Assert.Equal(100, card.Domains.Single(d => d.Domain == "credentials").Score);
        Assert.Equal(0, card.Domains.Single(d => d.Domain == "legacy").Score);
    }

    [Fact]
    public void A_complete_scan_is_not_flagged_as_partial()
    {
        var card = Scoring.Compute([Verdict("a", Severity.High, VerdictStatus.Pass)]);

        Assert.False(card.IsPartial);
    }

    private static Verdict Verdict(
        string id, Severity severity, VerdictStatus status, string domain = "test") =>
        new(id, $"Règle {id}", severity, domain, status, null, null);
}
