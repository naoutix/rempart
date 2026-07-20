using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// Un contrôle qui ne vaut que dans un contexte précis produit du bruit partout
/// ailleurs, et le bruit disqualifie un outil d'audit plus sûrement qu'un contrôle
/// manquant : on cesse de lire des alertes dont la moitié ne s'applique pas.
/// </summary>
public sealed class ApplicabilityTests
{
    private const string Key = @"HKLM\SOFTWARE\Test";

    [Theory]
    [InlineData(true, true, VerdictStatus.Fail)]
    [InlineData(true, false, VerdictStatus.NotApplicable)]
    [InlineData(false, false, VerdictStatus.Fail)]
    [InlineData(false, true, VerdictStatus.NotApplicable)]
    public void Domain_membership_gates_the_rule(
        bool required, bool actual, VerdictStatus expected)
    {
        var rule = Rule(new Applicability(DomainJoined: required));
        var system = FakeSystemInfoProvider.Default with { IsDomainJoined = actual };

        Assert.Equal(expected,
            RuleEvaluator.Evaluate(rule, new FakeRegistryProvider(), system).Status);
    }

    [Fact]
    public void A_registry_condition_gates_the_rule()
    {
        // Cas réel : NLA ne vaut que si RDP est activé.
        var rule = Rule(new Applicability(Registry: new CheckSpec(
            CheckKind.Registry, Key, "Enabled", CheckOperator.Equals, "1", "0")));

        var disabled = new FakeRegistryProvider().WithNumber(Key, "Enabled", 0);
        var enabled = new FakeRegistryProvider().WithNumber(Key, "Enabled", 1);

        Assert.Equal(VerdictStatus.NotApplicable, Evaluate(rule, disabled).Status);
        Assert.Equal(VerdictStatus.Fail, Evaluate(rule, enabled).Status);
    }

    [Fact]
    public void An_unconditional_rule_is_always_evaluated()
    {
        Assert.Equal(VerdictStatus.Fail,
            Evaluate(Rule(applicability: null), new FakeRegistryProvider()).Status);
    }

    [Fact]
    public void An_unreadable_condition_does_not_hide_the_rule()
    {
        // Mieux vaut évaluer et rendre un verdict que masquer un contrôle sur une
        // incertitude d'applicabilité : une règle escamotée ne se remarque pas.
        var rule = Rule(new Applicability(Registry: new CheckSpec(
            CheckKind.Registry, Key, "Enabled", CheckOperator.Equals, "1", "0")));

        var denied = new FakeRegistryProvider().WithAccessDenied(Key, "Enabled");

        Assert.NotEqual(VerdictStatus.NotApplicable, Evaluate(rule, denied).Status);
    }

    [Fact]
    public void Not_applicable_verdicts_leave_the_score_untouched()
    {
        // Compter ces règles comme des échecs pénaliserait une machine pour ne pas
        // être ce qu'elle n'a jamais eu à être.
        var alone = Scoring.Compute([Verdict(VerdictStatus.Pass)]);
        var withNotApplicable = Scoring.Compute([
            Verdict(VerdictStatus.Pass),
            Verdict(VerdictStatus.NotApplicable),
        ]);

        Assert.Equal(alone.Overall, withNotApplicable.Overall);
        Assert.Equal(100, withNotApplicable.Overall);
    }

    [Fact]
    public void Not_applicable_is_not_a_coverage_gap()
    {
        // Contrairement à Unknown : ici on sait, et la réponse est qu'il n'y avait
        // rien à vérifier. Le rapport ne doit pas se déclarer partiel pour autant.
        var card = Scoring.Compute([
            Verdict(VerdictStatus.Pass),
            Verdict(VerdictStatus.NotApplicable),
        ]);

        Assert.False(card.IsPartial);
        Assert.Equal(0, card.TotalUnknown);
        Assert.Equal(1, Assert.Single(card.Domains).NotApplicable);
    }

    [Fact]
    public void An_empty_applies_when_block_is_rejected()
    {
        // Un bloc vide laisse croire à une condition alors que la règle s'applique
        // partout : l'intention de l'auteur serait perdue en silence.
        var yaml = """
            - id: TEST-001
              title: Un contrôle
              severity: high
              domain: test
              rationale: Une justification suffisamment longue pour passer la validation.
              appliesWhen: {}
              check:
                type: registryKey
                path: HKLM\SOFTWARE\Test
                operator: exists
            """;

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml));

        Assert.Contains("aucune condition", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_non_boolean_domain_join_condition_is_rejected()
    {
        var yaml = """
            - id: TEST-001
              title: Un contrôle
              severity: high
              domain: test
              rationale: Une justification suffisamment longue pour passer la validation.
              appliesWhen:
                domainJoined: peut-être
              check:
                type: registryKey
                path: HKLM\SOFTWARE\Test
                operator: exists
            """;

        Assert.Contains("true ou false", Assert.Throws<RuleFormatException>(
            () => RuleLoader.Load(yaml)).Message, StringComparison.Ordinal);
    }

    private static Verdict Evaluate(Rule rule, IRegistryProvider registry) =>
        RuleEvaluator.Evaluate(rule, registry, FakeSystemInfoProvider.Default);

    private static Rule Rule(Applicability? applicability) =>
        new("TEST-001", "Un contrôle", Severity.High, "test", "Parce que.", [],
            new CheckSpec(CheckKind.Registry, Key, "Flag", CheckOperator.Equals, "1", "0"),
            null, applicability);

    private static Verdict Verdict(VerdictStatus status) =>
        new("TEST-001", "Un contrôle", Severity.High, "test", status, null, null);
}
