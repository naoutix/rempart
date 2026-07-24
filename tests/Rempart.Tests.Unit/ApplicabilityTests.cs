using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// A check that only makes sense in a specific context produces noise everywhere
/// else, and noise undermines an audit tool: alerts stop being read when half of
/// them do not apply.
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
        // Real case: NLA only matters if RDP is enabled.
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
        // Better to evaluate and return a verdict than to hide a check over an
        // applicability uncertainty: a suppressed rule goes unnoticed.
        var rule = Rule(new Applicability(Registry: new CheckSpec(
            CheckKind.Registry, Key, "Enabled", CheckOperator.Equals, "1", "0")));

        var denied = new FakeRegistryProvider().WithAccessDenied(Key, "Enabled");

        Assert.NotEqual(VerdictStatus.NotApplicable, Evaluate(rule, denied).Status);
    }

    [Fact]
    public void Not_applicable_verdicts_leave_the_score_untouched()
    {
        // Counting these rules as failures would penalize a machine for a
        // context that does not apply to it.
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
        // Unlike Unknown: here we do know, and the answer is that there was
        // nothing to verify. The report must not declare itself partial for it.
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
        // An empty block suggests a condition while the rule actually applies
        // everywhere: the author's intent would be silently lost.
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
