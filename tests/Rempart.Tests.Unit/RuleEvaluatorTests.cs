using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

public sealed class RuleEvaluatorTests
{
    private const string Key = @"HKLM\SOFTWARE\Test";

    /// <summary>
    /// The engine's most important behavior, missing from the first version: an
    /// absent key does not mean "non-compliant". On Windows it means "the default
    /// applies", and the default is often the desired state. Without this the tool
    /// would raise false alarms on healthy machines.
    /// </summary>
    public sealed class WhenTheValueIsAbsent
    {
        [Fact]
        public void A_secure_windows_default_passes()
        {
            // Real case: WDigest. Absent since Windows 8.1, so no cleartext
            // password in memory — the desired state.
            var rule = Rule(CheckOperator.NotEquals, expect: "1", windowsDefault: "0");

            Assert.Equal(VerdictStatus.Pass, Evaluate(rule, new FakeRegistryProvider()).Status);
        }

        [Fact]
        public void An_insecure_windows_default_fails()
        {
            // Real case: LLMNR. Policy not configured means LLMNR is active.
            var rule = Rule(CheckOperator.Equals, expect: "0", windowsDefault: "1");

            Assert.Equal(VerdictStatus.Fail, Evaluate(rule, new FakeRegistryProvider()).Status);
        }

        [Fact]
        public void The_verdict_says_the_value_was_absent_and_which_default_applied()
        {
            var rule = Rule(CheckOperator.Equals, expect: "0", windowsDefault: "1");

            var observed = Evaluate(rule, new FakeRegistryProvider()).Observed;

            // Without this note, the output would suggest the tool failed to read the key.
            Assert.Contains("absent", observed!, StringComparison.Ordinal);
            Assert.Contains("1", observed!, StringComparison.Ordinal);
        }

        [Fact]
        public void A_present_value_takes_precedence_over_the_default()
        {
            var rule = Rule(CheckOperator.Equals, expect: "0", windowsDefault: "0");
            var registry = new FakeRegistryProvider().WithNumber(Key, "Flag", 1);

            Assert.Equal(VerdictStatus.Fail, Evaluate(rule, registry).Status);
        }
    }

    [Theory]
    [InlineData(CheckOperator.Equals, "1", 1, VerdictStatus.Pass)]
    [InlineData(CheckOperator.Equals, "1", 0, VerdictStatus.Fail)]
    [InlineData(CheckOperator.NotEquals, "1", 0, VerdictStatus.Pass)]
    [InlineData(CheckOperator.NotEquals, "1", 1, VerdictStatus.Fail)]
    [InlineData(CheckOperator.AtLeast, "1", 2, VerdictStatus.Pass)]
    [InlineData(CheckOperator.AtLeast, "1", 1, VerdictStatus.Pass)]
    [InlineData(CheckOperator.AtLeast, "1", 0, VerdictStatus.Fail)]
    public void Operators_compare_as_expected(
        CheckOperator op, string expect, long actual, VerdictStatus expected)
    {
        var registry = new FakeRegistryProvider().WithNumber(Key, "Flag", actual);

        Assert.Equal(expected, Evaluate(Rule(op, expect, "0"), registry).Status);
    }

    [Fact]
    public void AtLeast_accepts_a_stronger_setting_than_required()
    {
        // Real case: RunAsPPL is 1 (with UEFI lock) or 2 (without). Both protect
        // LSASS. Requiring equality would reject a correctly configured machine.
        var registry = new FakeRegistryProvider().WithNumber(Key, "Flag", 2);

        Assert.Equal(VerdictStatus.Pass,
            Evaluate(Rule(CheckOperator.AtLeast, "1", "0"), registry).Status);
    }

    [Fact]
    public void Access_denied_yields_unknown_never_a_pass_or_a_fail()
    {
        // Neither compliant nor non-compliant. The audit must not pick a side here.
        var registry = new FakeRegistryProvider().WithAccessDenied(Key, "Flag");

        var verdict = Evaluate(Rule(CheckOperator.Equals, "1", "0"), registry);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
    }

    [Fact]
    public void Key_existence_checks_ignore_the_windows_default()
    {
        // These operators test key presence itself, not an effective value.
        var rule = KeyRule(CheckOperator.Absent);

        Assert.Equal(VerdictStatus.Pass, Evaluate(rule, new FakeRegistryProvider()).Status);
        Assert.Equal(VerdictStatus.Fail,
            Evaluate(rule, new FakeRegistryProvider().WithKey(Key, ReadStatus.Found)).Status);
    }

    [Fact]
    public void The_verdict_carries_the_rule_metadata_for_reporting()
    {
        var verdict = Evaluate(Rule(CheckOperator.Equals, "1", "0"), new FakeRegistryProvider());

        Assert.Equal("TEST-001", verdict.RuleId);
        Assert.Equal("Un contrôle", verdict.Title);
        Assert.Equal(Severity.High, verdict.Severity);
        Assert.Equal("test", verdict.Domain);
    }

    private static Verdict Evaluate(Rule rule, IRegistryProvider registry) =>
        RuleEvaluator.Evaluate(rule, registry);

    private static Rule Rule(CheckOperator op, string expect, string windowsDefault) =>
        new("TEST-001", "Un contrôle", Severity.High, "test", "Parce que.", [],
            new CheckSpec(CheckKind.Registry, Key, "Flag", op, expect, windowsDefault), null);

    private static Rule KeyRule(CheckOperator op) =>
        new("TEST-002", "Une clé", Severity.Medium, "test", "Parce que.", [],
            new CheckSpec(CheckKind.RegistryKey, Key, null, op, null, null), null);
}
