using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

internal sealed class FakePolicyProvider(params (string Name, string Value)[] facts) : ISecurityPolicyProvider
{
    public static readonly FakePolicyProvider Denied = new() { denied = true };

    private bool denied;

    private Dictionary<string, string>? gaps;

    /// <summary>
    /// A fact the read could not establish, and what it says about why. This is the shape a
    /// partial policy read produces: the facts that were established, and a reason named
    /// beside each one that was not.
    /// </summary>
    public FakePolicyProvider WithGap(string name, string reason)
    {
        (gaps ??= new Dictionary<string, string>(StringComparer.Ordinal))[name] = reason;
        return this;
    }

    public PolicyFacts Read() => denied
        ? PolicyFacts.AccessDenied
        : new PolicyFacts(
            facts.ToDictionary(f => f.Name, f => f.Value, StringComparer.Ordinal), Gaps: gaps);
}

/// <summary>
/// Policy facts — password, lockout, accounts — are readable neither from the
/// registry nor from the service control manager. They are exposed as named values
/// rather than as a list of accounts: an audit asks "how many", not "which ones",
/// and enumerating user names in a report would expose them needlessly.
/// </summary>
public sealed class PolicyCheckTests
{
    [Fact]
    public void A_fact_is_compared_like_any_other_value()
    {
        var policy = new FakePolicyProvider(("password.minLength", "14"));

        Assert.Equal(VerdictStatus.Pass,
            Evaluate(Rule("password.minLength", CheckOperator.AtLeast, "14"), policy).Status);
    }

    [Fact]
    public void A_fact_the_provider_could_not_establish_is_unverifiable()
    {
        // A key absent from the dictionary means the API could not answer.
        // Concluding non-compliance would blame the machine for something the
        // tool failed to read.
        var policy = new FakePolicyProvider(("password.minLength", "14"));

        var verdict = Evaluate(Rule("lockout.threshold", CheckOperator.AtLeast, "1"), policy);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
    }

    /// <summary>
    /// The reason a fact is missing, carried as far as the verdict.
    ///
    /// <para>
    /// Same shape as the service and WMI branches beside it, and for the same reason: a
    /// <c>type: policy</c> rule reported « non vérifiable » with nothing said about why, so
    /// an unreachable <c>netapi32</c> and a genuine refusal produced the identical report.
    /// The status is deliberately unchanged — <see cref="VerdictStatus.Unknown"/>, out of the
    /// score, never <see cref="VerdictStatus.Fail"/> — because what the scan could not
    /// establish says nothing about the machine. What travels now is the reason.
    /// </para>
    /// </summary>
    [Fact]
    public void A_fact_the_read_could_not_establish_names_what_failed()
    {
        var policy = new FakePolicyProvider(("password.minLength", "14"))
            .WithGap("lockout.threshold", "NetUserModalsGet(niveau 3) : échec 1722");

        var verdict = Evaluate(Rule("lockout.threshold", CheckOperator.AtLeast, "1"), policy);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Equal("NetUserModalsGet(niveau 3) : échec 1722", verdict.Observed);
    }

    /// <summary>
    /// The other half, and the one that makes the first safe: a gap on one fact says nothing
    /// about the fact beside it.
    ///
    /// <para>
    /// A partial read is the ordinary case here — four independent netapi32 surfaces feed one
    /// dictionary — so a reader that let any gap speak for the whole read would turn a
    /// lockout policy nobody could read into a password policy nobody could read either.
    /// </para>
    /// </summary>
    [Fact]
    public void A_fact_that_was_established_is_untouched_by_a_gap_on_another()
    {
        var policy = new FakePolicyProvider(("password.minLength", "14"))
            .WithGap("lockout.threshold", "NetUserModalsGet(niveau 3) : échec 1722");

        var verdict = Evaluate(Rule("password.minLength", CheckOperator.AtLeast, "14"), policy);

        Assert.Equal(VerdictStatus.Pass, verdict.Status);
        Assert.Equal("14", verdict.Observed);
    }

    /// <summary>
    /// A read that recorded no gap reads exactly as it did before the channel existed, which
    /// is what every capture written until now carries.
    /// </summary>
    [Fact]
    public void A_read_without_gaps_leaves_a_missing_fact_as_silent_as_it_was()
    {
        var policy = new FakePolicyProvider(("password.minLength", "14"));

        var verdict = Evaluate(Rule("lockout.threshold", CheckOperator.AtLeast, "1"), policy);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
    }

    [Fact]
    public void A_denied_provider_yields_unknown_for_every_fact()
    {
        Assert.Equal(VerdictStatus.Unknown,
            Evaluate(Rule("password.minLength", CheckOperator.AtLeast, "14"),
                FakePolicyProvider.Denied).Status);
    }

    [Fact]
    public void Without_a_policy_provider_the_check_stays_unverifiable()
    {
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        Assert.Equal(VerdictStatus.Unknown,
            RuleEvaluator.Evaluate(Rule("password.minLength", CheckOperator.AtLeast, "14"),
                providers).Status);
    }

    /// <summary>
    /// And it says which of the two it is. A scan wired without a policy provider asked
    /// netapi32 nothing at all, so « accès refusé » described a machine that had done
    /// nothing — the six shipped <c>type: policy</c> controls sent to be re-run elevated
    /// against a provider nobody supplied.
    ///
    /// <para>
    /// The neighbouring path of #160 rather than the defect itself: the five collectors beside
    /// this one in <c>ISystemInfoProvider</c> already answer <c>Failed(…)</c> here, and this
    /// one could not until <c>PolicyFacts</c> had somewhere to put a reason.
    /// </para>
    /// </summary>
    [Fact]
    public void Without_a_policy_provider_the_check_names_the_absence_instead_of_a_refusal()
    {
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        var verdict = RuleEvaluator.Evaluate(
            Rule("password.minLength", CheckOperator.AtLeast, "14"), providers);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Equal("Aucun fournisseur de politique de sécurité n'a été fourni à ce scan.",
            verdict.Observed);
    }

    /// <summary>
    /// The same absence one layer down, on the replay side: a capture carrying no policy
    /// block recorded nothing, which is not a machine that refused.
    /// </summary>
    [Fact]
    public void A_capture_with_no_policy_block_names_the_absence_instead_of_a_refusal()
    {
        var facts = new SnapshotSecurityPolicyProvider(new MachineSnapshot()).Read();

        Assert.False(facts.Denied);
        Assert.Equal("La capture rejouée ne porte aucun bloc de politique de sécurité.",
            facts.WhyMissing(PolicyFactNames.PasswordMinLength));
    }

    [Theory]
    [InlineData(CheckOperator.AtMost, "2", "2", VerdictStatus.Pass)]
    [InlineData(CheckOperator.AtMost, "2", "1", VerdictStatus.Pass)]
    [InlineData(CheckOperator.AtMost, "2", "5", VerdictStatus.Fail)]
    [InlineData(CheckOperator.AtLeast, "14", "8", VerdictStatus.Fail)]
    public void AtMost_caps_a_value_where_AtLeast_floors_it(
        CheckOperator op, string expect, string actual, VerdictStatus expected)
    {
        // atMost exists for upper bounds: local administrator count, thresholds.
        // Without it, those checks could not be expressed.
        var policy = new FakePolicyProvider(("accounts.localAdminCount", actual));

        Assert.Equal(expected,
            Evaluate(Rule("accounts.localAdminCount", op, expect), policy).Status);
    }

    [Fact]
    public void A_non_numeric_value_fails_an_ordering_comparison_without_throwing()
    {
        // Fail visibly rather than abort the scan: a badly written rule must not
        // deprive the operator of all the other verdicts.
        var policy = new FakePolicyProvider(("accounts.guestEnabled", "true"));

        Assert.Equal(VerdictStatus.Fail,
            Evaluate(Rule("accounts.guestEnabled", CheckOperator.AtLeast, "1"), policy).Status);
    }

    [Fact]
    public void A_policy_check_needs_no_windows_default()
    {
        var yaml = """
            - id: TEST-POL
              title: Un fait de politique
              severity: high
              domain: accounts
              rationale: Une justification suffisamment longue pour passer la validation.
              check:
                type: policy
                path: password.minLength
                operator: atLeast
                expect: "14"
            """;

        Assert.Equal(CheckKind.Policy, RuleLoader.Load(yaml)[0].Check.Kind);
    }

    private static Verdict Evaluate(Rule rule, ISecurityPolicyProvider policy) =>
        RuleEvaluator.Evaluate(rule, new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(), null, policy));

    private static Rule Rule(string fact, CheckOperator op, string expect) =>
        new("TEST-POL", "Un fait", Severity.High, "accounts", "Parce que.", [],
            new CheckSpec(CheckKind.Policy, fact, null, op, expect, null), null);
}
