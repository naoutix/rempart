using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

internal sealed class FakePolicyProvider(params (string Name, string Value)[] facts) : ISecurityPolicyProvider
{
    public static readonly FakePolicyProvider Denied = new() { denied = true };

    private bool denied;

    public PolicyFacts Read() => denied
        ? PolicyFacts.AccessDenied
        : new PolicyFacts(facts.ToDictionary(f => f.Name, f => f.Value, StringComparer.Ordinal));
}

/// <summary>
/// Les faits de politique — mot de passe, verrouillage, comptes — ne se lisent ni au
/// registre ni au gestionnaire de services. Ils sont exposés comme valeurs nommées
/// plutôt que comme une liste de comptes : un audit demande « combien », pas
/// « lesquels », et énumérer des noms d'utilisateurs dans un rapport les exposerait
/// sans nécessité.
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
        // Une clé absente du dictionnaire signifie que l'API n'a pas su répondre.
        // Conclure à une non-conformité reprocherait à la machine ce que l'outil
        // n'a pas su lire.
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

    [Theory]
    [InlineData(CheckOperator.AtMost, "2", "2", VerdictStatus.Pass)]
    [InlineData(CheckOperator.AtMost, "2", "1", VerdictStatus.Pass)]
    [InlineData(CheckOperator.AtMost, "2", "5", VerdictStatus.Fail)]
    [InlineData(CheckOperator.AtLeast, "14", "8", VerdictStatus.Fail)]
    public void AtMost_caps_a_value_where_AtLeast_floors_it(
        CheckOperator op, string expect, string actual, VerdictStatus expected)
    {
        // atMost existe pour les plafonds : nombre d'administrateurs locaux, seuils.
        // Sans lui, ces contrôles ne s'exprimaient pas.
        var policy = new FakePolicyProvider(("accounts.localAdminCount", actual));

        Assert.Equal(expected,
            Evaluate(Rule("accounts.localAdminCount", op, expect), policy).Status);
    }

    [Fact]
    public void A_non_numeric_value_fails_an_ordering_comparison_without_throwing()
    {
        // Échouer visiblement plutôt qu'interrompre le scan : une règle mal écrite ne
        // doit pas priver l'opérateur de tous les autres verdicts.
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
