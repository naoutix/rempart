using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// La fabrique de fixtures est elle-même testée : c'est elle qui produit les données
/// sur lesquelles reposent tous les tests de rejeu. Une fabrique fausse rendrait
/// l'ensemble de la suite silencieusement inutile.
/// </summary>
public sealed class SyntheticSnapshotTests
{
    private const string Key = @"HKLM\SOFTWARE\Test";

    [Fact]
    public void The_hardened_profile_satisfies_every_rule_it_touches()
    {
        var rules = RuleCatalog.Load();
        var built = SyntheticSnapshot.Build(
            Base(rules), rules, SyntheticProfile.Hardened, "anon:test", domainJoined: true);

        var verdicts = rules
            .Select(r => RuleEvaluator.Evaluate(r, new SnapshotRegistryProvider(built), built.SystemInfo))
            .ToList();

        Assert.DoesNotContain(verdicts, v => v.Status is VerdictStatus.Fail or VerdictStatus.Unknown);
    }

    [Fact]
    public void The_defaults_profile_removes_every_hardening_key()
    {
        var rules = RuleCatalog.Load();
        var built = SyntheticSnapshot.Build(
            Base(rules), rules, SyntheticProfile.WindowsDefaults, "anon:test");

        // Le profil doit exercer la sémantique des défauts Windows : si des clés
        // subsistaient, la fixture testerait autre chose que ce qu'elle annonce.
        Assert.All(rules, rule =>
        {
            var key = rule.Check.Kind == CheckKind.RegistryKey
                ? SnapshotKeys.Existence(rule.Check.Path)
                : SnapshotKeys.Value(rule.Check.Path, rule.Check.ValueName!);

            Assert.Equal(ReadStatus.NotFound, built.Registry[key].Status);
        });
    }

    [Theory]
    [InlineData(CheckOperator.Equals, "1")]
    [InlineData(CheckOperator.AtLeast, "5")]
    [InlineData(CheckOperator.NotEquals, "1")]
    [InlineData(CheckOperator.NotEquals, "0")]
    public void A_satisfying_value_is_produced_for_each_operator(CheckOperator op, string expect)
    {
        var rule = Rule(new CheckSpec(CheckKind.Registry, Key, "Flag", op, expect, "9"));

        var built = Build([rule], SyntheticProfile.Hardened);

        Assert.Equal(VerdictStatus.Pass,
            RuleEvaluator.Evaluate(rule, new SnapshotRegistryProvider(built)).Status);
    }

    [Fact]
    public void Keys_absent_from_the_source_capture_are_not_invented()
    {
        // Les ajouter masquerait une lacune de la capture au lieu de la révéler :
        // c'est précisément ce trou qui a fait échouer le rejeu inter-contextes.
        var rule = Rule(new CheckSpec(CheckKind.Registry, Key, "Absente", CheckOperator.Equals, "1", "0"));

        var built = SyntheticSnapshot.Build(
            new MachineSnapshot(), [rule], SyntheticProfile.Hardened, "anon:test");

        Assert.DoesNotContain(SnapshotKeys.Value(Key, "Absente"), built.Registry);
    }

    [Fact]
    public void Denied_fragments_become_access_denied()
    {
        var rule = Rule(new CheckSpec(CheckKind.Registry, Key, "Flag", CheckOperator.Equals, "1", "0"));

        var built = SyntheticSnapshot.Build(
            WithKey(SnapshotKeys.Value(Key, "Flag")), [rule], SyntheticProfile.Hardened,
            "anon:test", denyPathFragments: ["SOFTWARE\\Test"]);

        Assert.Equal(ReadStatus.AccessDenied, built.Registry[SnapshotKeys.Value(Key, "Flag")].Status);
    }

    [Fact]
    public void The_result_is_always_marked_anonymised_with_a_frozen_uptime()
    {
        // Une fixture versionnée dans un dépôt public ne peut ni porter d'identifiant
        // machine, ni figer une durée qui change à chaque exécution.
        var built = SyntheticSnapshot.Build(
            new MachineSnapshot(), [], SyntheticProfile.Hardened, "anon:test");

        Assert.True(built.Anonymised);
        Assert.Equal("anon:test", built.SystemInfo?.MachineName);
        Assert.Equal(3600, built.SystemInfo?.UptimeSeconds);
    }

    [Fact]
    public void The_source_capture_is_left_untouched()
    {
        var source = WithKey(SnapshotKeys.Value(Key, "Flag"));
        var rule = Rule(new CheckSpec(CheckKind.Registry, Key, "Flag", CheckOperator.Equals, "1", "0"));

        SyntheticSnapshot.Build(source, [rule], SyntheticProfile.Hardened, "anon:test");

        Assert.Equal(ReadStatus.NotFound, source.Registry[SnapshotKeys.Value(Key, "Flag")].Status);
    }

    private static MachineSnapshot Base(IReadOnlyList<Rule> rules)
    {
        var snapshot = new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default };

        foreach (var rule in rules)
        {
            var key = rule.Check.Kind == CheckKind.RegistryKey
                ? SnapshotKeys.Existence(rule.Check.Path)
                : SnapshotKeys.Value(rule.Check.Path, rule.Check.ValueName!);

            snapshot.Registry[key] = RegistryRead.NotFound;
        }

        return snapshot;
    }

    private static MachineSnapshot WithKey(string key) => new()
    {
        SystemInfo = FakeSystemInfoProvider.Default,
        Registry = { [key] = RegistryRead.NotFound },
    };

    private static MachineSnapshot Build(IReadOnlyList<Rule> rules, SyntheticProfile profile) =>
        SyntheticSnapshot.Build(
            WithKey(SnapshotKeys.Value(Key, "Flag")), rules, profile, "anon:test");

    private static Rule Rule(CheckSpec check) =>
        new("TEST-001", "Un contrôle", Severity.High, "test", "Parce que.", [], check, null);
}
