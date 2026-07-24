using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// The fixture factory is itself under test: it produces the data every replay
/// test relies on. A broken factory would silently invalidate the whole suite.
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
            .Select(r => RuleEvaluator.Evaluate(r, new ProviderSet(
                new SnapshotRegistryProvider(built),
                new SnapshotSystemInfoProvider(built),
                new SnapshotServiceStateProvider(built),
                new SnapshotSecurityPolicyProvider(built),
                new SnapshotWmiProvider(built)), built.SystemInfo))
            .ToList();

        Assert.DoesNotContain(verdicts, v => v.Status is VerdictStatus.Fail or VerdictStatus.Unknown);
    }

    [Fact]
    public void The_defaults_profile_removes_every_hardening_key()
    {
        var rules = RuleCatalog.Load();
        var built = SyntheticSnapshot.Build(
            Base(rules), rules, SyntheticProfile.WindowsDefaults, "anon:test");

        // The profile must exercise Windows-default semantics: if keys remained,
        // the fixture would test something other than what it claims. Services
        // and policy facts are excluded: their state is directly observable,
        // there is no "Windows default" to reveal by removing a key. The profile
        // leaves them as the capture saw them.
        var registryRules = rules.Where(r =>
            r.Check.Kind is CheckKind.Registry or CheckKind.RegistryKey);

        Assert.All(registryRules, rule =>
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
        // Adding them would hide a capture gap instead of revealing it: that
        // exact gap is what broke cross-context replay before.
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
        // A fixture versioned in a public repository can neither carry a machine
        // identifier nor freeze a duration that changes on every run.
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
        var facts = new Dictionary<string, string>(StringComparer.Ordinal);
        var snapshot = new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default };

        foreach (var rule in rules)
        {
            if (rule.Check.Kind == CheckKind.Service)
            {
                snapshot.Services[rule.Check.Path] = ServiceRead.NotInstalled;
                continue;
            }

            if (rule.Check.Kind == CheckKind.Policy)
            {
                // A fact present but empty: the factory must replace it with a
                // satisfying value, not merely handle a missing dictionary.
                facts[rule.Check.Path] = "0";
                continue;
            }

            var key = rule.Check.Kind == CheckKind.RegistryKey
                ? SnapshotKeys.Existence(rule.Check.Path)
                : SnapshotKeys.Value(rule.Check.Path, rule.Check.ValueName!);

            snapshot.Registry[key] = RegistryRead.NotFound;
        }

        snapshot.Policy = new PolicyFacts(facts);
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
