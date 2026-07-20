using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

internal sealed class FakeWmiProvider(WmiRead read) : IWmiProvider
{
    public static FakeWmiProvider With(params string[] values) =>
        new(WmiRead.Found([.. values.Select(v => new WmiInstance(
            new Dictionary<string, string> { ["ProtectionStatus"] = v }))]));

    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties) => read;
}

public sealed class WmiCheckTests
{
    [Fact]
    public void A_single_conforming_instance_passes()
    {
        Assert.Equal(VerdictStatus.Pass, Evaluate(FakeWmiProvider.With("1")).Status);
    }

    [Fact]
    public void Every_instance_must_conform()
    {
        // Un seul disque en clair suffit a exposer ce qu'il porte : le controle porte
        // sur tous les volumes, pas sur le premier.
        var verdict = Evaluate(FakeWmiProvider.With("1", "0"));

        Assert.Equal(VerdictStatus.Fail, verdict.Status);
        Assert.Contains("0", verdict.Observed!, StringComparison.Ordinal);
    }

    [Fact]
    public void Access_denied_yields_unknown_never_a_failure()
    {
        // L'espace de noms BitLocker exige l'elevation. Sans droits, conclure
        // reprocherait a la machine ce que le scan n'a pas pu regarder.
        var verdict = Evaluate(new FakeWmiProvider(WmiRead.AccessDenied));

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
    }

    [Fact]
    public void No_instance_is_unverifiable_rather_than_non_compliant()
    {
        // BitLocker absent d'une edition Famille n'est pas une non-conformite,
        // c'est une absence de sujet.
        Assert.Equal(VerdictStatus.Unknown, Evaluate(new FakeWmiProvider(WmiRead.NotFound)).Status);
    }

    [Fact]
    public void Without_a_provider_the_check_stays_unverifiable()
    {
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        Assert.Equal(VerdictStatus.Unknown, RuleEvaluator.Evaluate(Rule(), providers).Status);
    }

    [Fact]
    public void A_path_without_a_class_is_rejected_at_load()
    {
        var yaml = """
            - id: TEST-WMI
              title: Un controle WMI
              severity: high
              domain: test
              rationale: Une justification suffisamment longue pour passer la validation.
              check:
                type: wmi
                path: root\CIMV2
                value: Caption
                operator: equals
                expect: x
            """;

        Assert.Contains("espaceDeNoms:Classe", Assert.Throws<RuleFormatException>(
            () => RuleLoader.Load(yaml)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_check_without_a_property_is_rejected_at_load()
    {
        var yaml = """
            - id: TEST-WMI
              title: Un controle WMI
              severity: high
              domain: test
              rationale: Une justification suffisamment longue pour passer la validation.
              check:
                type: wmi
                path: root\CIMV2:Win32_OperatingSystem
                operator: exists
            """;

        Assert.Contains("value", Assert.Throws<RuleFormatException>(
            () => RuleLoader.Load(yaml)).Message, StringComparison.Ordinal);
    }

    private static Verdict Evaluate(IWmiProvider wmi) =>
        RuleEvaluator.Evaluate(Rule(), new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(), null, null, wmi));

    private static Rule Rule() =>
        new("TEST-WMI", "Un controle", Severity.High, "encryption", "Parce que.", [],
            new CheckSpec(CheckKind.Wmi,
                @"root\CIMV2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume",
                "ProtectionStatus", CheckOperator.Equals, "1", null), null);
}
