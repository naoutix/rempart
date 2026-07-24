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
        // A single unencrypted disk exposes what it holds: the check covers all
        // volumes, not just the first one.
        var verdict = Evaluate(FakeWmiProvider.With("1", "0"));

        Assert.Equal(VerdictStatus.Fail, verdict.Status);
        Assert.Contains("0", verdict.Observed!, StringComparison.Ordinal);
    }

    [Fact]
    public void Access_denied_yields_unknown_never_a_failure()
    {
        // The BitLocker namespace requires elevation. Without rights, a verdict
        // would blame the machine for what the scan could not look at.
        var verdict = Evaluate(new FakeWmiProvider(WmiRead.AccessDenied));

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
    }

    [Fact]
    public void No_instance_is_unverifiable_rather_than_non_compliant()
    {
        // BitLocker missing on a Home edition is not a non-compliance; there is
        // simply nothing to check.
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
