using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// Fixtures end up under version control. A raw snapshot carries the hostname, serial
/// number and registered owner: that is machine identification, not test data.
/// </summary>
public sealed class AnonymiserTests
{
    [Fact]
    public void Firewall_rule_application_paths_are_scrubbed()
    {
        // A firewall rule can target an application installed under a user profile: its
        // path then names someone, and a capture meant to travel would carry it. System
        // paths (%SystemRoot%) have nothing to hide and stay readable.
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Firewall = new FirewallState(
                [
                    new FirewallRule(true, "In", "Allow", 6, "5000", ["Public"],
                        @"C:\Users\leoar\AppData\Local\App\app.exe"),
                    new FirewallRule(true, "In", "Allow", 6, "445", ["Public"],
                        @"%SystemRoot%\system32\svchost.exe"),
                ],
                PublicFirewallEnabled: true, PublicDefaultInboundAllow: false),
        };

        var rules = Anonymiser.Apply(snapshot).Firewall!.Rules;

        Assert.DoesNotContain("leoar", rules[0].App, StringComparison.Ordinal);
        Assert.EndsWith(@"\App\app.exe", rules[0].App, StringComparison.Ordinal);
        Assert.Equal(@"%SystemRoot%\system32\svchost.exe", rules[1].App);
    }

    [Fact]
    public void Machine_name_is_replaced()
    {
        var snapshot = new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default };

        Anonymiser.Apply(snapshot);

        Assert.NotEqual("POSTE-TEST", snapshot.SystemInfo!.MachineName);
        Assert.StartsWith("anon:", snapshot.SystemInfo.MachineName, StringComparison.Ordinal);
        Assert.True(snapshot.Anonymised);
    }

    [Theory]
    [InlineData("SystemSerialNumber")]
    [InlineData("RegisteredOwner")]
    [InlineData("ProductId")]
    public void Identifying_values_are_replaced(string valueName)
    {
        var snapshot = WithValue(valueName, "ABC123");

        Anonymiser.Apply(snapshot);

        Assert.StartsWith("anon:", Text(snapshot, valueName), StringComparison.Ordinal);
    }

    [Fact]
    public void Ordinary_values_are_left_alone()
    {
        var snapshot = WithValue("ProductName", "Windows 11 Pro");

        Anonymiser.Apply(snapshot);

        // Anonymising beyond what is necessary would drain the fixtures of their value.
        Assert.Equal("Windows 11 Pro", Text(snapshot, "ProductName"));
    }

    [Fact]
    public void Hashing_is_stable_so_captures_stay_comparable()
    {
        Assert.Equal(Anonymiser.Hash("POSTE-A"), Anonymiser.Hash("POSTE-A"));
        Assert.NotEqual(Anonymiser.Hash("POSTE-A"), Anonymiser.Hash("POSTE-B"));
    }

    [Fact]
    public void Hash_is_truncated_beyond_reversal()
    {
        Assert.Equal(17, Anonymiser.Hash("POSTE-A").Length);
    }

    private static MachineSnapshot WithValue(string valueName, string text) => new()
    {
        Registry =
        {
            [$@"HKLM\SOFTWARE\Test||{valueName}"] = RegistryRead.Found(RegistryValue.OfText(text)),
        },
    };

    private static string? Text(MachineSnapshot snapshot, string valueName) =>
        snapshot.Registry[$@"HKLM\SOFTWARE\Test||{valueName}"].Value?.Text;
}
