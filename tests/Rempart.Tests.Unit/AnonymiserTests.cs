using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// Les fixtures finissent versionnées. Un instantané brut porte hostname, numéro de
/// série et propriétaire enregistré : c'est de l'identification de machine, pas de la
/// donnée de test.
/// </summary>
public sealed class AnonymiserTests
{
    [Fact]
    public void Firewall_rule_application_paths_are_scrubbed()
    {
        // Une règle de pare-feu peut viser une application installée sous un profil
        // utilisateur : son chemin nomme alors quelqu'un, et la capture destinée à voyager
        // le porterait. Les chemins système (%SystemRoot%) n'ont rien à cacher et restent
        // lisibles.
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

        // Anonymiser au-delà du nécessaire viderait les fixtures de leur intérêt.
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
