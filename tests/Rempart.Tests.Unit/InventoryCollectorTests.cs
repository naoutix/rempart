using Rempart.Core.Collectors;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public sealed class InventoryCollectorTests
{
    private const string CurrentVersion = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private const string SecureBootState = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State";

    [Fact]
    public void Access_denied_is_reported_never_swallowed()
    {
        var registry = new FakeRegistryProvider().WithAccessDenied(CurrentVersion, "ProductName");

        var result = Collect(registry);

        // Un rapport qui cache ses trous est pire qu'un rapport incomplet.
        Assert.Equal(CollectorStatus.InsufficientPrivileges, result.Status);
        Assert.Contains(result.Diagnostics, d => d.Contains("Accès refusé", StringComparison.Ordinal));
        Assert.Null(result.Fields["os.registryProductName"]);
    }

    [Fact]
    public void Derived_os_name_comes_before_the_raw_registry_value()
    {
        // Ordre d'affichage, pas cosmétique : « Windows 10 Pro » en premiere ligne
        // sur une machine Windows 11 fait douter tout lecteur. La valeur dérivée
        // ouvre la liste, la valeur brute la ferme.
        var registry = new FakeRegistryProvider()
            .WithText(CurrentVersion, "ProductName", "Windows 10 Pro")
            .WithText(CurrentVersion, "CurrentBuildNumber", "26200");

        var keys = Collect(registry).Fields.Keys.ToList();

        Assert.Equal("os.name", keys[0]);
        Assert.Equal("os.registryProductName", keys[^1]);
    }

    [Theory]
    [InlineData(1, "enabled")]
    [InlineData(0, "disabled")]
    public void Secure_boot_state_is_read_from_the_registry(long raw, string expected)
    {
        var registry = new FakeRegistryProvider().WithNumber(SecureBootState, "UEFISecureBootEnabled", raw);

        Assert.Equal(expected, Collect(registry).Fields["security.secureBoot"]);
    }

    [Fact]
    public void Absent_secure_boot_key_means_unsupported_not_disabled()
    {
        // En démarrage Legacy/CSM la clé n'existe pas. « Absent » et « désactivé »
        // appellent des remédiations différentes : les confondre induirait en erreur.
        Assert.Equal("unsupported", Collect(new FakeRegistryProvider()).Fields["security.secureBoot"]);
    }

    [Fact]
    public void Unelevated_scan_is_flagged()
    {
        var providers = new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(FakeSystemInfoProvider.Default with { IsElevated = false }));

        var result = new InventoryCollector().Collect(providers);

        Assert.Equal("False", result.Fields["scan.elevated"]);
        Assert.Contains(result.Diagnostics, d => d.Contains("non élevé", StringComparison.Ordinal));
    }

    private static CollectorResult Collect(IRegistryProvider registry) =>
        new InventoryCollector().Collect(new ProviderSet(registry, new FakeSystemInfoProvider()));
}
