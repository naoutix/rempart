using Rempart.Core.Collectors;

namespace Rempart.Tests.Unit;

/// <summary>
/// On Windows 11, the <c>ProductName</c> registry value still reports
/// "Windows 10" — Microsoft never fixed it. Reporting that value as-is would
/// break any rule conditioned on the OS version.
/// </summary>
public sealed class OsNameTests
{
    [Theory]
    [InlineData("26200", "Windows 10 Pro", "Windows 11 Pro")]
    [InlineData("22000", "Windows 10 Pro", "Windows 11 Pro")]
    [InlineData("22631", "Windows 10 Home", "Windows 11 Home")]
    public void Windows_11_is_detected_despite_the_registry_saying_otherwise(
        string build, string productName, string expected)
    {
        Assert.Equal(expected, InventoryCollector.DeriveOsName(build, productName));
    }

    [Theory]
    [InlineData("19045", "Windows 10 Pro", "Windows 10 Pro")]
    [InlineData("10240", "Windows 10 Enterprise", "Windows 10 Enterprise")]
    public void Windows_10_stays_windows_10(string build, string productName, string expected)
    {
        Assert.Equal(expected, InventoryCollector.DeriveOsName(build, productName));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("pas-un-nombre")]
    public void Unreadable_build_falls_back_to_the_raw_registry_value(string? build)
    {
        // Return the raw value rather than invent a version.
        Assert.Equal("Windows 10 Pro", InventoryCollector.DeriveOsName(build, "Windows 10 Pro"));
    }

    [Fact]
    public void Unknown_build_range_falls_back_too()
    {
        Assert.Equal("Windows 8.1", InventoryCollector.DeriveOsName("9600", "Windows 8.1"));
    }

    /// <summary>
    /// Build 26100 is shared by Windows 11 24H2 and Windows Server 2025, so the number
    /// alone cannot tell them apart. The first row is a real reading, taken from the CI
    /// runner on 2026-08-02: build 26100, <c>InstallationType=Server</c>,
    /// <c>ProductName=Windows Server 2025 Datacenter</c> — where the derivation used to
    /// answer "Windows 11 Windows Server 2025 Datacenter".
    ///
    /// On a server the registry value is accurate and is returned untouched: the lie
    /// this derivation exists to correct is a client one.
    /// </summary>
    [Theory]
    [InlineData("Server", "26100", "Windows Server 2025 Datacenter")]
    [InlineData("Server Core", "20348", "Windows Server 2022 Standard")]
    [InlineData("WinPE", "26100", "Windows 10 Pro")]
    public void A_non_client_install_is_never_given_a_client_family(
        string installationType, string build, string productName)
    {
        Assert.Equal(
            productName,
            InventoryCollector.DeriveOsName(build, productName, installationType));
    }

    [Fact]
    public void A_client_install_is_still_corrected()
    {
        Assert.Equal(
            "Windows 11 Pro",
            InventoryCollector.DeriveOsName("26100", "Windows 10 Pro", "Client"));
    }

    /// <summary>
    /// Every capture taken before this field was consulted carries no installation type,
    /// and every one of them was taken on a workstation. Absence keeps the previous
    /// behaviour rather than dropping those captures to the raw registry value.
    /// </summary>
    [Fact]
    public void An_absent_installation_type_keeps_the_client_derivation()
    {
        Assert.Equal(
            "Windows 11 Pro",
            InventoryCollector.DeriveOsName("26100", "Windows 10 Pro", null));
    }
}
