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
}
