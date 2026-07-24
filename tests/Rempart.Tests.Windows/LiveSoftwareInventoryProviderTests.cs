using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Real-machine test: the runner's installed software is unknown, so we check that the
/// read does not throw, returns consistent entries, and finds at least uninstall entries
/// (every Windows machine has some).
/// </summary>
public sealed class LiveSoftwareInventoryProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var software = new LiveSoftwareInventoryProvider().Read();

        Assert.NotNull(software);
        Assert.All(software, entry => Assert.False(string.IsNullOrEmpty(entry.Name)));

        // Every Windows installation carries uninstall entries.
        Assert.Contains(software, entry => entry.Source == SoftwareSource.Uninstall);
    }

    [Fact]
    public void Appx_entries_carry_a_package_family_name_as_identifier()
    {
        var software = new LiveSoftwareInventoryProvider().Read();
        var appx = software.Where(s => s.Source == SoftwareSource.Appx).ToList();

        // Every modern Windows machine has Appx packages, and each one has a PFN.
        Assert.NotEmpty(appx);
        Assert.All(appx, s => Assert.False(string.IsNullOrWhiteSpace(s.Identifier)));
    }
}
