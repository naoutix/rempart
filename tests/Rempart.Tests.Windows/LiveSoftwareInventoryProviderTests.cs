using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Test machine réelle : on ne connaît pas les logiciels du runner, on vérifie que la
/// lecture ne lève pas, rend des entrées cohérentes, et trouve au moins des désinstallations
/// (toute machine Windows en a).
/// </summary>
public sealed class LiveSoftwareInventoryProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var software = new LiveSoftwareInventoryProvider().Read();

        Assert.NotNull(software);
        Assert.All(software, entry => Assert.False(string.IsNullOrEmpty(entry.Name)));

        // Toute installation de Windows porte des entrées de désinstallation.
        Assert.Contains(software, entry => entry.Source == SoftwareSource.Uninstall);
    }
}
