using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Enumerates loaded kernel drivers via WMI (<c>Win32_SystemDriver</c>).
///
/// <para>
/// The obvious route — <c>EnumDeviceDrivers</c> — is a trap since Windows 10: without
/// elevation it returns the <b>count</b> of drivers but zeroes their kernel addresses,
/// a protection against kernel address disclosure (KASLR). Without an address there is
/// no path, so the enumeration returned zero drivers while appearing to succeed.
/// </para>
///
/// <para>
/// <c>Win32_SystemDriver</c> provides the file path directly, without elevation and
/// without ever exposing a kernel address. Only <c>Running</c> drivers are kept: a
/// driver that is installed but stopped does not execute, and reporting it as loaded
/// would be wrong.
/// </para>
/// </summary>
public sealed class LiveDriverProvider(IWmiProvider wmi) : IDriverProvider
{
    private const string Namespace = @"root\CIMV2";

    public LiveDriverProvider()
        : this(new Wmi.LiveWmiProvider())
    {
    }

    public IReadOnlyList<LoadedDriver> Enumerate()
    {
        var read = wmi.Query(Namespace, "Win32_SystemDriver", ["Name", "PathName", "State"]);

        if (read.Status != ReadStatus.Found)
        {
            return [];
        }

        var drivers = new List<LoadedDriver>();

        foreach (var instance in read.Instances)
        {
            // Only drivers that are currently running: the others sit on disk without
            // being loaded, and the surface to assess is what actually runs.
            if (!string.Equals(instance.Find("State"), "Running", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var path = instance.Find("PathName");
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            drivers.Add(new LoadedDriver(
                instance.Find("Name") ?? Path.GetFileName(path), path));
        }

        return drivers;
    }
}
