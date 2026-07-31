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

    public DriverRead Enumerate()
    {
        var read = wmi.Query(Namespace, "Win32_SystemDriver", ["Name", "PathName", "State"]);

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

        if (read.Status == ReadStatus.Found)
        {
            return DriverRead.Found(drivers);
        }

        // Never an empty list where the read is: this is the surface a BYOVD attack lands
        // on, and "no drivers" would read as a clean machine rather than as a failed read.
        //
        // What is handed over is what the walk did collect, which used to be discarded here.
        // A WMI enumeration breaks one object at a time, so a driver already returned before
        // the provider faulted was dropped along with the failure that followed it — the
        // silence DET-WMI-MUET closed, re-entered from the other side.
        //
        // The status AND the diagnostic are forwarded untouched, the second one included when
        // it is null. That null is not a missing sentence to be helpful about: on this channel
        // it is the message. WmiRead spells a denial as AccessDenied carrying no reason and
        // every other failure as one carrying the code, which is the single inference #166
        // kept because LiveWmiProvider.Classify writes it down. Filling the silence in here
        // erased it one layer below the collector that reads it, so a refused root\CIMV2 came
        // back classified as a repository failure — while the sentence substituted underneath
        // said « relancer en administrateur ». The collector holds the fallback wording for a
        // read that said nothing, which is where a sentence for a silence belongs.
        return new DriverRead(read.Status, drivers, read.Diagnostic);
    }
}
