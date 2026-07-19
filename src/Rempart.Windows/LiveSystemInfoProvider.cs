using System.Runtime.InteropServices;
using System.Security.Principal;
using Rempart.Core.Providers;
using CoreSystemInfo = Rempart.Core.Providers.SystemInfo;

namespace Rempart.Windows;

public sealed partial class LiveSystemInfoProvider : ISystemInfoProvider
{
    private enum FirmwareType
    {
        Unknown = 0,
        Bios = 1,
        Uefi = 2,
        Max = 3,
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFirmwareType(out uint firmwareType);

    public CoreSystemInfo Read() => new(
        MachineName: Environment.MachineName,
        OsVersion: Environment.OSVersion.Version.ToString(),
        Is64BitOperatingSystem: Environment.Is64BitOperatingSystem,
        IsElevated: IsElevated(),
        ProcessorCount: Environment.ProcessorCount,
        UptimeSeconds: Environment.TickCount64 / 1000,
        FirmwareType: ReadFirmwareType());

    private static string ReadFirmwareType()
    {
        if (!GetFirmwareType(out var raw))
        {
            return "unknown";
        }

        return (FirmwareType)raw switch
        {
            FirmwareType.Bios => "bios",
            FirmwareType.Uefi => "uefi",
            _ => "unknown",
        };
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            // Ne pas prétendre à l'élévation en cas de doute : le rapport signalera
            // un scan restreint plutôt que de laisser croire à un inventaire complet.
            return false;
        }
    }
}
