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

    /// <summary>Join status returned by <c>NetGetJoinInformation</c>.</summary>
    private enum JoinStatus
    {
        Unknown = 0,
        Unjoined = 1,
        Workgroup = 2,
        Domain = 3,
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFirmwareType(out uint firmwareType);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetGetJoinInformation(
        string? server, out IntPtr nameBuffer, out int joinStatus);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    public CoreSystemInfo Read() => new(
        MachineName: Environment.MachineName,
        OsVersion: Environment.OSVersion.Version.ToString(),
        Is64BitOperatingSystem: Environment.Is64BitOperatingSystem,
        IsElevated: IsElevated(),
        ProcessorCount: Environment.ProcessorCount,
        UptimeSeconds: Environment.TickCount64 / 1000,
        FirmwareType: ReadFirmwareType(),
        IsDomainJoined: ReadDomainJoined());

    /// <summary>
    /// Queries the API rather than the registry: several registry values can suggest
    /// domain membership on a standalone machine, notably a manually configured DNS
    /// suffix.
    /// </summary>
    private static bool ReadDomainJoined()
    {
        var buffer = IntPtr.Zero;
        try
        {
            // 0 = NERR_Success.
            if (NetGetJoinInformation(null, out buffer, out var status) != 0)
            {
                return false;
            }

            return (JoinStatus)status == JoinStatus.Domain;
        }
        catch (Exception)
        {
            // When in doubt, treat the machine as standalone: domain-conditioned
            // rules will simply be marked not applicable, which is less harmful than
            // hardening applied by mistake.
            return false;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NetApiBufferFree(buffer);
            }
        }
    }

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
            // Do not claim elevation when in doubt: the report will indicate a
            // restricted scan rather than suggest a complete inventory.
            return false;
        }
    }
}
