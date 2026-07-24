using System.Runtime.InteropServices;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Queries the service control manager via <c>advapi32</c>.
///
/// The start mode could be read from the registry, but not the current state: a
/// service declared automatic can be stopped, because it failed or someone stopped it.
/// For Windows Update or the firewall, that gap is exactly what an audit must
/// establish.
///
/// The native structs are not marshaled: only two integers at fixed offsets matter in
/// each, and reading them from a byte buffer avoids any memory layout question — and
/// with it any silent error under Native AOT.
/// </summary>
public sealed partial class LiveServiceStateProvider : IServiceStateProvider
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;

    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorAccessDenied = 5;
    private const int ErrorInsufficientBuffer = 122;

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW",
        StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial IntPtr OpenScManager(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW",
        StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial IntPtr OpenService(IntPtr manager, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceStatusEx(
        IntPtr service, int infoLevel, byte[]? buffer, int bufferSize, out int needed);

    [LibraryImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceConfig(
        IntPtr service, byte[]? buffer, int bufferSize, out int needed);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);

    public ServiceRead Read(string serviceName)
    {
        var manager = OpenScManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return ServiceRead.AccessDenied;
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceQueryStatus | ServiceQueryConfig);
            if (service == IntPtr.Zero)
            {
                // A missing service and denied access call for different follow-ups:
                // uninstalling a service that does not exist makes no sense, and a
                // denial signals that the scan should be rerun as administrator.
                return Marshal.GetLastWin32Error() switch
                {
                    ErrorServiceDoesNotExist => ServiceRead.NotInstalled,
                    _ => ServiceRead.AccessDenied,
                };
            }

            try
            {
                var state = ReadState(service);
                var startMode = ReadStartMode(service);

                return state is null || startMode is null
                    ? ServiceRead.AccessDenied
                    : ServiceRead.Found(new ServiceInfo(serviceName, state.Value, startMode.Value));
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>SERVICE_STATUS_PROCESS: dwCurrentState at offset 4.</summary>
    private static ServiceState? ReadState(IntPtr service)
    {
        var buffer = Allocate((byte[]? size, out int need) => QueryServiceStatusEx(
            service, ScStatusProcessInfo, size, size?.Length ?? 0, out need), out _);

        if (buffer is null)
        {
            return null;
        }

        return BitConverter.ToInt32(buffer, 4) switch
        {
            1 => ServiceState.Stopped,
            4 => ServiceState.Running,
            7 => ServiceState.Paused,
            _ => ServiceState.Unknown,
        };
    }

    /// <summary>QUERY_SERVICE_CONFIG: dwStartType at offset 4.</summary>
    private static ServiceStartMode? ReadStartMode(IntPtr service)
    {
        var buffer = Allocate((byte[]? size, out int need) => QueryServiceConfig(
            service, size, size?.Length ?? 0, out need), out _);

        if (buffer is null)
        {
            return null;
        }

        return BitConverter.ToInt32(buffer, 4) switch
        {
            0 => ServiceStartMode.Boot,
            1 => ServiceStartMode.System,
            2 => ServiceStartMode.Automatic,
            3 => ServiceStartMode.Manual,
            4 => ServiceStartMode.Disabled,
            _ => ServiceStartMode.Unknown,
        };
    }

    /// <summary>
    /// Two-step call, as the API requires: once to learn the required size, then again
    /// with a buffer of that size.
    /// </summary>
    private static byte[]? Allocate(TryQuery query, out int size)
    {
        size = 0;

        if (query(null, out var needed) || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
        {
            return null;
        }

        var buffer = new byte[needed];
        size = needed;

        return query(buffer, out _) ? buffer : null;
    }

    private delegate bool TryQuery(byte[]? buffer, out int needed);
}
