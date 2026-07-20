using System.Runtime.InteropServices;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Interroge le gestionnaire de services par <c>advapi32</c>.
///
/// Le mode de démarrage se lirait au registre, mais pas l'état courant : un service
/// déclaré automatique peut être arrêté, parce qu'il a échoué ou qu'on l'a stoppé. Pour
/// Windows Update ou le pare-feu, c'est précisément cet écart qu'un audit doit établir.
///
/// Les structures natives ne sont pas marshalées : seuls deux entiers à décalage fixe
/// nous intéressent dans chacune, et les lire dans un tampon d'octets évite toute
/// question de disposition mémoire — donc toute erreur silencieuse sous Native AOT.
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
                // Service absent et accès refusé appellent des suites différentes :
                // désinstaller un service qui n'existe pas n'a pas de sens, et un
                // refus signale un scan à relancer en administrateur.
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

    /// <summary>SERVICE_STATUS_PROCESS : dwCurrentState au décalage 4.</summary>
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

    /// <summary>QUERY_SERVICE_CONFIG : dwStartType au décalage 4.</summary>
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
    /// Appel en deux temps, comme l'exige l'API : une première fois pour connaître la
    /// taille nécessaire, une seconde avec le tampon dimensionné.
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
