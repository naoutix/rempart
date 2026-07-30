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
///
/// A failure is not a refusal and does not get to look like one — see
/// <see cref="Classify"/>.
/// </summary>
public sealed partial class LiveServiceStateProvider : IServiceStateProvider
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;

    // Named once and passed to Classify from the call site, because the mapping reads it:
    // the absence arm belongs to this call alone, and a typo on either side would silently
    // hand it back to the other three. See Classify.
    private const string OpenServiceApi = "OpenService";

    // Values read from winerror.h, not from memory. ERROR_SUCCESS is here because a call
    // can fail while GetLastError says nothing happened — see Allocate.
    private const int ErrorSuccess = 0;
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
            // The first of the four failure sites, all reporting through the same mapping,
            // and the bluntest of the three the audit found: this used to answer the bare
            // refusal whatever had happened, and the SCM fails to open for reasons that have
            // nothing to do with rights. Each site reads its code on the spot —
            // CloseServiceHandle sets the last error too, so a value fetched after the
            // finally blocks below would describe the close rather than the failure.
            return Classify("OpenSCManager", Marshal.GetLastWin32Error());
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceQueryStatus | ServiceQueryConfig);
            if (service == IntPtr.Zero)
            {
                return Classify(OpenServiceApi, Marshal.GetLastWin32Error());
            }

            try
            {
                // Asked one at a time so the diagnostic can name which query went quiet.
                // They failed together into a single « accès refusé » before, which said
                // neither which call nor on what.
                var state = ReadState(service, out var stateError);
                if (state is null)
                {
                    return Classify("QueryServiceStatusEx", stateError);
                }

                var startMode = ReadStartMode(service, out var configError);
                if (startMode is null)
                {
                    return Classify("QueryServiceConfig", configError);
                }

                return ServiceRead.Found(
                    new ServiceInfo(serviceName, state.Value, startMode.Value));
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

    /// <summary>
    /// Turns the Win32 code of a failed <c>advapi32</c> call into a read status.
    ///
    /// <para>
    /// The mapping used to end on <c>_ =&gt; ServiceRead.AccessDenied</c>, and two of the
    /// three failure sites did not even get that far — an SCM that would not open and a
    /// query that returned nothing were answered with the bare refusal, unread. So an
    /// unreachable service control manager, a dead RPC endpoint, a machine shutting down all
    /// arrived in the report under « non vérifiable — accès refusé », on every
    /// <c>type: service</c> rule at once: the one label whose only remedy is an elevation
    /// that would have changed nothing. That is the invariant CONTRIBUTING states — never
    /// translate a failure into an access denial — broken exactly as WMI broke it, one
    /// interface later. <c>ErrorAccessDenied</c> had been declared here since the file was
    /// written and never read once: the distinction was foreseen and never spelled out.
    /// </para>
    ///
    /// <para>
    /// Hence the shape rather than the entries: only codes whose meaning is verified are
    /// enumerated, and the default arm is the honest one. That is not a list waiting to be
    /// completed, and three of the four calls say so themselves — <c>OpenSCManager</c>,
    /// <c>OpenService</c> and <c>QueryServiceConfig</c> each close their return table with
    /// « others can be set by the registry functions that are called by the service control
    /// manager ». A code nobody enumerated therefore surfaces with its own number, which is
    /// something to search for, instead of borrowing a meaning.
    /// </para>
    /// </summary>
    internal static ServiceRead Classify(string api, int error) => error switch
    {
        // Absence, not refusal: uninstalling a service that does not exist makes no sense.
        // Documented for OpenService alone, which is the only one of the four that can
        // answer it — the SCM does not know the name yet, and the two queries hold a handle
        // to a service that was found. The guard is on the call and not on a comment,
        // because this is the one arm that does not answer Unknown: NotFound reaches
        // CheckReader as « absent », observed and compared, and « absent » against
        // « state equals running » is a critical Fail. Read from any other call it would
        // turn a read that failed into a verdict against the machine.
        ErrorServiceDoesNotExist when api == OpenServiceApi => ServiceRead.NotInstalled,

        // The one code that means « relancer en administrateur », and it is documented for
        // all four calls. Dropping it would be the mirror mistake: a real denial dressed as
        // a failure, and the one piece of advice that helps stops being given.
        ErrorAccessDenied => ServiceRead.AccessDenied,

        // A call that failed while the thread's last error says nothing went wrong. The
        // sizing step of Allocate lands here if it ever succeeds — nothing was written to a
        // buffer that does not exist — and « erreur Win32 0 » would render as
        // « l'opération a réussi », which is worse than saying nothing.
        ErrorSuccess => ServiceRead.Failed($"{api} : réponse inattendue, sans code d'erreur."),

        _ => ServiceRead.Failed(
            $"{api} : erreur Win32 {error} ({Marshal.GetPInvokeErrorMessage(error)})"),
    };

    /// <summary>SERVICE_STATUS_PROCESS: dwCurrentState at offset 4.</summary>
    private static ServiceState? ReadState(IntPtr service, out int error)
    {
        var buffer = Allocate((byte[]? size, out int need) => QueryServiceStatusEx(
            service, ScStatusProcessInfo, size, size?.Length ?? 0, out need), out error);

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
    private static ServiceStartMode? ReadStartMode(IntPtr service, out int error)
    {
        var buffer = Allocate((byte[]? size, out int need) => QueryServiceConfig(
            service, size, size?.Length ?? 0, out need), out error);

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
    ///
    /// <para>
    /// The Win32 code travels out beside the buffer, and that is the whole reason for the
    /// signature. It used to hand back a bare null on all three of its failure paths, and
    /// the caller, having nothing else, called every one of them an access denial — so a
    /// query refused by the handle's rights and one that broke while a machine was shutting
    /// down produced the same sentence. The <c>out</c> parameter it replaces held the buffer
    /// size, which neither caller ever read.
    /// </para>
    /// </summary>
    /// <returns>
    /// The filled buffer with <paramref name="error"/> at <c>ERROR_SUCCESS</c>, or null with
    /// the code that explains why.
    /// </returns>
    private static byte[]? Allocate(TryQuery query, out int error)
    {
        // The sizing call is *expected* to fail with ERROR_INSUFFICIENT_BUFFER: a null
        // buffer of length zero cannot hold either structure. A success therefore means the
        // API did not do what its own documentation promises, and nothing was written —
        // reported as the unexplained failure it is rather than given a borrowed code.
        if (query(null, out var needed))
        {
            error = ErrorSuccess;
            return null;
        }

        error = Marshal.GetLastWin32Error();
        if (error != ErrorInsufficientBuffer)
        {
            return null;
        }

        var buffer = new byte[needed];
        if (!query(buffer, out _))
        {
            error = Marshal.GetLastWin32Error();
            return null;
        }

        error = ErrorSuccess;
        return buffer;
    }

    private delegate bool TryQuery(byte[]? buffer, out int needed);
}
