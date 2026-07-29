using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Rempart.Core.Providers;

namespace Rempart.Windows.Wmi;

/// <summary>
/// WMI client built on COM interop generated at compile time.
///
/// Answers the question left open since M0: <c>System.Management</c> does not
/// survive Native AOT, but WMI stays reachable by going straight to its COM
/// interfaces. No reflection at runtime, hence no trim warning and no surprise
/// after publishing.
///
/// Most of the namespaces we target require elevation. A refusal maps to
/// <see cref="ReadStatus.AccessDenied"/>, which the engine renders as
/// « non vérifiable »: the scan could not look, the machine is not at fault.
/// A failure is not a refusal and does not get to look like one — see
/// <see cref="Classify"/>.
/// </summary>
public sealed unsafe partial class LiveWmiProvider : IWmiProvider
{
    private static readonly Guid ClsidWbemLocator = new("4590f811-1d3a-11d0-891f-00aa004b2e24");
    private static readonly Guid IidWbemLocator = new("dc12a687-737f-11cf-884d-00aa004b2e24");

    private const int WbemFlagForwardOnly = 0x20;
    private const int WbemFlagReturnImmediately = 0x10;
    private const int WbemInfiniteTimeout = -1;

    private const int RpcCAuthnLevelDefault = 0;
    private const int RpcCImpLevelImpersonate = 3;
    private const int EoacNone = 0;

    // Named rather than inlined: a bare hexadecimal literal cannot be reviewed, and these
    // codes sit one digit apart from unrelated ones — 0x80041062 is the privilege refusal,
    // 0x80041045 is WBEM_E_SERVER_TOO_BUSY, which must never advise elevation. Values read
    // from wbemcli.h and winerror.h, not from memory.
    private const uint WbemENotFound = 0x80041002;
    private const uint WbemEAccessDenied = 0x80041003;
    private const uint WbemEInvalidNamespace = 0x8004100E;
    private const uint WbemEPrivilegeNotHeld = 0x80041062;
    private const uint EAccessDenied = 0x80070005;

    [LibraryImport("ole32.dll")]
    private static partial int CoInitializeSecurity(
        IntPtr descriptor, int authServices, IntPtr services, IntPtr reserved1,
        int authnLevel, int impLevel, IntPtr authList, int capabilities, IntPtr reserved3);

    [LibraryImport("ole32.dll")]
    private static partial int CoSetProxyBlanket(
        IntPtr proxy, int authnService, int authzService, IntPtr principalName,
        int authnLevel, int impLevel, IntPtr authInfo, int capabilities);

    /// <summary>
    /// COM security initialisation only counts once per process, and failing a
    /// second time is normal — hence the ignored result.
    /// </summary>
    private static readonly bool SecurityInitialised = InitialiseSecurity();

    private static bool InitialiseSecurity()
    {
        CoInitializeSecurity(
            IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero,
            RpcCAuthnLevelDefault, RpcCImpLevelImpersonate, IntPtr.Zero, EoacNone, IntPtr.Zero);
        return true;
    }

    [LibraryImport("oleaut32.dll")]
    private static partial int VariantClear(ref Variant value);

    [LibraryImport("ole32.dll")]
    private static partial int CoCreateInstance(
        in Guid clsid, IntPtr outer, int context, in Guid iid, out IntPtr instance);

    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties)
    {
        _ = SecurityInitialised;

        try
        {
            return Execute(namespacePath, className, properties);
        }
        catch (COMException ex)
        {
            return Classify(ex);
        }
        catch (Exception ex)
        {
            // A failure must not interrupt the scan, but neither must it disguise
            // itself as an access denial: that confusion is what once led to the
            // wrong conclusion that elevation would be enough.
            return WmiRead.Failed($"{ex.GetType().Name} : {ex.Message}");
        }
    }

    /// <summary>
    /// Turns a COM failure into a read status.
    ///
    /// <para>
    /// The list used to end on <c>_ => WmiRead.AccessDenied</c>, so every HRESULT nobody had
    /// thought of borrowed the meaning « relancer en administrateur ». A damaged repository
    /// (<c>WBEM_E_INVALID_CLASS</c>) and a Winmgmt service refusing to start
    /// (<c>RPC_S_SERVER_UNAVAILABLE</c>) therefore asked for an elevation the user already
    /// had, on every WMI-backed surface at once — drivers, processes, unquoted service
    /// paths, <c>root\subscription</c> — and <see cref="WmiRead.AccessDenied"/> carries no
    /// diagnostic, so the report had nothing to contradict it with. That is the invariant
    /// this very file documents, broken inside it: the <c>catch (Exception)</c> below
    /// refused the disguise the arm above it applied.
    /// </para>
    ///
    /// <para>
    /// Hence the shape rather than the entries: what is enumerated is only what a code
    /// genuinely means, and the default arm is the honest one. A HRESULT left off the list
    /// now surfaces as a failure carrying its own code — the user has something to search
    /// for, and this mapping cannot silently rot as WMI grows new ways to fail.
    /// </para>
    /// </summary>
    internal static WmiRead Classify(COMException ex) => (uint)ex.HResult switch
    {
        // The scan is not elevated, or lacks a privilege the namespace demands: elevation
        // is the answer, and these are the only codes that say so.
        WbemEAccessDenied or EAccessDenied or WbemEPrivilegeNotHeld => WmiRead.AccessDenied,

        // The namespace or the class is not there, which is what a Windows edition lacking
        // the feature answers. Absence, not refusal.
        WbemEInvalidNamespace or WbemENotFound => WmiRead.NotFound,

        _ => WmiRead.Failed($"COM 0x{(uint)ex.HResult:X8} : {ex.Message}"),
    };

    private static WmiRead Execute(
        string namespacePath, string className, IReadOnlyList<string> properties)
    {
        var locator = CreateLocator();

        if (locator.ConnectServer(namespacePath, null, null, null, 0, null, IntPtr.Zero,
                out var services) is var connect && connect < 0)
        {
            throw new COMException($"ConnectServer({namespacePath})", connect);
        }

        // The blanket specifies the caller's identity. It is only essential for
        // remote connections: locally, CoInitializeSecurity is enough. Its failure
        // must therefore not doom the query.
        TrySetBlanket(services);

        var query = $"SELECT * FROM {className}";
        if (services.ExecQuery("WQL", query, WbemFlagForwardOnly | WbemFlagReturnImmediately,
                IntPtr.Zero, out var enumerator) is var exec && exec < 0)
        {
            throw new COMException(query, exec);
        }

        TrySetBlanket(enumerator);

        var instances = new List<WmiInstance>();
        var buffer = new IntPtr[1];

        while (enumerator.Next(WbemInfiniteTimeout, 1, buffer, out var returned) >= 0 && returned == 1)
        {
            var instance = ComInterfaceMarshaller<IWbemClassObject>.ConvertToManaged(
                (void*)buffer[0]);

            if (instance is not null)
            {
                instances.Add(ReadProperties(instance, properties));
            }

            Marshal.Release(buffer[0]);
        }

        return instances.Count == 0 ? WmiRead.NotFound : WmiRead.Found(instances);
    }

    private static WmiInstance ReadProperties(
        IWbemClassObject instance, IReadOnlyList<string> names)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in names)
        {
            var variant = default(Variant);

            if (instance.Get(name, 0, ref variant, IntPtr.Zero, IntPtr.Zero) < 0)
            {
                continue;
            }

            try
            {
                if (Decode(variant) is { } text)
                {
                    values[name] = text;
                }
            }
            finally
            {
                // An unreleased BSTR leaks on every read, hence on every scan.
                VariantClear(ref variant);
            }
        }

        return new WmiInstance(values);
    }

    /// <summary>
    /// Only the types WMI returns for the properties we query. An uncovered type is
    /// ignored rather than rendered approximately: better an absent property, hence
    /// a « non vérifiable » verdict, than a wrong value.
    /// </summary>
    private static string? Decode(Variant variant) => variant.Vt switch
    {
        VariantType.Empty or VariantType.Null => null,

        VariantType.Bstr => Marshal.PtrToStringBSTR(variant.Data),

        VariantType.Bool => ((short)variant.Data.ToInt64()) != 0 ? "true" : "false",

        VariantType.I2 or VariantType.I4 or VariantType.Int =>
            ((int)variant.Data.ToInt64()).ToString(CultureInfo.InvariantCulture),

        VariantType.I1 or VariantType.Ui1 or VariantType.Ui2
            or VariantType.Ui4 or VariantType.Uint =>
            ((uint)variant.Data.ToInt64()).ToString(CultureInfo.InvariantCulture),

        _ => null,
    };

    /// <summary>
    /// <c>Marshal.GetIUnknownForObject</c> requires the runtime's built-in COM
    /// support, absent under Native AOT: there it always throws.
    ///
    /// This is the bug that left WMI dead in the published binary. The exception
    /// bubbled up to the catch-all, translated into "access denied" — so every WMI
    /// check rendered « non vérifiable », even elevated, with nothing to tell this
    /// bug apart from missing rights.
    ///
    /// The query works without a blanket locally: the failure is ignored.
    /// </summary>
    private static void TrySetBlanket(object proxy)
    {
        try
        {
            var pointer = Marshal.GetIUnknownForObject(proxy);
            try
            {
                CoSetProxyBlanket(pointer, 10 /* RPC_C_AUTHN_WINNT */, 0, IntPtr.Zero,
                    RpcCAuthnLevelDefault, RpcCImpLevelImpersonate, IntPtr.Zero, EoacNone);
            }
            finally
            {
                Marshal.Release(pointer);
            }
        }
        catch (Exception)
        {
            // No effect locally: the connection keeps the process identity.
        }
    }

    /// <summary>
    /// Instantiated through CoCreateInstance rather than Type.GetTypeFromCLSID: the
    /// latter goes through reflection and the AOT compiler refuses it. The
    /// IsAotCompatible guard flagged it at compile time, where the problem would
    /// otherwise only have surfaced after publishing.
    /// </summary>
    private static IWbemLocator CreateLocator()
    {
        const int ClsCtxInprocServer = 1;

        var result = CoCreateInstance(
            in ClsidWbemLocator, IntPtr.Zero, ClsCtxInprocServer, in IidWbemLocator, out var pointer);

        if (result < 0 || pointer == IntPtr.Zero)
        {
            throw new COMException("CoCreateInstance(WbemLocator)", result);
        }

        try
        {
            return ComInterfaceMarshaller<IWbemLocator>.ConvertToManaged((void*)pointer)
                ?? throw new COMException("WbemLocator non convertible", -1);
        }
        finally
        {
            Marshal.Release(pointer);
        }
    }
}
