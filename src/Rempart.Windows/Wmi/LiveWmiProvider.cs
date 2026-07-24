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
            // 0x80041003 WBEM_E_ACCESS_DENIED, 0x80070005 E_ACCESSDENIED:
            // the scan is not elevated. 0x8004100E: the namespace does not exist,
            // which happens on a Windows edition lacking the feature.
            return (uint)ex.HResult switch
            {
                0x80041003 or 0x80070005 => WmiRead.AccessDenied,
                0x8004100E or 0x80041002 => WmiRead.NotFound,
                _ => WmiRead.AccessDenied,
            };
        }
        catch (Exception ex)
        {
            // A failure must not interrupt the scan, but neither must it disguise
            // itself as an access denial: that confusion is what once led to the
            // wrong conclusion that elevation would be enough.
            return WmiRead.Failed($"{ex.GetType().Name} : {ex.Message}");
        }
    }

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
