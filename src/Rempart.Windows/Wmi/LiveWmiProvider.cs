using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Rempart.Core.Providers;

namespace Rempart.Windows.Wmi;

/// <summary>
/// Client WMI bâti sur l'interop COM générée à la compilation.
///
/// Répond à la question laissée ouverte depuis M0 : <c>System.Management</c> ne
/// survit pas à Native AOT, mais WMI reste accessible en passant directement par ses
/// interfaces COM. Aucune réflexion à l'exécution, donc aucun avertissement de
/// trim ni surprise après publication.
///
/// La plupart des espaces de noms visés exigent l'élévation. Un refus se traduit par
/// <see cref="ReadStatus.AccessDenied"/>, que le moteur rend en « non vérifiable » :
/// le scan n'a pas pu regarder, la machine n'est pas en cause.
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
    /// L'initialisation de la sécurité COM ne vaut qu'une fois par processus, et
    /// échouer une seconde fois est normal — d'où le résultat ignoré.
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
            // 0x80041003 WBEM_E_ACCESS_DENIED, 0x80070005 E_ACCESSDENIED :
            // le scan n'est pas élevé. 0x8004100E : l'espace de noms n'existe pas,
            // ce qui arrive sur une édition de Windows dépourvue de la fonctionnalité.
            return (uint)ex.HResult switch
            {
                0x80041003 or 0x80070005 => WmiRead.AccessDenied,
                0x8004100E or 0x80041002 => WmiRead.NotFound,
                _ => WmiRead.AccessDenied,
            };
        }
        catch (Exception)
        {
            // Ne jamais laisser une défaillance WMI interrompre le scan : les autres
            // domaines doivent continuer de rendre leurs verdicts.
            return WmiRead.AccessDenied;
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

        // Sans blanket, l'appel part sans identité et WMI refuse.
        SetBlanket(services);

        var query = $"SELECT * FROM {className}";
        if (services.ExecQuery("WQL", query, WbemFlagForwardOnly | WbemFlagReturnImmediately,
                IntPtr.Zero, out var enumerator) is var exec && exec < 0)
        {
            throw new COMException(query, exec);
        }

        SetBlanket(enumerator);

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
                // Un BSTR non libere fuit a chaque lecture, donc a chaque scan.
                VariantClear(ref variant);
            }
        }

        return new WmiInstance(values);
    }

    /// <summary>
    /// Seuls les types que WMI rend pour les proprietes interrogees. Un type non
    /// couvert est ignore plutot que rendu approximativement : mieux vaut une
    /// propriete absente, donc un verdict « non verifiable », qu'une valeur fausse.
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

    private static void SetBlanket(object proxy)
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

    /// <summary>
    /// Instanciation par CoCreateInstance plutot que par Type.GetTypeFromCLSID :
    /// cette derniere passe par la reflexion et le compilateur AOT la refuse. Le
    /// garde-fou IsAotCompatible l'a signale a la compilation, la ou le probleme
    /// ne serait autrement apparu qu'apres publication.
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
