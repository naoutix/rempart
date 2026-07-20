using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace Rempart.Windows.Wmi;

/// <summary>
/// Interfaces COM de WMI, déclarées pour le générateur d'interop de .NET.
///
/// <c>GeneratedComInterface</c> produit le code de transition à la compilation, sans
/// réflexion à l'exécution : c'est ce qui rend WMI accessible sous Native AOT, là où
/// <c>System.Management</c> ne l'est pas. La question était ouverte depuis M0.
///
/// Seules les méthodes réellement employées sont déclarées ; les autres sont
/// remplacées par des emplacements vides pour conserver l'ordre de la table virtuelle,
/// dont dépend l'appel. Retirer un emplacement décalerait tous les suivants et
/// appellerait la mauvaise fonction — un plantage, ou pire, un résultat faux.
/// </summary>
[GeneratedComInterface]
[Guid("dc12a687-737f-11cf-884d-00aa004b2e24")]
internal partial interface IWbemLocator
{
    [PreserveSig]
    int ConnectServer(
        [MarshalAs(UnmanagedType.BStr)] string networkResource,
        [MarshalAs(UnmanagedType.BStr)] string? user,
        [MarshalAs(UnmanagedType.BStr)] string? password,
        [MarshalAs(UnmanagedType.BStr)] string? locale,
        int securityFlags,
        [MarshalAs(UnmanagedType.BStr)] string? authority,
        IntPtr context,
        out IWbemServices services);
}

[GeneratedComInterface]
[Guid("9556dc99-828c-11cf-a37e-00aa003240c7")]
internal partial interface IWbemServices
{
    void OpenNamespace_Unused();

    void CancelAsyncCall_Unused();

    void QueryObjectSink_Unused();

    void GetObject_Unused();

    void GetObjectAsync_Unused();

    void PutClass_Unused();

    void PutClassAsync_Unused();

    void DeleteClass_Unused();

    void DeleteClassAsync_Unused();

    void CreateClassEnum_Unused();

    void CreateClassEnumAsync_Unused();

    void PutInstance_Unused();

    void PutInstanceAsync_Unused();

    void DeleteInstance_Unused();

    void DeleteInstanceAsync_Unused();

    void CreateInstanceEnum_Unused();

    void CreateInstanceEnumAsync_Unused();

    [PreserveSig]
    int ExecQuery(
        [MarshalAs(UnmanagedType.BStr)] string queryLanguage,
        [MarshalAs(UnmanagedType.BStr)] string query,
        int flags,
        IntPtr context,
        out IEnumWbemClassObject enumerator);
}

[GeneratedComInterface]
[Guid("027947e1-d731-11ce-a357-000000000001")]
internal partial interface IEnumWbemClassObject
{
    void Reset_Unused();

    [PreserveSig]
    int Next(
        int timeout,
        uint count,
        [Out][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] IntPtr[] objects,
        out uint returned);
}

[GeneratedComInterface]
[Guid("dc12a681-737f-11cf-884d-00aa004b2e24")]
internal partial interface IWbemClassObject
{
    void GetQualifierSet_Unused();

    // VARIANT passe par une structure blittable decodee a la main : l'interop
    // generee a la compilation ne sait exprimer ni VARIANT ni SAFEARRAY, et c'est
    // la seule voie qui reste compatible Native AOT.
    [PreserveSig]
    int Get(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        int flags,
        ref Variant value,
        IntPtr type,
        IntPtr flavor);
}

/// <summary>
/// Disposition d'un VARIANT en x64 : type sur deux octets, trois champs reserves,
/// puis la donnee alignee sur huit octets. Declaree plutot que parcourue a coups de
/// decalages calcules — un calcul manuel s'etait deja trompe ailleurs dans ce projet.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct Variant
{
    public ushort Vt;
    public ushort Reserved1;
    public ushort Reserved2;
    public ushort Reserved3;
    public IntPtr Data;
    public IntPtr Data2;
}

internal static class VariantType
{
    public const ushort Empty = 0;
    public const ushort Null = 1;
    public const ushort I2 = 2;
    public const ushort I4 = 3;
    public const ushort Bstr = 8;
    public const ushort Bool = 11;
    public const ushort I1 = 16;
    public const ushort Ui1 = 17;
    public const ushort Ui2 = 18;
    public const ushort Ui4 = 19;
    public const ushort Int = 22;
    public const ushort Uint = 23;
}
