using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace Rempart.Windows.Wmi;

/// <summary>
/// WMI's COM interfaces, declared for the .NET interop generator.
///
/// <c>GeneratedComInterface</c> produces the thunking code at compile time, with no
/// reflection at runtime: this is what makes WMI reachable under Native AOT, where
/// <c>System.Management</c> is not. The question had been open since M0.
///
/// Only the methods actually used are declared; the others are replaced by empty
/// slots to preserve the vtable order the calls depend on. Removing a slot would
/// shift every following one and call the wrong function — a crash, or worse, a
/// wrong result.
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

    // VARIANT goes through a blittable struct decoded by hand: compile-time
    // generated interop can express neither VARIANT nor SAFEARRAY, and this is
    // the only path that stays Native AOT-compatible.
    [PreserveSig]
    int Get(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        int flags,
        ref Variant value,
        IntPtr type,
        IntPtr flavor);
}

/// <summary>
/// Layout of a VARIANT on x64: a two-byte type, three reserved fields, then the
/// data aligned on eight bytes. Declared rather than walked with computed offsets —
/// a manual calculation had already gone wrong elsewhere in this project.
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
