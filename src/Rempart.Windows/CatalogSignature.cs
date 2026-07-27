using System.Runtime.InteropServices;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Catalog-based signature verification.
///
/// Most Windows binaries carry no embedded signature: their signature lives in a
/// separate <c>.cat</c> file, indexed by hash. A check that only inspects the file
/// itself would report them as unsigned — classifying <c>cmd.exe</c> as suspect,
/// along with almost every autostart entry of a healthy Windows install.
///
/// This follows the same steps Windows uses: compute the file hash, find the
/// catalog that contains it, then validate that catalog.
/// </summary>
internal static unsafe partial class CatalogSignature
{
    private const int MaxPath = 260;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;

    private static readonly Guid ActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct CatalogInfo
    {
        public uint StructSize;
        public fixed char CatalogFile[MaxPath];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustCatalogInfo
    {
        public uint StructSize;
        public uint CatalogVersion;
        public IntPtr CatalogFilePath;
        public IntPtr MemberTag;
        public IntPtr MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public IntPtr CatalogContext;
        public IntPtr CatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr Info;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [LibraryImport("wintrust.dll", EntryPoint = "CryptCATAdminAcquireContext2",
        StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AcquireContext(
        out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr policy, uint flags);

    [LibraryImport("wintrust.dll", EntryPoint = "CryptCATAdminCalcHashFromFileHandle2")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CalcHash(
        IntPtr admin, IntPtr file, ref uint hashSize, byte[]? hash, uint flags);

    [LibraryImport("wintrust.dll", EntryPoint = "CryptCATAdminEnumCatalogFromHash")]
    private static partial IntPtr EnumCatalogFromHash(
        IntPtr admin, byte[] hash, uint hashSize, uint flags, IntPtr previous);

    [LibraryImport("wintrust.dll", EntryPoint = "CryptCATCatalogInfoFromContext")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CatalogInfoFromContext(
        IntPtr catalogContext, ref CatalogInfo info, uint flags);

    [LibraryImport("wintrust.dll", EntryPoint = "CryptCATAdminReleaseCatalogContext")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReleaseCatalogContext(
        IntPtr admin, IntPtr catalogContext, uint flags);

    [LibraryImport("wintrust.dll", EntryPoint = "CryptCATAdminReleaseContext")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReleaseContext(IntPtr admin, uint flags);

    [LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
    private static partial int WinVerifyTrust(IntPtr window, ref Guid action, ref WintrustData data);

    /// <summary>
    /// Checks whether the file is covered by a valid catalog.
    ///
    /// <para>
    /// <b>Every early return names which of the two it is.</b> This method used to answer
    /// <c>int?</c>, and <c>null</c> stood for « no catalog references this file » as well as
    /// for every way the store could refuse to answer — the context not acquired, the hash
    /// not computed, the file not opened. The judgement in Core turned that single null into
    /// <c>Unsigned</c> and the ladder turned <c>Unsigned</c> into a <c>Suspicious</c>
    /// finding, so a driver held open by another process was accused rather than reported
    /// as unverifiable (DET-CATALOGUE-MUET). Only this method knows which happened, so this
    /// is where the two are told apart.
    /// </para>
    /// </summary>
    internal static CatalogOutcome Verify(string path)
    {
        if (!AcquireContext(out var admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            // Without a context nothing was ever looked up. Answering « not catalogued »
            // here would report the whole machine as unsigned.
            return CatalogOutcome.Unaskable;
        }

        try
        {
            using var stream = File.OpenRead(path);
            var handle = stream.SafeFileHandle.DangerousGetHandle();

            // Two-step call: first the hash size, then its content.
            uint size = 0;
            CalcHash(admin, handle, ref size, null, 0);
            if (size == 0)
            {
                return CatalogOutcome.Unaskable;
            }

            var hash = new byte[size];
            if (!CalcHash(admin, handle, ref size, hash, 0))
            {
                // No hash, no lookup key: the catalogs were never consulted.
                return CatalogOutcome.Unaskable;
            }

            var catalog = EnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catalog == IntPtr.Zero)
            {
                // The store answered, and no catalog covers this file: this is not a
                // verification failure, the file just has no catalog signature. The one
                // outcome here that legitimately leads to an accusation.
                return CatalogOutcome.NotCatalogued;
            }

            try
            {
                return VerifyAgainstCatalog(admin, catalog, path, hash);
            }
            finally
            {
                ReleaseCatalogContext(admin, catalog, 0);
            }
        }
        catch (Exception)
        {
            // A file that could not be opened — locked, denied, gone between the two
            // calls. Nothing was verified, and nothing is claimed.
            return CatalogOutcome.Unaskable;
        }
        finally
        {
            ReleaseContext(admin, 0);
        }
    }

    private static CatalogOutcome VerifyAgainstCatalog(
        IntPtr admin, IntPtr catalog, string path, byte[] hash)
    {
        var info = new CatalogInfo { StructSize = (uint)sizeof(CatalogInfo) };
        if (!CatalogInfoFromContext(catalog, ref info, 0))
        {
            // A catalog was found and its path could not be read: the verification never
            // ran, so this is a gap and not a refusal.
            return CatalogOutcome.Unaskable;
        }

        // The buffer is a fixed array in the local struct: read it directly.
        var catalogPath = new string(info.CatalogFile);

        // The member is identified in the catalog by its hash in hexadecimal.
        var memberTag = Convert.ToHexString(hash);

        var catalogPathPointer = Marshal.StringToHGlobalUni(catalogPath);
        var memberTagPointer = Marshal.StringToHGlobalUni(memberTag);
        var filePathPointer = Marshal.StringToHGlobalUni(path);
        var hashPointer = Marshal.AllocHGlobal(hash.Length);
        var catalogInfoPointer = Marshal.AllocHGlobal(sizeof(WintrustCatalogInfo));

        try
        {
            Marshal.Copy(hash, 0, hashPointer, hash.Length);

            var trustCatalog = new WintrustCatalogInfo
            {
                StructSize = (uint)sizeof(WintrustCatalogInfo),
                CatalogFilePath = catalogPathPointer,
                MemberTag = memberTagPointer,
                MemberFilePath = filePathPointer,
                CalculatedFileHash = hashPointer,
                CalculatedFileHashSize = (uint)hash.Length,
                CatalogContext = catalog,
                CatAdmin = admin,
            };

            Marshal.StructureToPtr(trustCatalog, catalogInfoPointer, false);

            var data = new WintrustData
            {
                StructSize = (uint)sizeof(WintrustData),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeWholeChain,
                UnionChoice = WtdChoiceCatalog,
                Info = catalogInfoPointer,
                StateAction = WtdStateActionVerify,
            };

            var action = ActionGenericVerifyV2;
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            // The second call is mandatory: without it the allocated state leaks on every file.
            data.StateAction = WtdStateActionClose;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            // What the number means is decided in Core, where the Linux job compiles it:
            // only the exact zero is a signature that held.
            return AuthenticodeVerdict.FromCatalogHResult(result);
        }
        finally
        {
            Marshal.FreeHGlobal(catalogInfoPointer);
            Marshal.FreeHGlobal(hashPointer);
            Marshal.FreeHGlobal(filePathPointer);
            Marshal.FreeHGlobal(memberTagPointer);
            Marshal.FreeHGlobal(catalogPathPointer);
        }
    }
}
