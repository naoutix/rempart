using System.Runtime.InteropServices;

namespace Rempart.Windows;

/// <summary>
/// Vérification par catalogue.
///
/// La plupart des binaires Windows ne portent aucune signature embarquée : leur
/// signature vit dans un fichier <c>.cat</c> séparé, indexé par empreinte. Une
/// vérification qui n'examine que le fichier les déclare non signés — ce qui
/// classerait <c>cmd.exe</c> comme suspect, et avec lui la quasi-totalité des
/// démarrages automatiques d'un Windows sain.
///
/// La démarche est celle de Windows lui-même : calculer l'empreinte du fichier,
/// chercher le catalogue qui la contient, puis valider ce catalogue.
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
    /// Vérifie que le fichier est couvert par un catalogue valide.
    /// </summary>
    /// <returns>
    /// <c>0</c> si un catalogue valide couvre le fichier, un HRESULT sinon, et
    /// <c>null</c> si aucun catalogue ne le référence — auquel cas le fichier n'est
    /// simplement pas signé de cette manière.
    /// </returns>
    internal static int? Verify(string path)
    {
        if (!AcquireContext(out var admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            return null;
        }

        try
        {
            using var stream = File.OpenRead(path);
            var handle = stream.SafeFileHandle.DangerousGetHandle();

            // Appel en deux temps : la taille de l'empreinte d'abord, son contenu ensuite.
            uint size = 0;
            CalcHash(admin, handle, ref size, null, 0);
            if (size == 0)
            {
                return null;
            }

            var hash = new byte[size];
            if (!CalcHash(admin, handle, ref size, hash, 0))
            {
                return null;
            }

            var catalog = EnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catalog == IntPtr.Zero)
            {
                // Aucun catalogue ne couvre ce fichier : ce n'est pas un échec de
                // vérification, c'est une absence de signature par catalogue.
                return null;
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
            return null;
        }
        finally
        {
            ReleaseContext(admin, 0);
        }
    }

    private static int? VerifyAgainstCatalog(
        IntPtr admin, IntPtr catalog, string path, byte[] hash)
    {
        var info = new CatalogInfo { StructSize = (uint)sizeof(CatalogInfo) };
        if (!CatalogInfoFromContext(catalog, ref info, 0))
        {
            return null;
        }

        // Le tampon est deja fixe dans la structure locale : on lit directement.
        var catalogPath = new string(info.CatalogFile);

        // Le membre est designe dans le catalogue par son empreinte en hexadecimal.
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

            // Second appel obligatoire : sans lui l'état alloué fuit à chaque fichier.
            data.StateAction = WtdStateActionClose;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return result;
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
