using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Vérification Authenticode par <c>WinVerifyTrust</c>.
///
/// C'est l'API que Windows utilise lui-même : elle valide la chaîne de confiance, la
/// péremption et la révocation, là où lire le certificat embarqué ne dirait que sa
/// présence. Un binaire signé par un certificat expiré ou révoqué est bien signé —
/// et n'est pas digne de confiance pour autant.
///
/// Une vérification qui n'aboutit pas rend <see cref="SignatureStatus.Unknown"/>,
/// jamais <c>Unsigned</c> : confondre « je n'ai pas pu vérifier » avec « ce n'est pas
/// signé » produirait des alertes fausses sur les machines les moins auditables.
/// </summary>
public sealed partial class LiveSignatureProvider : ISignatureProvider
{
    private static readonly Guid ActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;

    // 0x800B0100 TRUST_E_NOSIGNATURE, 0x800B0003 TRUST_E_SUBJECT_FORM_UNKNOWN,
    // 0x800B0001 TRUST_E_PROVIDER_UNKNOWN : aucune signature exploitable.
    private const int TrustNoSignature = unchecked((int)0x800B0100);
    private const int TrustSubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustProviderUnknown = unchecked((int)0x800B0001);

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
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
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
    private static partial int WinVerifyTrust(IntPtr window, ref Guid action, ref WintrustData data);

    public FileSignature Verify(string path)
    {
        if (!File.Exists(path))
        {
            return new FileSignature(SignatureStatus.FileNotFound);
        }

        var hash = ComputeHash(path);

        try
        {
            var embedded = Check(path);

            if (embedded == 0)
            {
                return new FileSignature(SignatureStatus.Valid, ReadPublisher(path), hash);
            }

            // Pas de signature embarquée : la plupart des binaires Windows sont signés
            // par catalogue. S'arrêter ici classerait cmd.exe comme non signé, et avec
            // lui la quasi-totalité des démarrages automatiques d'un système sain.
            if (embedded is TrustNoSignature or TrustSubjectFormUnknown or TrustProviderUnknown)
            {
                return CatalogSignature.Verify(path) switch
                {
                    0 => new FileSignature(SignatureStatus.Valid, ReadPublisher(path), hash),

                    // Aucun catalogue ne référence ce fichier : il n'est signé
                    // d'aucune manière.
                    null => new FileSignature(SignatureStatus.Unsigned, null, hash),

                    // Un catalogue le couvre, mais ne valide pas.
                    _ => new FileSignature(SignatureStatus.Invalid, null, hash),
                };
            }

            // Signée, mais la chaîne ne tient pas : expirée, révoquée, altérée.
            return new FileSignature(SignatureStatus.Invalid, ReadPublisher(path), hash);
        }
        catch (Exception)
        {
            return new FileSignature(SignatureStatus.Unknown, null, hash);
        }
    }

    private static unsafe int Check(string path)
    {
        var pathPointer = Marshal.StringToHGlobalUni(path);

        try
        {
            var file = new WintrustFileInfo
            {
                StructSize = (uint)sizeof(WintrustFileInfo),
                FilePath = pathPointer,
            };

            var filePointer = Marshal.AllocHGlobal(sizeof(WintrustFileInfo));

            try
            {
                Marshal.StructureToPtr(file, filePointer, false);

                var data = new WintrustData
                {
                    StructSize = (uint)sizeof(WintrustData),
                    UiChoice = WtdUiNone,
                    RevocationChecks = WtdRevokeWholeChain,
                    UnionChoice = WtdChoiceFile,
                    FileInfo = filePointer,
                    StateAction = WtdStateActionVerify,
                };

                var action = ActionGenericVerifyV2;
                var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

                // Second appel obligatoire : sans lui, l'etat alloue par la
                // verification fuit a chaque fichier examine.
                data.StateAction = WtdStateActionClose;
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(filePointer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pathPointer);
        }
    }

    /// <summary>
    /// Nom de l'éditeur, lu sur le certificat embarqué. Sans valeur de preuve à lui
    /// seul — c'est <c>WinVerifyTrust</c> qui tranche — mais c'est ce qui rend un
    /// constat lisible.
    /// </summary>
    private static string? ReadPublisher(string path)
    {
        try
        {
            using var certificate = X509CertificateLoader.LoadCertificateFromFile(path);
            return certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string? ComputeHash(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception)
        {
            // Fichier verrouillé ou illisible : l'empreinte manque, la signature
            // reste vérifiable.
            return null;
        }
    }
}
