using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Authenticode verification via <c>WinVerifyTrust</c>.
///
/// This is the API Windows itself uses: it validates the trust chain, expiration, and
/// revocation, whereas reading the embedded certificate would only prove its presence.
/// A binary signed with an expired or revoked certificate is signed — and still not
/// trustworthy.
///
/// A verification that cannot complete returns <see cref="SignatureStatus.Unknown"/>,
/// never <c>Unsigned</c>: conflating "could not verify" with "not signed" would
/// produce false alerts on the least auditable machines.
///
/// That promise used to stop at this file. The catalog lookup below answered <c>int?</c>
/// and its <c>null</c> meant both "no catalog covers this file" and "the store could not
/// be asked", so a locked file came back <c>Unsigned</c> — accused — through the very path
/// this paragraph claimed to protect. <see cref="CatalogOutcome"/> separates the two
/// (DET-CATALOGUE-MUET).
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

            // No embedded signature: most Windows binaries are catalog-signed. Stopping
            // here would classify cmd.exe as unsigned, along with almost every autostart
            // entry of a healthy system. The lookup opens and hashes the file, so it only
            // runs when the embedded check found nothing to judge.
            var catalog = AuthenticodeVerdict.HasNoEmbeddedSignature(embedded)
                ? CatalogSignature.Verify(path)
                : CatalogOutcome.NotAsked;

            // What the two numbers mean is decided in Core, where the Linux job can hold
            // it to account. This file keeps only what genuinely needs Windows.
            return new FileSignature(
                AuthenticodeVerdict.Judge(embedded, catalog),
                AuthenticodeVerdict.ReadsPublisher(embedded, catalog) ? ReadPublisher(path) : null,
                hash);
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

                // The second call is mandatory: without it, the state allocated by
                // the verification leaks on every file examined.
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
    /// Publisher name, read from the embedded certificate. It proves nothing on its
    /// own — <c>WinVerifyTrust</c> decides — but it makes a finding readable.
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
            // Locked or unreadable file: the hash is missing, but the signature can
            // still be verified.
            return null;
        }
    }
}
