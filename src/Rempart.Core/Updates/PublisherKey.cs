using System.Security.Cryptography;

namespace Rempart.Core.Updates;

/// <summary>
/// The publisher key pair: what key generation outputs, and nothing more.
///
/// <see cref="EncryptedPrivateKey"/> is already encrypted with the passphrase by the
/// time this object exists. There is deliberately no way to obtain the private key in
/// cleartext: the only intended use is writing it to offline storage.
/// </summary>
public sealed record PublisherKeyPair(
    string EncryptedPrivateKey,
    string PublicKey,
    string KeyId);

/// <summary>
/// Generates the key pair that will sign manifests.
///
/// <para>
/// Lives in the binary because the binary is self-contained and fits on a USB stick:
/// generation must be possible on an offline machine, possibly a disposable VM, without
/// installing anything on it. The initial ADR-002 procedure used six lines of PowerShell
/// calling into .NET — they do not work on Windows PowerShell 5.1, which runs on .NET
/// Framework and does not have <c>ExportPkcs8PrivateKey</c>. On an offline machine, a
/// failing script is a script that cannot be debugged.
/// </para>
/// </summary>
public static class PublisherKey
{
    /// <summary>
    /// Passphrase derivation iteration count. The cost is paid once at generation and
    /// once per signing — never during a scan. A high value is therefore free here, and
    /// it is what separates a lost USB stick from a compromised key.
    /// </summary>
    private const int Iterations = 600_000;

    /// <summary>
    /// Encryption is not optional, and there is no passphrase-less variant. A cleartext
    /// private key on removable media makes the media worth as much as the key — and
    /// such media gets lost, lent out, and left plugged in.
    /// </summary>
    public static PublisherKeyPair Generate(ReadOnlySpan<char> passphrase)
    {
        if (passphrase.Length < 12)
        {
            throw new ArgumentException(
                "Phrase de passe trop courte : 12 caractères au minimum. C'est elle " +
                "qui protège la clé si le support est perdu.");
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var parameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Iterations);

        var spki = key.ExportSubjectPublicKeyInfo();

        return new PublisherKeyPair(
            Convert.ToBase64String(key.ExportEncryptedPkcs8PrivateKey(passphrase, parameters)),
            Convert.ToBase64String(spki),
            ManifestVerifier.KeyId(spki));
    }

    /// <summary>
    /// Reads back an encrypted private key. Used immediately after generation to verify
    /// that the written file is usable — an unreadable key should be discovered now, not
    /// on the day a release must be published.
    /// </summary>
    public static string ReadPublicKeyOf(string encryptedPrivateKey, ReadOnlySpan<char> passphrase)
    {
        using var key = Open(encryptedPrivateKey, passphrase);
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>
    /// Opens an encrypted private key for signing. The caller must dispose it — the key
    /// must not stay in memory longer than the signature it produces.
    /// </summary>
    public static ECDsa Open(string encryptedPrivateKey, ReadOnlySpan<char> passphrase)
    {
        var key = ECDsa.Create();
        key.ImportEncryptedPkcs8PrivateKey(
            passphrase, Convert.FromBase64String(encryptedPrivateKey), out _);
        return key;
    }
}
