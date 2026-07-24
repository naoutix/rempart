using System.Security.Cryptography;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class PublisherKeyTests
{
    private const string Passphrase = "une phrase de passe correcte";

    /// <summary>
    /// The full round-trip: generate, write, reload, sign, verify. This is what
    /// matters — a key that cannot be reopened would otherwise only be discovered
    /// on publish day, on an offline machine probably destroyed since.
    /// </summary>
    [Fact]
    public void A_generated_key_can_be_reopened_and_actually_signs()
    {
        var pair = PublisherKey.Generate(Passphrase);

        using var reopened = ECDsa.Create();
        reopened.ImportEncryptedPkcs8PrivateKey(
            Passphrase, Convert.FromBase64String(pair.EncryptedPrivateKey), out _);

        var payload = "manifeste"u8.ToArray();
        var signature = reopened.SignData(payload, HashAlgorithmName.SHA256);

        // Verified with the announced public key, not the one just reopened:
        // the pairing of the two is what is under test.
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pair.PublicKey), out _);

        Assert.True(verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256));
    }

    /// <summary>
    /// The announced fingerprint must be the one the verifier will compute,
    /// otherwise the signed manifest would be rejected as an unknown key.
    /// </summary>
    [Fact]
    public void The_announced_key_id_is_the_one_the_verifier_computes()
    {
        var pair = PublisherKey.Generate(Passphrase);

        Assert.Equal(
            ManifestVerifier.KeyId(Convert.FromBase64String(pair.PublicKey)),
            pair.KeyId);
    }

    [Fact]
    public void The_wrong_passphrase_does_not_open_the_key()
    {
        var pair = PublisherKey.Generate(Passphrase);

        using var key = ECDsa.Create();

        Assert.Throws<CryptographicException>(() =>
            key.ImportEncryptedPkcs8PrivateKey(
                "une autre phrase de passe", Convert.FromBase64String(pair.EncryptedPrivateKey),
                out _));
    }

    /// <summary>
    /// Removable media gets lost. A passphrase that is too short would turn that
    /// loss into a compromise, and there is deliberately no option to write the
    /// key in cleartext.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("court")]
    [InlineData("onzecarac")]
    public void A_short_passphrase_is_refused(string passphrase) =>
        Assert.Throws<ArgumentException>(() => PublisherKey.Generate(passphrase));

    /// <summary>
    /// Two generations never produce the same key: otherwise two publishers
    /// could sign for each other.
    /// </summary>
    [Fact]
    public void Two_generations_produce_different_keys()
    {
        Assert.NotEqual(
            PublisherKey.Generate(Passphrase).KeyId,
            PublisherKey.Generate(Passphrase).KeyId);
    }

    /// <summary>
    /// The written private key never contains the unencrypted form. Verify it
    /// rather than assume it: this is the file that goes onto a USB stick.
    /// </summary>
    [Fact]
    public void The_written_private_key_is_encrypted()
    {
        var pair = PublisherKey.Generate(Passphrase);
        var written = Convert.FromBase64String(pair.EncryptedPrivateKey);

        // A cleartext PKCS#8 imports without a passphrase; an encrypted one does not.
        using var key = ECDsa.Create();

        Assert.ThrowsAny<CryptographicException>(
            () => key.ImportPkcs8PrivateKey(written, out _));
    }
}
