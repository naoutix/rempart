using System.Security.Cryptography;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class PublisherKeyTests
{
    private const string Passphrase = "une phrase de passe correcte";

    /// <summary>
    /// Le tour complet : générer, écrire, relire, signer, vérifier. C'est ce qui compte
    /// vraiment — une clé qu'on ne peut pas rouvrir ne se découvre autrement que le
    /// jour où l'on doit publier, sur une machine hors ligne probablement détruite
    /// depuis.
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

        // Vérifié par la clé publique annoncée, pas par celle qu'on vient de rouvrir :
        // c'est l'appariement des deux qui est en cause.
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pair.PublicKey), out _);

        Assert.True(verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256));
    }

    /// <summary>
    /// L'empreinte annoncée est bien celle que le vérificateur calculera, sans quoi le
    /// manifeste signé serait rejeté pour clé inconnue.
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
    /// Un support amovible se perd. Une phrase de passe trop courte ferait de cette
    /// perte une compromission, et il n'existe volontairement aucune option pour
    /// écrire la clé en clair.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("court")]
    [InlineData("onzecarac")]
    public void A_short_passphrase_is_refused(string passphrase) =>
        Assert.Throws<ArgumentException>(() => PublisherKey.Generate(passphrase));

    /// <summary>
    /// Deux générations ne donnent jamais la même clé : sans cela, deux éditeurs
    /// pourraient signer l'un pour l'autre.
    /// </summary>
    [Fact]
    public void Two_generations_produce_different_keys()
    {
        Assert.NotEqual(
            PublisherKey.Generate(Passphrase).KeyId,
            PublisherKey.Generate(Passphrase).KeyId);
    }

    /// <summary>
    /// La clé privée écrite ne contient jamais la forme non chiffrée. Le vérifier
    /// plutôt que de le supposer : c'est le fichier qui part sur une clé USB.
    /// </summary>
    [Fact]
    public void The_written_private_key_is_encrypted()
    {
        var pair = PublisherKey.Generate(Passphrase);
        var written = Convert.FromBase64String(pair.EncryptedPrivateKey);

        // Un PKCS#8 en clair s'importe sans phrase de passe ; un chiffré non.
        using var key = ECDsa.Create();

        Assert.ThrowsAny<CryptographicException>(
            () => key.ImportPkcs8PrivateKey(written, out _));
    }
}
