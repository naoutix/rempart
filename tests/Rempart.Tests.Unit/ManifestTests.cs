using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Un éditeur de manifestes, pour les tests uniquement. La vraie clé privée ne touche
/// jamais une machine de développement (ADR-002, D16) — ce qui est aussi la raison
/// pour laquelle ces tests fabriquent la leur à chaque exécution.
/// </summary>
internal sealed class TestPublisher : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public string PublicKey => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    public string KeyId => ManifestVerifier.KeyId(key.ExportSubjectPublicKeyInfo());

    public string Sign(byte[] payload) =>
        Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256));

    public void Dispose() => key.Dispose();
}

public class ManifestTests
{
    private static byte[] Payload(string version = "1.0.0", string published = "2026-07-20T00:00:00Z")
    {
        var payload = new ManifestPayload(1, published,
            [new ManifestEntry("regles-securite", version, Hash("contenu"), 7)]);

        return JsonSerializer.SerializeToUtf8Bytes(
            payload, RempartJsonContext.Default.ManifestPayload);
    }

    private static string Hash(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    private static string Wrap(byte[] payload, params ManifestSignature[] signatures) =>
        RempartJson.Serialise(
            new SignedManifest(Convert.ToBase64String(payload), [.. signatures]));

    [Fact]
    public void A_manifest_signed_by_a_pinned_key_is_trusted()
    {
        using var publisher = new TestPublisher();
        var payload = Payload();

        var verdict = new ManifestVerifier(
                new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey })
            .Verify(Wrap(payload, new ManifestSignature(publisher.KeyId, publisher.Sign(payload))));

        Assert.Equal(ManifestStatus.Trusted, verdict.Status);
        Assert.Equal(publisher.KeyId, verdict.KeyId);
        Assert.Equal("regles-securite", verdict.Payload!.Datasets[0].Name);
    }

    /// <summary>
    /// Le cas qui justifie tout ce code. Un attaquant qui contrôle le dépôt peut
    /// remplacer le contenu ; il ne peut pas produire la signature qui va avec.
    ///
    /// Sans cette vérification, il pourrait publier un catalogue vide : chaque scan
    /// rendrait 100 % sur une machine ouverte, et personne n'irait chercher — c'est
    /// précisément ce qu'un rapport vert est censé dispenser de faire.
    /// </summary>
    [Fact]
    public void Tampering_with_the_payload_after_signature_is_refused()
    {
        using var publisher = new TestPublisher();
        var signature = publisher.Sign(Payload(version: "1.0.0"));

        // La signature de l'original, collée sur une charge utile différente.
        var verdict = new ManifestVerifier(
                new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey })
            .Verify(Wrap(Payload(version: "6.6.6"),
                new ManifestSignature(publisher.KeyId, signature)));

        Assert.Equal(ManifestStatus.BadSignature, verdict.Status);
        Assert.Null(verdict.Payload);
    }

    /// <summary>
    /// Signer avec sa propre clé ne suffit pas : encore faut-il que ce binaire la
    /// connaisse. C'est ce qui distingue « signé » de « signé par l'éditeur ».
    /// </summary>
    [Fact]
    public void A_manifest_signed_by_a_stranger_is_refused()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();
        var payload = Payload();

        var verdict = new ManifestVerifier(
                new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey })
            .Verify(Wrap(payload, new ManifestSignature(stranger.KeyId, stranger.Sign(payload))));

        Assert.Equal(ManifestStatus.UnknownKey, verdict.Status);
    }

    /// <summary>
    /// L'inconnu ne peut pas non plus se faire passer pour l'éditeur en revendiquant
    /// son empreinte de clé : c'est la clé publique épinglée qui vérifie, jamais
    /// l'identifiant annoncé.
    /// </summary>
    [Fact]
    public void Claiming_a_trusted_key_id_without_the_key_is_refused()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();
        var payload = Payload();

        var verdict = new ManifestVerifier(
                new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey })
            .Verify(Wrap(payload, new ManifestSignature(publisher.KeyId, stranger.Sign(payload))));

        Assert.Equal(ManifestStatus.BadSignature, verdict.Status);
    }

    /// <summary>
    /// La rotation exige que les deux clés soient acceptées en même temps (D16). Sans
    /// ce chevauchement, publier avec une nouvelle clé casserait toutes les
    /// installations existantes d'un coup.
    /// </summary>
    [Fact]
    public void During_rotation_both_keys_are_accepted()
    {
        using var oldKey = new TestPublisher();
        using var newKey = new TestPublisher();
        var payload = Payload();

        var manifest = Wrap(payload,
            new ManifestSignature(oldKey.KeyId, oldKey.Sign(payload)),
            new ManifestSignature(newKey.KeyId, newKey.Sign(payload)));

        // Un binaire ancien ne connaît que l'ancienne clé.
        var old = new ManifestVerifier(
            new Dictionary<string, string> { [oldKey.KeyId] = oldKey.PublicKey }).Verify(manifest);

        // Un binaire récent connaît les deux.
        var recent = new ManifestVerifier(new Dictionary<string, string>
        {
            [oldKey.KeyId] = oldKey.PublicKey,
            [newKey.KeyId] = newKey.PublicKey,
        }).Verify(manifest);

        Assert.Equal(ManifestStatus.Trusted, old.Status);
        Assert.Equal(ManifestStatus.Trusted, recent.Status);
    }

    /// <summary>
    /// Une signature illisible parmi plusieurs ne doit pas emporter les autres :
    /// pendant une rotation, un manifeste en porte deux, et l'une peut venir d'une
    /// version d'outil qu'on ne connaît pas.
    /// </summary>
    [Fact]
    public void A_malformed_signature_does_not_hide_a_valid_one()
    {
        using var publisher = new TestPublisher();
        var payload = Payload();

        var verdict = new ManifestVerifier(new Dictionary<string, string>
        {
            ["ffffffffffff"] = "pas une clé",
            [publisher.KeyId] = publisher.PublicKey,
        }).Verify(Wrap(payload,
            new ManifestSignature("ffffffffffff", "pas une signature"),
            new ManifestSignature(publisher.KeyId, publisher.Sign(payload))));

        Assert.Equal(ManifestStatus.Trusted, verdict.Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("pas du json")]
    [InlineData("""{"payload":"pas du base64!!","signatures":[{"keyId":"a","value":"b"}]}""")]
    public void Anything_unreadable_is_malformed_never_trusted(string content)
    {
        var verdict = new ManifestVerifier(new Dictionary<string, string>()).Verify(content);

        Assert.NotEqual(ManifestStatus.Trusted, verdict.Status);
        Assert.False(verdict.IsTrusted);
    }

    /// <summary>
    /// Un manifeste authentique accompagné d'un fichier corrompu doit se voir comme
    /// tel : ce sont deux questions distinctes, et les confondre ferait annoncer une
    /// falsification là où il n'y a qu'un téléchargement interrompu.
    /// </summary>
    [Fact]
    public void A_file_that_does_not_match_its_entry_is_refused()
    {
        var entry = new ManifestEntry("regles", "1.0.0", Hash("contenu"), 7);

        Assert.True(ManifestVerifier.FileMatches(entry, "contenu"u8.ToArray()));
        Assert.False(ManifestVerifier.FileMatches(entry, "contenv"u8.ToArray()));
    }

    /// <summary>
    /// Même empreinte annoncée mais taille différente : refusé sans même hacher. Une
    /// incohérence interne au manifeste est déjà une raison de ne rien charger.
    /// </summary>
    [Fact]
    public void A_file_of_the_wrong_size_is_refused_before_hashing()
    {
        var entry = new ManifestEntry("regles", "1.0.0", Hash("contenu"), SizeBytes: 999);

        Assert.False(ManifestVerifier.FileMatches(entry, "contenu"u8.ToArray()));
    }
}
