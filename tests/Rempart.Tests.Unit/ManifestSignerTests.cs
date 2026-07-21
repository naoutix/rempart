using System.Security.Cryptography;
using System.Text;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class ManifestSignerTests
{
    /// <summary>
    /// Le test qui ferme la boucle. Signer et vérifier s'accordent-ils sur le même
    /// format de signature, le même octet près ? On ne le suppose pas : on génère une
    /// vraie paire (comme <c>keygen</c>), on signe (comme <c>sign</c>), on vérifie
    /// (comme <c>update</c>). Si les deux côtés divergeaient d'un rien — format de
    /// signature, sérialisation — ce test casserait.
    /// </summary>
    [Fact]
    public void A_manifest_signed_here_verifies_there()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var content = "- id: WIN-X"u8.ToArray();
        var payload = new ManifestPayload(1, "2026-08-01T00:00:00Z",
            [ManifestSigner.Describe("regles.yaml", content)]);

        var manifest = ManifestSigner.Sign(payload, key);

        var keyId = ManifestVerifier.KeyId(key.ExportSubjectPublicKeyInfo());
        var verifier = new ManifestVerifier(new Dictionary<string, string>
        {
            [keyId] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        });

        var verdict = verifier.Verify(Rempart.Core.Json.RempartJson.Serialise(manifest));

        Assert.Equal(ManifestStatus.Trusted, verdict.Status);
        Assert.Equal(keyId, verdict.KeyId);
        Assert.Equal("2026-08-01T00:00:00Z", verdict.Payload!.PublishedAtUtc);
    }

    /// <summary>
    /// Modifier la charge utile après signature invalide celle-ci : la preuve, du côté
    /// producteur cette fois, que la signature porte bien sur les octets et non sur une
    /// vague idée du contenu.
    /// </summary>
    [Fact]
    public void Tampering_after_signing_breaks_verification()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var payload = new ManifestPayload(1, "2026-08-01T00:00:00Z",
            [ManifestSigner.Describe("d", "x"u8.ToArray())]);
        var manifest = ManifestSigner.Sign(payload, key);

        // On garde la signature, on remplace la charge utile.
        var forged = manifest with
        {
            Payload = Convert.ToBase64String(
                Encoding.UTF8.GetBytes("""{"schemaVersion":1,"publishedAtUtc":"2000-01-01T00:00:00Z","datasets":[]}""")),
        };

        var keyId = ManifestVerifier.KeyId(key.ExportSubjectPublicKeyInfo());
        var verifier = new ManifestVerifier(new Dictionary<string, string>
        {
            [keyId] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        });

        Assert.Equal(ManifestStatus.BadSignature,
            verifier.Verify(Rempart.Core.Json.RempartJson.Serialise(forged)).Status);
    }

    /// <summary>
    /// La version d'un jeu de données dérive de son contenu : même contenu, même
    /// version ; contenu différent, version différente. Rien à incrémenter à la main.
    /// </summary>
    [Fact]
    public void Dataset_version_follows_the_content()
    {
        var a = ManifestSigner.Describe("d", "contenu"u8.ToArray());
        var again = ManifestSigner.Describe("d", "contenu"u8.ToArray());
        var other = ManifestSigner.Describe("d", "autre"u8.ToArray());

        Assert.Equal(a.Version, again.Version);
        Assert.NotEqual(a.Version, other.Version);
        Assert.StartsWith(a.Version, a.Sha256);
    }

    /// <summary>
    /// La cérémonie complète, de bout en bout : générer une clé (keygen), signer une
    /// mise à jour de règles (sign), la déposer, puis la résoudre comme le fait un scan
    /// (update + store). C'est le trajet réel d'une donnée, prouvé sans jamais la vraie
    /// clé de production.
    /// </summary>
    [Fact]
    public void The_whole_ceremony_generate_sign_apply_resolve()
    {
        // 1. keygen — sur une machine hors ligne.
        var pair = PublisherKey.Generate("phrase de passe correcte");

        // 2. sign — avec la clé privée déchiffrée.
        var rule = """
            - id: WIN-NEW-001
              title: Ajouté par mise à jour
              severity: high
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: Flag
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;
        var content = Encoding.UTF8.GetBytes(rule);

        SignedManifest manifest;
        using (var key = PublisherKey.Open(pair.EncryptedPrivateKey, "phrase de passe correcte"))
        {
            manifest = ManifestSigner.Sign(
                new ManifestPayload(1, "2026-09-01T00:00:00Z",
                    [ManifestSigner.Describe("regles.yaml", content)]),
                key);
        }

        // 3. Le binaire cible n'épingle que cette clé publique.
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [pair.KeyId] = pair.PublicKey });

        // 4. update — le manifeste et son jeu de données sont vérifiés et différenciés.
        var preview = UpdatePlanner.Prepare(
            Rempart.Core.Json.RempartJson.Serialise(manifest),
            verifier,
            name => name == "regles.yaml" ? content : null,
            []);

        Assert.True(preview.ReadyToApply);
        Assert.Equal(["WIN-NEW-001"], Assert.Single(preview.Datasets).Diff!.Added);
    }
}
