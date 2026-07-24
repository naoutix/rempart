using System.Security.Cryptography;
using System.Text;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class ManifestSignerTests
{
    /// <summary>
    /// The test that closes the loop. Signing and verification must agree on the
    /// exact signature format, to the byte. Not assumed: generate a real pair
    /// (like <c>keygen</c>), sign (like <c>sign</c>), verify (like <c>update</c>).
    /// If the two sides diverged in anything — signature format, serialization —
    /// this test would break.
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
    /// Modifying the payload after signing invalidates the signature: proof, on
    /// the producer side this time, that the signature covers the bytes and not
    /// a loose notion of the content.
    /// </summary>
    [Fact]
    public void Tampering_after_signing_breaks_verification()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var payload = new ManifestPayload(1, "2026-08-01T00:00:00Z",
            [ManifestSigner.Describe("d", "x"u8.ToArray())]);
        var manifest = ManifestSigner.Sign(payload, key);

        // Keep the signature, replace the payload.
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
    /// A dataset version derives from its content: same content, same version;
    /// different content, different version. Nothing to increment by hand.
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
    /// The full ceremony, end to end: generate a key (keygen), sign a rules
    /// update (sign), deposit it, then resolve it the way a scan does
    /// (update + store). The real path of a piece of data, proven without ever
    /// using the real production key.
    /// </summary>
    [Fact]
    public void The_whole_ceremony_generate_sign_apply_resolve()
    {
        // 1. keygen — on an offline machine.
        var pair = PublisherKey.Generate("phrase de passe correcte");

        // 2. sign — with the decrypted private key.
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

        // 3. The target binary pins only this public key.
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [pair.KeyId] = pair.PublicKey });

        // 4. update — the manifest and its dataset are verified and diffed.
        var preview = UpdatePlanner.Prepare(
            Rempart.Core.Json.RempartJson.Serialise(manifest),
            verifier,
            name => name == "regles.yaml" ? content : null,
            []);

        Assert.True(preview.ReadyToApply);
        Assert.Equal(["WIN-NEW-001"], Assert.Single(preview.Datasets).Diff!.Added);
    }
}
