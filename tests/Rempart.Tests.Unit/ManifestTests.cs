using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// A manifest publisher, for tests only. The real private key never touches a
/// development machine (ADR-002, D16) — which is also why these tests generate
/// their own key on every run.
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
    /// The case that justifies all this code. An attacker who controls the
    /// repository can replace the content; they cannot produce the matching
    /// signature.
    ///
    /// Without this check they could publish an empty catalog: every scan would
    /// report 100% on an exposed machine, and nobody would investigate a green
    /// report.
    /// </summary>
    [Fact]
    public void Tampering_with_the_payload_after_signature_is_refused()
    {
        using var publisher = new TestPublisher();
        var signature = publisher.Sign(Payload(version: "1.0.0"));

        // The original's signature, pasted onto a different payload.
        var verdict = new ManifestVerifier(
                new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey })
            .Verify(Wrap(Payload(version: "6.6.6"),
                new ManifestSignature(publisher.KeyId, signature)));

        Assert.Equal(ManifestStatus.BadSignature, verdict.Status);
        Assert.Null(verdict.Payload);
    }

    /// <summary>
    /// Signing with one's own key is not enough: this binary must also know it.
    /// That is the difference between "signed" and "signed by the publisher".
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
    /// A stranger cannot impersonate the publisher by claiming their key
    /// fingerprint either: verification uses the pinned public key, never the
    /// declared identifier.
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
    /// Rotation requires both keys to be accepted at the same time (D16). Without
    /// this overlap, publishing with a new key would break every existing
    /// installation at once.
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

        // An old binary only knows the old key.
        var old = new ManifestVerifier(
            new Dictionary<string, string> { [oldKey.KeyId] = oldKey.PublicKey }).Verify(manifest);

        // A recent binary knows both.
        var recent = new ManifestVerifier(new Dictionary<string, string>
        {
            [oldKey.KeyId] = oldKey.PublicKey,
            [newKey.KeyId] = newKey.PublicKey,
        }).Verify(manifest);

        Assert.Equal(ManifestStatus.Trusted, old.Status);
        Assert.Equal(ManifestStatus.Trusted, recent.Status);
    }

    /// <summary>
    /// One unreadable signature among several must not invalidate the others:
    /// during a rotation a manifest carries two, and one may come from a tool
    /// version we do not know.
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
    /// An authentic manifest with a corrupted file must be reported as exactly
    /// that: they are two distinct questions, and conflating them would report
    /// tampering where there is only an interrupted download.
    /// </summary>
    [Fact]
    public void A_file_that_does_not_match_its_entry_is_refused()
    {
        var entry = new ManifestEntry("regles", "1.0.0", Hash("contenu"), 7);

        Assert.True(ManifestVerifier.FileMatches(entry, "contenu"u8.ToArray()));
        Assert.False(ManifestVerifier.FileMatches(entry, "contenv"u8.ToArray()));
    }

    /// <summary>
    /// Same declared hash but a different size: refused without even hashing. An
    /// internal inconsistency in the manifest is already a reason to load nothing.
    /// </summary>
    [Fact]
    public void A_file_of_the_wrong_size_is_refused_before_hashing()
    {
        var entry = new ManifestEntry("regles", "1.0.0", Hash("contenu"), SizeBytes: 999);

        Assert.False(ManifestVerifier.FileMatches(entry, "contenu"u8.ToArray()));
    }
}
