using System.Security.Cryptography;
using System.Text.Json;
using Rempart.Core.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Produces a signed manifest — the counterpart of <see cref="ManifestVerifier"/>.
///
/// <para>
/// This is the publication step of ADR-002, and it stays manual (D16): no automation
/// holds the key; signing happens on an offline machine. This code applies the same
/// principle as the verifier — <b>sign the bytes, then describe them; never the
/// reverse</b>. The payload is serialized once, those exact bytes are signed, and those
/// bytes are what travels as base64. The verifier operates on exactly the same byte
/// sequence, without re-serializing.
/// </para>
/// </summary>
public static class ManifestSigner
{
    /// <summary>
    /// Describes a file the way the manifest must declare it: hash and size, which is
    /// what the verifier uses to decide that a received file is this one.
    /// </summary>
    public static ManifestEntry Describe(string name, byte[] content, string? kind = null)
    {
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(content));

        return new ManifestEntry(
            name,
            // Version derived from the content: two publications of the same file carry
            // the same version, two different contents do not. Nothing to enter by hand,
            // nothing to forget to increment.
            sha256[..8],
            sha256,
            content.LongLength,
            kind ?? DatasetKind.Infer(name));
    }

    /// <summary>
    /// Signs a payload with the publisher private key.
    ///
    /// The ECDSA signature is produced in IEEE P1363 format (r‖s, a fixed 64 bytes for
    /// P-256) — the default format of <c>SignData</c>, and the one <c>VerifyData</c>
    /// expects on the verifier side. The two sides agree implicitly; a test proves it
    /// rather than assuming it.
    /// </summary>
    public static SignedManifest Sign(ManifestPayload payload, ECDsa privateKey)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            payload, RempartJsonContext.Default.ManifestPayload);

        var signature = privateKey.SignData(bytes, HashAlgorithmName.SHA256);
        var keyId = ManifestVerifier.KeyId(privateKey.ExportSubjectPublicKeyInfo());

        return new SignedManifest(
            Convert.ToBase64String(bytes),
            [new ManifestSignature(keyId, Convert.ToBase64String(signature))]);
    }
}
