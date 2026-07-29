using System.Security.Cryptography;
using System.Text.Json;
using Rempart.Core.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Verifies a manifest against the public keys pinned in this binary.
///
/// <para>
/// This is the single point where the project decides to trust data it did not compile.
/// As ADR-002 puts it: the rules define what "secure" means, so anyone who silently
/// replaces them does not break the tool, they make it <b>lie</b>. A scan would report
/// 100% on a wide-open machine, and nobody would investigate.
/// </para>
///
/// <para>
/// ECDSA P-256 rather than Ed25519, which would have been the natural choice: .NET 10
/// does not expose Ed25519 as a public type. The post-quantum ML-DSA and SLH-DSA exist
/// but are marked experimental (<c>SYSLIB5006</c>: "subject to change or removal").
/// Building a trust channel on an API Microsoft reserves the right to remove would be a
/// bad trade for a tool whose whole point is not breaking. P-256 is stable, available
/// everywhere, and its signatures are a fixed 64 bytes.
/// </para>
///
/// <para>
/// <b>Every rejection returns a verdict; none of them throws.</b> A manifest is a file
/// anyone can write — the update store and the stick seal live in the two folders the
/// seal deliberately leaves out — and this class used to check the top level only. Fifty
/// bytes of well-formed JSON with a field missing therefore reached a null dereference
/// outside the <c>try</c>, and "update refused, embedded baseline kept" became no scan at
/// all, on that machine and on every machine the stick met afterwards.
/// </para>
/// </summary>
public sealed class ManifestVerifier
{
    /// <summary>
    /// Accepted public keys, as base64-encoded SubjectPublicKeyInfo, indexed by their
    /// fingerprint.
    ///
    /// Two at most — a constraint from ADR-002 (D16), not a technical limit: rotation
    /// requires an overlap — publish with the new key, keep the old one valid until the
    /// binaries in circulation are replaced, then remove it. Without that overlap, any
    /// rotation would break existing installations.
    /// </summary>
    private readonly IReadOnlyDictionary<string, string> keys;

    public ManifestVerifier(IReadOnlyDictionary<string, string> trustedKeys)
    {
        keys = trustedKeys;
    }

    /// <summary>
    /// Fingerprint of a public key: the first twelve characters of the SHA-256 of its
    /// SPKI encoding. Same shape as the rule catalog fingerprint, so both read the same
    /// way in a report.
    /// </summary>
    public static string KeyId(byte[] subjectPublicKeyInfo) =>
        Convert.ToHexStringLower(SHA256.HashData(subjectPublicKeyInfo))[..12];

    public ManifestVerdict Verify(string manifestJson)
    {
        SignedManifest? signed;
        byte[] payloadBytes;

        try
        {
            signed = JsonSerializer.Deserialize(
                manifestJson, RempartJsonContext.Default.SignedManifest);

            // The fields are declared non-nullable, but a record enforces nothing during
            // deserialization: `{}` produces an object whose fields are all null. Check
            // explicitly — otherwise an empty file crashes the process instead of being
            // rejected, and this file arrives over the network.
            if (signed?.Payload is null || signed.Signatures is null
                || signed.Signatures.Count == 0)
            {
                return Fail(ManifestStatus.Malformed,
                    "Manifeste sans charge utile ni signature : rien à vérifier.");
            }

            payloadBytes = Convert.FromBase64String(signed.Payload);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return Fail(ManifestStatus.Malformed,
                $"Manifeste illisible : {ex.Message}");
        }

        // The same holds one level down, and that level was left out: `[null]` and
        // `[{"value":"x"}]` deserialize into signatures whose non-nullable fields are
        // null all the same, and `ContainsKey(null)` threw here — outside the try, so a
        // fifty-byte file dropped into the store aborted every later scan.
        //
        // Dropped rather than refused wholesale, deliberately: the signature list travels
        // outside the signed bytes, so refusing the file over one junk entry would let
        // anyone able to append to it turn a valid update into a refused one.
        var usable = signed.Signatures
            .Where(s => s is not null && s.KeyId is not null && s.Value is not null)
            .ToList();

        if (usable.Count == 0)
        {
            return Fail(ManifestStatus.Malformed,
                "Aucune signature exploitable : identifiant de clé ou valeur manquants.");
        }

        // Is there any signature from a known key at all? Distinguishing this case
        // avoids reporting tampering when the binary is merely too old to know the
        // current key.
        var known = usable.Where(s => keys.ContainsKey(s.KeyId)).ToList();

        if (known.Count == 0)
        {
            var offered = string.Join(", ", usable.Select(s => s.KeyId));
            return Fail(ManifestStatus.UnknownKey,
                $"Aucune clé connue n'a signé ce manifeste. Signé par : {offered}. " +
                "Ce binaire est peut-être antérieur à une rotation de clé ; " +
                "en installer une version récente plutôt que forcer la mise à jour.");
        }

        foreach (var signature in known)
        {
            if (!Matches(keys[signature.KeyId], payloadBytes, signature.Value))
            {
                continue;
            }

            // Valid signature: only now is the content parsed.
            try
            {
                var payload = JsonSerializer.Deserialize(
                    payloadBytes, RempartJsonContext.Default.ManifestPayload);

                if (payload?.Datasets is null || payload.PublishedAtUtc is null)
                {
                    return Fail(ManifestStatus.Malformed,
                        "Charge utile signée mais vide, sans date ou sans jeu de données.");
                }

                if (payload.Datasets.Any(Incomplete))
                {
                    return Fail(ManifestStatus.Malformed,
                        "Charge utile signée dont un jeu de données est incomplet : nom, " +
                        "version, empreinte ou type manquants. Rien n'est chargé.");
                }

                return new ManifestVerdict(ManifestStatus.Trusted, payload, signature.KeyId,
                    $"Signé par {signature.KeyId}, publié le {payload.PublishedAtUtc}.");
            }
            catch (JsonException ex)
            {
                // Valid signature, unreadable content: the publisher shipped something
                // this binary cannot parse. That is not an attack, and saying so avoids
                // a false alarm.
                return Fail(ManifestStatus.Malformed,
                    $"Charge utile correctement signée mais illisible par cette version : " +
                    $"{ex.Message}");
            }
        }

        return Fail(ManifestStatus.BadSignature,
            "Une clé connue est revendiquée, mais la signature ne correspond pas à la " +
            "charge utile. Le contenu a été modifié après signature. Ne rien charger.");
    }

    /// <summary>
    /// A dataset entry with a hole in it — <c>"datasets":[{}]</c>, or an entry left null.
    ///
    /// Refused here because this is the one place all three readers of a manifest go
    /// through, and none of them asks again: the store resolves <c>Name</c> into a path,
    /// the seal looks it up in a dictionary, <see cref="FileMatches"/> lowercases
    /// <c>Sha256</c>. A trusted verdict promises a payload that can be read, so the
    /// promise is checked before it is made rather than at each of the three.
    /// </summary>
    private static bool Incomplete(ManifestEntry entry) =>
        entry is null || entry.Name is null || entry.Version is null
        || entry.Sha256 is null || entry.Kind is null;

    private static bool Matches(string publicKeyBase64, byte[] payload, string signatureBase64)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(
                Convert.FromBase64String(publicKeyBase64), out _);

            return ecdsa.VerifyData(
                payload, Convert.FromBase64String(signatureBase64), HashAlgorithmName.SHA256);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            // A malformed key or signature is not a valid signature. It must not abort
            // checking the remaining signatures either: during a rotation the manifest
            // carries several.
            return false;
        }
    }

    /// <summary>
    /// Checks that a received file is the one the manifest describes.
    ///
    /// Separate from signature verification because these are two distinct questions:
    /// is the manifest truthful, and did we receive what it declares. An authentic
    /// manifest paired with a corrupted file must be reported as exactly that, not as
    /// an invalid signature.
    /// </summary>
    public static bool FileMatches(ManifestEntry entry, byte[] content)
    {
        if (content.LongLength != entry.SizeBytes)
        {
            return false;
        }

        var actual = Convert.ToHexStringLower(SHA256.HashData(content));

        // Constant-time comparison: as a principle, code that makes a trust decision
        // must not leak how the received value differs from the expected one.
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(actual),
            System.Text.Encoding.ASCII.GetBytes(entry.Sha256.ToLowerInvariant()));
    }

    private static ManifestVerdict Fail(ManifestStatus status, string explanation) =>
        new(status, null, null, explanation);
}
