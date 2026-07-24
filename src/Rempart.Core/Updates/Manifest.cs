namespace Rempart.Core.Updates;

/// <summary>The dataset kinds the channel knows how to route.</summary>
public static class DatasetKind
{
    /// <summary>YAML rules, merged into the catalog (D12).</summary>
    public const string Rules = "rules";

    /// <summary>List of known vulnerable drivers (LOLDrivers), as JSON.</summary>
    public const string Drivers = "drivers";

    /// <summary>Bloatware catalog (M5b), as JSON. Kind forced at signing time (--kind bloatware):
    /// extension-based inference cannot tell this JSON apart from the driver list.</summary>
    public const string Bloatware = "bloatware";

    /// <summary>
    /// A file of the stick itself, listed by its integrity seal (M6).
    ///
    /// Never a dataset: nothing of this kind is ever loaded into the catalog. It exists
    /// so the seal can reuse the signed envelope of ADR-002 — one signature format, one
    /// verifier, one pinned key for the whole project — and <see cref="UpdateStore"/>
    /// refuses it explicitly, so a seal dropped into the store by mistake is rejected
    /// with a message that says what happened rather than one about a version to install.
    /// </summary>
    public const string Binary = "binary";

    /// <summary>
    /// Guesses a file's kind from its extension: <c>.yaml</c>/<c>.yml</c> are rules,
    /// everything else (JSON) a driver list. A publisher can always force it
    /// explicitly at signing time; this is only a convenient default.
    /// </summary>
    public static string Infer(string name) =>
        name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            ? Rules
            : Drivers;
}

/// <summary>
/// A published dataset, described by its fingerprint.
///
/// The fingerprint is what is authoritative: name and version are reading comfort,
/// but <see cref="Sha256"/> is what decides whether the received file is the one the
/// publisher signed.
///
/// <para>
/// <see cref="Kind"/> says how to read the file — rules or drivers. Its default value
/// is <c>rules</c>: a manifest predating the kind field therefore reads as rules,
/// which is what it was. Conversely, a manifest carrying a kind an old version does
/// not know must be refused, not guessed.
/// </para>
/// </summary>
public sealed record ManifestEntry(
    string Name,
    string Version,
    string Sha256,
    long SizeBytes,
    string Kind = DatasetKind.Rules);

/// <summary>
/// The signed payload: what the publisher asserts, and nothing else.
///
/// Deliberately sparse. Everything added here becomes an assertion a key holder can
/// make about a machine that trusts them.
/// </summary>
public sealed record ManifestPayload(
    int SchemaVersion,
    string PublishedAtUtc,
    List<ManifestEntry> Datasets);

/// <summary>
/// The file as it travels: the payload in the clear, and its signature.
///
/// <para>
/// <see cref="Payload"/> is the payload encoded in base64, not a nested JSON object.
/// That is not a convenience but the heart of the scheme: <b>the signature covers
/// exactly those bytes</b>. A nested object would force re-serialization before
/// verifying, and the slightest difference — a space, field order, how an accent is
/// escaped — would invalidate a perfectly valid signature. Verify the bytes, then
/// parse them. Never the other way around.
/// </para>
///
/// <para>
/// <see cref="Signatures"/> is a list because key rotation requires it
/// (ADR-002, D16): during the overlap, a manifest carries both the old key's
/// signature and the new one's, and the binaries in circulation accept the one
/// they know.
/// </para>
/// </summary>
public sealed record SignedManifest(
    string Payload,
    List<ManifestSignature> Signatures);

/// <summary>
/// A signature, tied to the key that produced it by that key's fingerprint.
///
/// Without <see cref="KeyId"/>, verifying would mean trying every known key against
/// every signature — feasible, but there would be no telling <i>which</i> one failed,
/// and a diagnostic that cannot distinguish "signed by a key I do not know" from
/// "invalid signature" is worth nothing on the day it matters.
/// </summary>
public sealed record ManifestSignature(string KeyId, string Value);

/// <summary>
/// What was concluded about a manifest. Each case is distinct, and none folds into
/// another.
///
/// The temptation of a boolean is strong, and it is exactly the mistake that left WMI
/// broken for two batches: a single <c>catch</c> translated every failure into
/// "access denied", making a bug indistinguishable from missing privileges. Here, a
/// forged signature and an unknown key call for opposite reactions — one is an
/// attack, the other is probably a binary that is too old.
/// </summary>
public enum ManifestStatus
{
    /// <summary>Valid signature, produced by a key pinned in this binary.</summary>
    Trusted,

    /// <summary>The file is not a readable manifest.</summary>
    Malformed,

    /// <summary>No signature comes from a key known to this binary.</summary>
    UnknownKey,

    /// <summary>
    /// A known key signed, but the signature does not match the payload. The content
    /// was modified after signing, or the signature was fabricated.
    /// </summary>
    BadSignature,
}

public sealed record ManifestVerdict(
    ManifestStatus Status,
    ManifestPayload? Payload,
    string? KeyId,
    string Explanation)
{
    public bool IsTrusted => Status == ManifestStatus.Trusted;
}
