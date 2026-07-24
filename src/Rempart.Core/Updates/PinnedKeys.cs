namespace Rempart.Core.Updates;

/// <summary>
/// The publisher public keys pinned in this binary.
///
/// <para>
/// This is where the trust described by ADR-002 is anchored: a manifest is only trusted
/// if it carries a signature from one of these keys. The values are public by nature — a
/// public key verifies, it does not sign — so they belong in code, versioned and
/// readable, not in a secret.
/// </para>
///
/// <para>
/// The corresponding private key was generated away from any development machine,
/// encrypted with a passphrase, and never comes back here (ADR-002, D16). This file only
/// contains what is needed to <em>verify</em>, never anything that can sign.
/// </para>
///
/// <para>
/// Two keys at most, and only for the duration of a rotation: publish with the new key,
/// keep the old one valid until the binaries in circulation are replaced, then remove
/// it. Without that overlap, any rotation would break existing installations.
/// </para>
/// </summary>
public static class PinnedKeys
{
    /// <summary>
    /// Fingerprint (key) to base64 SPKI public key (value). The fingerprint must be
    /// exactly <see cref="ManifestVerifier.KeyId"/> of the value — a test verifies this,
    /// so a copy mistake in this file cannot ship.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Publisher =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // Generated on 2026-07-21, offline, in a disposable Windows sandbox.
            ["168e543a9424"] =
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgzwiZrW8eJHyqXlqmp5JyB7+5/xC+hn9" +
                "9Q0v/r/nvzoBdyR2xRWRBswGOIv/0sEIrEgG43ecpDLDTL6n5xf6mA==",
        };

    /// <summary>A verifier configured with the production keys.</summary>
    public static ManifestVerifier Verifier() => new(Publisher);
}
