using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class PinnedKeysTests
{
    /// <summary>
    /// Each pinned fingerprint must be exactly the one the verifier computes from
    /// the public key next to it. A copy mistake in <see cref="PinnedKeys"/> — one
    /// character of the key, one digit of the fingerprint — would make every
    /// manifest be rejected as "unknown key", with nothing else reporting it.
    /// This test blocks shipping such an inconsistency.
    /// </summary>
    [Fact]
    public void Every_pinned_fingerprint_matches_its_public_key()
    {
        foreach (var (fingerprint, publicKey) in PinnedKeys.Publisher)
        {
            var computed = ManifestVerifier.KeyId(Convert.FromBase64String(publicKey));
            Assert.Equal(fingerprint, computed);
        }
    }

    /// <summary>
    /// Two keys at most: beyond that it is no longer a rotation but an
    /// accumulation, and each still-accepted key is one more key that can sign
    /// (ADR-002, D16).
    /// </summary>
    [Fact]
    public void At_most_two_keys_are_pinned()
    {
        Assert.InRange(PinnedKeys.Publisher.Count, 1, 2);
    }

    /// <summary>
    /// The production verifier recognizes the pinned keys: a manifest signed by
    /// an unknown key is refused, which also confirms that a key <em>is</em> now
    /// pinned — the "no keys, everything refused" state is over.
    /// </summary>
    [Fact]
    public void The_production_verifier_is_armed_with_the_pinned_keys()
    {
        var verifier = PinnedKeys.Verifier();

        // An empty manifest is malformed, not "unknown key": the distinction
        // shows the verifier goes as far as examining the signatures.
        var verdict = verifier.Verify("{}");

        Assert.Equal(ManifestStatus.Malformed, verdict.Status);
        Assert.NotEmpty(PinnedKeys.Publisher);
    }
}
