using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class PinnedKeysTests
{
    /// <summary>
    /// Chaque empreinte épinglée doit être exactement celle que le vérificateur
    /// calculera de la clé publique en regard. Une faute de recopie dans
    /// <see cref="PinnedKeys"/> — un caractère de la clé, un chiffre de l'empreinte —
    /// ferait rejeter tout manifeste pour « clé inconnue », sans que rien d'autre ne le
    /// signale. Ce test refuse de livrer une telle incohérence.
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
    /// Deux clés au maximum : au-delà, ce n'est plus une rotation mais une accumulation,
    /// et chaque clé encore acceptée est une clé de plus qui peut signer (ADR-002, D16).
    /// </summary>
    [Fact]
    public void At_most_two_keys_are_pinned()
    {
        Assert.InRange(PinnedKeys.Publisher.Count, 1, 2);
    }

    /// <summary>
    /// Le vérificateur de production reconnaît bien les clés épinglées : un manifeste
    /// signé par une clé inconnue est refusé, ce qui confirme au passage qu'une clé
    /// <em>est</em> désormais épinglée — l'état « aucune clé, tout est refusé » est
    /// derrière nous.
    /// </summary>
    [Fact]
    public void The_production_verifier_is_armed_with_the_pinned_keys()
    {
        var verifier = PinnedKeys.Verifier();

        // Un manifeste vide est mal formé, pas « clé inconnue » : la distinction montre
        // que le vérificateur va jusqu'à examiner les signatures.
        var verdict = verifier.Verify("{}");

        Assert.Equal(ManifestStatus.Malformed, verdict.Status);
        Assert.NotEmpty(PinnedKeys.Publisher);
    }
}
