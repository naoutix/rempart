namespace Rempart.Core.Updates;

/// <summary>
/// Les clés publiques d'éditeur épinglées dans ce binaire.
///
/// <para>
/// C'est ici que se matérialise la confiance décrite par l'ADR-002 : un manifeste
/// n'est cru que s'il porte la signature de l'une de ces clés. Les valeurs sont
/// publiques par nature — une clé publique vérifie, elle ne signe pas — et leur place
/// est donc dans le code, versionnée et lisible, pas dans un secret.
/// </para>
///
/// <para>
/// La clé privée correspondante a été générée hors de toute machine de développement,
/// chiffrée par une phrase de passe, et ne revient jamais ici (ADR-002, D16). Ce
/// fichier ne contient que de quoi <em>vérifier</em>, jamais de quoi signer.
/// </para>
///
/// <para>
/// Deux clés au maximum, et uniquement le temps d'une rotation : publier avec la
/// nouvelle, laisser l'ancienne valide le temps que les binaires en circulation soient
/// remplacés, puis la retirer. Sans ce chevauchement, toute rotation casserait les
/// installations existantes.
/// </para>
/// </summary>
public static class PinnedKeys
{
    /// <summary>
    /// Empreinte (clé) vers clé publique en base64 SPKI (valeur). L'empreinte doit être
    /// exactement <see cref="ManifestVerifier.KeyId"/> de la valeur — un test le vérifie,
    /// pour qu'une faute de recopie dans ce fichier ne puisse pas être livrée.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Publisher =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // Générée le 2026-07-21, hors ligne, dans un bac à sable Windows jetable.
            ["168e543a9424"] =
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgzwiZrW8eJHyqXlqmp5JyB7+5/xC+hn9" +
                "9Q0v/r/nvzoBdyR2xRWRBswGOIv/0sEIrEgG43ecpDLDTL6n5xf6mA==",
        };

    /// <summary>Un vérificateur armé des clés de production.</summary>
    public static ManifestVerifier Verifier() => new(Publisher);
}
