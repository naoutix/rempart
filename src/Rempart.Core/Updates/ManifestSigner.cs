using System.Security.Cryptography;
using System.Text.Json;
using Rempart.Core.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Produit un manifeste signé — le pendant de <see cref="ManifestVerifier"/>.
///
/// <para>
/// C'est l'acte de publication de l'ADR-002, et il reste manuel (D16) : aucune
/// automatisation ne détient la clé, la signature se fait sur une machine hors ligne.
/// Ce code est le même des deux côtés d'un principe — <b>on signe les octets, puis on
/// les décrit ; jamais l'inverse</b>. La charge utile est sérialisée une fois, ces
/// octets-là sont signés, et ce sont eux qui voyagent en base64. Le vérificateur
/// signera sur exactement la même suite d'octets, sans re-sérialiser.
/// </para>
/// </summary>
public static class ManifestSigner
{
    /// <summary>
    /// Décrit un fichier tel que le manifeste doit le déclarer : empreinte et taille,
    /// ce sur quoi le vérificateur jugera qu'un fichier reçu est bien celui-ci.
    /// </summary>
    public static ManifestEntry Describe(string name, byte[] content, string? kind = null)
    {
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(content));

        return new ManifestEntry(
            name,
            // Version dérivée du contenu : deux publications d'un même fichier portent
            // la même, deux contenus différents non. Rien à saisir à la main, rien à
            // oublier d'incrémenter.
            sha256[..8],
            sha256,
            content.LongLength,
            kind ?? DatasetKind.Infer(name));
    }

    /// <summary>
    /// Signe une charge utile avec la clé privée d'éditeur.
    ///
    /// La signature ECDSA est produite au format IEEE P1363 (r‖s, 64 octets fixes pour
    /// P-256) — le format par défaut de <c>SignData</c>, et celui qu'attend
    /// <c>VerifyData</c> côté vérificateur. Les deux côtés s'accordent sans le dire ;
    /// un test le prouve plutôt que de le supposer.
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
