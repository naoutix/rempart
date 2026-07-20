using System.Security.Cryptography;
using System.Text.Json;
using Rempart.Core.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Vérifie un manifeste contre les clés publiques épinglées dans ce binaire.
///
/// <para>
/// C'est le point unique où le projet décide de faire confiance à des données qu'il
/// n'a pas compilées. L'ADR-002 le formule ainsi : les règles définissent ce que
/// « sécurisé » signifie, donc quiconque les remplace silencieusement ne casse pas
/// l'outil, il le fait <b>mentir</b>. Un scan rendrait 100 % sur une machine ouverte,
/// et personne ne chercherait.
/// </para>
///
/// <para>
/// ECDSA P-256 plutôt qu'Ed25519, qui aurait été le choix naturel : .NET 10 n'expose
/// pas Ed25519 comme type public. ML-DSA et SLH-DSA, post-quantiques, existent mais
/// sont marqués expérimentaux (<c>SYSLIB5006</c> : « susceptible d'être modifié ou
/// supprimé »). Bâtir un canal de confiance sur une API que Microsoft se réserve de
/// retirer serait un mauvais échange pour un outil dont l'intérêt est de ne pas
/// casser. P-256 est stable, disponible partout, et ses signatures font 64 octets
/// fixes.
/// </para>
/// </summary>
public sealed class ManifestVerifier
{
    /// <summary>
    /// Clés publiques acceptées, au format SubjectPublicKeyInfo encodé en base64,
    /// indexées par leur empreinte.
    ///
    /// Deux au maximum, et c'est une contrainte de l'ADR-002 (D16) et non une limite
    /// technique : la rotation exige un chevauchement — publier avec la nouvelle clé,
    /// laisser l'ancienne valide le temps que les binaires en circulation soient
    /// remplacés, puis la retirer. Sans ce chevauchement, toute rotation casserait les
    /// installations existantes.
    /// </summary>
    private readonly IReadOnlyDictionary<string, string> keys;

    public ManifestVerifier(IReadOnlyDictionary<string, string> trustedKeys)
    {
        keys = trustedKeys;
    }

    /// <summary>
    /// Empreinte d'une clé publique : les douze premiers caractères du SHA-256 de son
    /// encodage SPKI. Même forme que l'empreinte du catalogue de règles, pour que les
    /// deux se lisent pareil dans un rapport.
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

            // Les champs sont déclarés non-nullables, mais un record n'impose rien à
            // la désérialisation : `{}` produit un objet dont tous les champs sont
            // null. Le vérifier explicitement — sans quoi un fichier vide fait planter
            // le processus au lieu d'être refusé, et il arrive par le réseau.
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

        // Une signature d'une clé connue existe-t-elle seulement ? Distinguer ce cas
        // évite d'annoncer une falsification là où il n'y a qu'un binaire trop ancien
        // pour connaître la clé courante.
        var known = signed.Signatures.Where(s => keys.ContainsKey(s.KeyId)).ToList();

        if (known.Count == 0)
        {
            var offered = string.Join(", ", signed.Signatures.Select(s => s.KeyId));
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

            // Signature valide : et seulement maintenant on analyse le contenu.
            try
            {
                var payload = JsonSerializer.Deserialize(
                    payloadBytes, RempartJsonContext.Default.ManifestPayload);

                if (payload?.Datasets is null)
                {
                    return Fail(ManifestStatus.Malformed,
                        "Charge utile signée mais vide ou sans jeu de données.");
                }

                return new ManifestVerdict(ManifestStatus.Trusted, payload, signature.KeyId,
                    $"Signé par {signature.KeyId}, publié le {payload.PublishedAtUtc}.");
            }
            catch (JsonException ex)
            {
                // Signature bonne, contenu incompréhensible : l'éditeur a publié
                // quelque chose que ce binaire ne sait pas lire. Ce n'est pas une
                // attaque, et le dire évite une fausse alerte.
                return Fail(ManifestStatus.Malformed,
                    $"Charge utile correctement signée mais illisible par cette version : " +
                    $"{ex.Message}");
            }
        }

        return Fail(ManifestStatus.BadSignature,
            "Une clé connue est revendiquée, mais la signature ne correspond pas à la " +
            "charge utile. Le contenu a été modifié après signature. Ne rien charger.");
    }

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
            // Une clé ou une signature mal formée n'est pas une signature valide.
            // Elle ne doit pas non plus interrompre l'examen des autres signatures :
            // pendant une rotation, le manifeste en porte plusieurs.
            return false;
        }
    }

    /// <summary>
    /// Vérifie qu'un fichier reçu est bien celui que le manifeste décrit.
    ///
    /// Séparé de la vérification de signature parce que ce sont deux questions
    /// distinctes : le manifeste dit-il vrai, et ai-je bien reçu ce qu'il annonce.
    /// Un manifeste authentique accompagné d'un fichier corrompu doit se voir comme
    /// tel, et non comme une signature invalide.
    /// </summary>
    public static bool FileMatches(ManifestEntry entry, byte[] content)
    {
        if (content.LongLength != entry.SizeBytes)
        {
            return false;
        }

        var actual = Convert.ToHexStringLower(SHA256.HashData(content));

        // Comparaison à temps constant : par principe, le code qui décide d'une
        // confiance ne renseigne pas sur l'écart entre l'attendu et le reçu.
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(actual),
            System.Text.Encoding.ASCII.GetBytes(entry.Sha256.ToLowerInvariant()));
    }

    private static ManifestVerdict Fail(ManifestStatus status, string explanation) =>
        new(status, null, null, explanation);
}
