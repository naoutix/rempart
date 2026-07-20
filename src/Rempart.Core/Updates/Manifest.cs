namespace Rempart.Core.Updates;

/// <summary>
/// Un jeu de données publié, décrit par son empreinte.
///
/// L'empreinte est ce qui fait foi : le nom et la version sont du confort de lecture,
/// mais c'est <see cref="Sha256"/> qui décide si le fichier reçu est celui que
/// l'éditeur a signé.
/// </summary>
public sealed record ManifestEntry(
    string Name,
    string Version,
    string Sha256,
    long SizeBytes);

/// <summary>
/// La charge utile signée : ce que l'éditeur affirme, et rien d'autre.
///
/// Volontairement pauvre. Tout ce qu'on y ajoute devient une affirmation qu'un porteur
/// de clé peut faire au sujet d'une machine qui lui fait confiance.
/// </summary>
public sealed record ManifestPayload(
    int SchemaVersion,
    string PublishedAtUtc,
    List<ManifestEntry> Datasets);

/// <summary>
/// Le fichier tel qu'il voyage : la charge utile en clair, et sa signature.
///
/// <para>
/// <see cref="Payload"/> est la charge utile encodée en base64, et non un objet JSON
/// imbriqué. Ce n'est pas une commodité mais le cœur du dispositif : <b>la signature
/// porte sur ces octets-là exactement</b>. Un objet imbriqué obligerait à ré-sérialiser
/// avant de vérifier, et la moindre différence — un espace, l'ordre des champs, la
/// façon d'échapper un accent — invaliderait une signature parfaitement valide. On
/// vérifie les octets, puis on les analyse. Jamais l'inverse.
/// </para>
///
/// <para>
/// <see cref="Signatures"/> est une liste parce que la rotation de clé l'exige
/// (ADR-002, D16) : pendant le chevauchement, un manifeste porte la signature de
/// l'ancienne clé et de la nouvelle, et les binaires en circulation acceptent celle
/// qu'ils connaissent.
/// </para>
/// </summary>
public sealed record SignedManifest(
    string Payload,
    List<ManifestSignature> Signatures);

/// <summary>
/// Une signature, rattachée à la clé qui l'a produite par l'empreinte de celle-ci.
///
/// Sans <see cref="KeyId"/>, vérifier reviendrait à essayer chaque clé connue contre
/// chaque signature — faisable, mais on ne saurait pas dire <i>laquelle</i> a échoué,
/// et un diagnostic qui ne distingue pas « signée par une clé que je ne connais pas »
/// de « signature invalide » ne vaut rien le jour où ça compte.
/// </summary>
public sealed record ManifestSignature(string KeyId, string Value);

/// <summary>
/// Ce qu'on a conclu d'un manifeste. Chaque cas est distinct, et aucun ne se replie
/// sur un autre.
///
/// La tentation d'un booléen est forte et c'est exactement l'erreur qui a rendu WMI
/// inopérant deux lots durant : un <c>catch</c> unique traduisait toute défaillance en
/// « accès refusé », rendant un bug indiscernable d'un manque de droits. Ici, une
/// signature falsifiée et une clé inconnue appellent des réactions opposées — l'une
/// est une attaque, l'autre est probablement un binaire trop vieux.
/// </summary>
public enum ManifestStatus
{
    /// <summary>Signature valide, produite par une clé épinglée dans ce binaire.</summary>
    Trusted,

    /// <summary>Le fichier n'est pas un manifeste lisible.</summary>
    Malformed,

    /// <summary>Aucune signature ne provient d'une clé connue de ce binaire.</summary>
    UnknownKey,

    /// <summary>
    /// Une clé connue a signé, mais la signature ne correspond pas à la charge utile.
    /// Le contenu a été modifié après signature, ou la signature a été fabriquée.
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
