namespace Rempart.Core.Providers;

public enum SignatureStatus
{
    /// <summary>Signature valide, chaîne de confiance vérifiée.</summary>
    Valid,

    /// <summary>Aucune signature.</summary>
    Unsigned,

    /// <summary>Signée, mais la vérification échoue — expirée, révoquée, altérée.</summary>
    Invalid,

    /// <summary>Le fichier n'existe pas au chemin indiqué.</summary>
    FileNotFound,

    /// <summary>La vérification n'a pas pu aboutir. Ni valide, ni invalide.</summary>
    Unknown,
}

public sealed record FileSignature(
    SignatureStatus Status,
    string? Publisher = null,
    string? Sha256 = null);

/// <summary>
/// Vérifie la signature Authenticode d'un fichier.
///
/// C'est le seul moyen de distinguer un binaire légitime lancé au démarrage d'un
/// programme déposé là par un tiers. Un chemin et un nom ne prouvent rien : les deux
/// s'imitent trivialement.
///
/// Une vérification qui échoue rend <see cref="SignatureStatus.Unknown"/>, jamais
/// <see cref="SignatureStatus.Unsigned"/> : confondre « je n'ai pas pu vérifier » avec
/// « ce n'est pas signé » produirait des alertes fausses sur les machines les moins
/// auditables — l'inverse exact de ce qu'on cherche.
/// </summary>
public interface ISignatureProvider
{
    FileSignature Verify(string path);
}
