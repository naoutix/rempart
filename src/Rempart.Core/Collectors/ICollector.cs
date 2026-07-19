using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

public enum CollectorStatus
{
    /// <summary>Collecte complète.</summary>
    Ok,

    /// <summary>Collecte partielle, faute de droits. Jamais silencieux (ADR-001).</summary>
    InsufficientPrivileges,

    /// <summary>La donnée n'existe pas sur cette machine (matériel ou édition absente).</summary>
    Unavailable,

    /// <summary>Le collecteur a échoué. Le scan continue : un collecteur n'en bloque pas un autre.</summary>
    Failed,
}

public sealed record CollectorResult(
    string Name,
    CollectorStatus Status,
    Dictionary<string, string?> Fields,
    List<string> Diagnostics);

/// <summary>
/// Un collecteur lit l'état de la machine à travers <see cref="ProviderSet"/> et n'en
/// tire aucune conclusion : l'évaluation appartient au moteur de règles (M1).
/// </summary>
public interface ICollector
{
    string Name { get; }

    CollectorResult Collect(ProviderSet providers);
}
