using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// État brut d'une machine, rejouable hors-ligne. Chaque machine auditée devient une
/// fixture de test permanente — une VM vierge n'a aucun bloatware OEM, les machines
/// réelles sont le seul banc de test valable.
/// </summary>
public sealed class MachineSnapshot
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public string CapturedAtUtc { get; set; } = string.Empty;

    /// <summary>
    /// Vrai si hostname, numéros de série et propriétaire ont été remplacés par des
    /// empreintes. Les fixtures versionnées doivent l'être (voir .gitignore).
    /// </summary>
    public bool Anonymised { get; set; }

    /// <summary>Clé : <c>chemin||nomDeValeur</c>. Voir <see cref="SnapshotKeys"/>.</summary>
    public Dictionary<string, RegistryRead> Registry { get; set; } = [];

    public SystemInfo? SystemInfo { get; set; }
}

public static class SnapshotKeys
{
    private const string Separator = "||";

    /// <summary>Marqueur de test d'existence, distinct de toute valeur nommée réelle.</summary>
    public const string ExistenceMarker = "#exists";

    public static string Value(string keyPath, string valueName) =>
        string.Concat(keyPath, Separator, valueName);

    public static string Existence(string keyPath) => Value(keyPath, ExistenceMarker);
}
