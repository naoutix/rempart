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

    /// <summary>Clé : nom du service.</summary>
    public Dictionary<string, ServiceRead> Services { get; set; } = [];

    /// <summary>Faits de politique locale, ou null s'ils n'ont pas pu être lus.</summary>
    public PolicyFacts? Policy { get; set; }

    /// <summary>Clé : <c>espaceDeNoms:Classe||propriétés</c>.</summary>
    public Dictionary<string, WmiRead> Wmi { get; set; } = [];

    /// <summary>
    /// Noms des valeurs présentes dans une clé énumérée. Distinct de
    /// <see cref="Registry"/>, qui ne dit rien de ce qu'on n'a pas cherché.
    /// </summary>
    public Dictionary<string, List<string>> RegistryLists { get; set; } = [];

    /// <summary>Noms des sous-clés d'une clé énumérée. Distinct de <see cref="RegistryLists"/>,
    /// qui porte les noms de valeurs.</summary>
    public Dictionary<string, List<string>> SubKeyLists { get; set; } = [];

    /// <summary>Signatures vérifiées, indexées par chemin de fichier.</summary>
    public Dictionary<string, FileSignature> Signatures { get; set; } = [];

    /// <summary>Contenu des répertoires énumérés.</summary>
    public Dictionary<string, List<string>> Directories { get; set; } = [];

    /// <summary>
    /// Tâches planifiées, ou null si l'instantané est antérieur à leur collecte. Le
    /// null compte : il distingue « pas encore capturé » de « planificateur vide ».
    /// </summary>
    public ScheduledTaskRead? ScheduledTasks { get; set; }

    /// <summary>Pilotes noyau chargés, ou null si l'instantané précède leur collecte.</summary>
    public List<LoadedDriver>? Drivers { get; set; }

    /// <summary>Processus en cours, ou null si l'instantané précède leur collecte.</summary>
    public List<RunningProcess>? Processes { get; set; }

    /// <summary>Points d'écoute réseau, ou null si l'instantané précède leur collecte.</summary>
    public List<ListeningPort>? ListeningPorts { get; set; }

    /// <summary>État du pare-feu, ou null si l'instantané précède sa collecte.</summary>
    public FirewallState? Firewall { get; set; }
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
