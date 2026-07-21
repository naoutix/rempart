namespace Rempart.Core.Providers;

public sealed record SystemInfo(
    string MachineName,
    string OsVersion,
    bool Is64BitOperatingSystem,
    bool IsElevated,
    int ProcessorCount,
    long UptimeSeconds,
    string FirmwareType,

    /// <summary>
    /// Machine jointe à un domaine Active Directory.
    ///
    /// Sert de condition d'applicabilité : plusieurs durcissements n'ont de sens que
    /// sous stratégie de groupe centrale, et les appliquer sur un poste autonome
    /// retire des fonctionnalités sans rien apporter.
    /// </summary>
    bool IsDomainJoined = false);

/// <summary>
/// Informations système qui ne viennent pas du registre. Abstrait pour la même raison
/// que <see cref="IRegistryProvider"/> : un instantané doit pouvoir être rejoué à
/// l'identique, y compris pour des valeurs volatiles comme l'uptime.
/// </summary>
public interface ISystemInfoProvider
{
    SystemInfo Read();
}

/// <summary>Les providers dont disposent collecteurs et règles.</summary>
public sealed class ProviderSet(
    IRegistryProvider registry,
    ISystemInfoProvider systemInfo,
    IServiceStateProvider? services = null,
    ISecurityPolicyProvider? policy = null,
    IWmiProvider? wmi = null,
    ISignatureProvider? signatures = null,
    IFileSystemProvider? files = null,
    IScheduledTaskProvider? scheduledTasks = null,
    IDriverProvider? drivers = null)
{
    public IRegistryProvider Registry { get; } = registry;

    public ISystemInfoProvider SystemInfo { get; } = systemInfo;

    /// <summary>
    /// Absent tant qu'aucun appelant n'en fournit : les contrôles portant sur les
    /// services rendent alors « non vérifiable » plutôt que d'échouer. Un provider
    /// manquant est une lacune de couverture, pas une non-conformité de la machine.
    /// </summary>
    public IServiceStateProvider Services { get; } = services ?? UnavailableServices.Instance;

    /// <summary>Même principe : absent, les contrôles de politique restent sans verdict.</summary>
    public ISecurityPolicyProvider Policy { get; } = policy ?? UnavailablePolicy.Instance;

    /// <summary>Même principe : absent, les contrôles WMI restent sans verdict.</summary>
    public IWmiProvider Wmi { get; } = wmi ?? UnavailableWmi.Instance;

    /// <summary>Absent, toute signature reste indéterminée — jamais « non signé ».</summary>
    public ISignatureProvider Signatures { get; } = signatures ?? UnavailableSignatures.Instance;

    /// <summary>Absent, aucun dossier n'est énuméré — pas d'invention de contenu.</summary>
    public IFileSystemProvider Files { get; } = files ?? EmptyFileSystem.Instance;

    /// <summary>
    /// Absent, l'énumération rend « refusée » et non « aucune tâche ». Rendre une
    /// liste vide ferait passer une absence de provider pour un planificateur propre.
    /// </summary>
    public IScheduledTaskProvider ScheduledTasks { get; } =
        scheduledTasks ?? UnavailableScheduledTasks.Instance;

    /// <summary>Absent, aucun pilote n'est énuméré — pas d'invention de chargement.</summary>
    public IDriverProvider Drivers { get; } = drivers ?? EmptyDrivers.Instance;
}

internal sealed class EmptyDrivers : IDriverProvider
{
    public static readonly EmptyDrivers Instance = new();

    public IReadOnlyList<LoadedDriver> Enumerate() => [];
}

internal sealed class UnavailableScheduledTasks : IScheduledTaskProvider
{
    public static readonly UnavailableScheduledTasks Instance = new();

    public ScheduledTaskRead Enumerate() =>
        ScheduledTaskRead.Failed("Aucun énumérateur de tâches planifiées n'est disponible.");
}

internal sealed class EmptyFileSystem : IFileSystemProvider
{
    public static readonly EmptyFileSystem Instance = new();

    public IReadOnlyList<string> ListFiles(string directory) => [];
}

internal sealed class UnavailableSignatures : ISignatureProvider
{
    public static readonly UnavailableSignatures Instance = new();

    public FileSignature Verify(string path) => new(SignatureStatus.Unknown);
}

internal sealed class UnavailableWmi : IWmiProvider
{
    public static readonly UnavailableWmi Instance = new();

    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties) =>
        WmiRead.AccessDenied;
}

internal sealed class UnavailablePolicy : ISecurityPolicyProvider
{
    public static readonly UnavailablePolicy Instance = new();

    public PolicyFacts Read() => PolicyFacts.AccessDenied;
}

/// <summary>Répond « accès refusé » à toute question : aucune conclusion n'en sort.</summary>
internal sealed class UnavailableServices : IServiceStateProvider
{
    public static readonly UnavailableServices Instance = new();

    public ServiceRead Read(string serviceName) => ServiceRead.AccessDenied;
}
