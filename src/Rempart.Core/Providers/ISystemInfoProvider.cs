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
    IDriverProvider? drivers = null,
    IProcessProvider? processes = null,
    IListeningPortProvider? listeningPorts = null,
    IFirewallProvider? firewall = null,
    IDnsProvider? dns = null,
    IHostsFileProvider? hostsFile = null,
    IProxyProvider? proxy = null,
    IWifiProfileProvider? wifi = null)
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

    /// <summary>Absent, aucun processus n'est énuméré — pas d'invention d'exécution.</summary>
    public IProcessProvider Processes { get; } = processes ?? EmptyProcesses.Instance;

    /// <summary>Absent, aucun port n'est énuméré — pas d'invention d'écoute.</summary>
    public IListeningPortProvider ListeningPorts { get; } =
        listeningPorts ?? EmptyListeningPorts.Instance;

    /// <summary>Absent, l'état du pare-feu reste « inconnu » — la règle croisée se retire.</summary>
    public IFirewallProvider Firewall { get; } = firewall ?? UnreadFirewall.Instance;

    /// <summary>Absent, aucune interface DNS n'est énumérée — pas d'invention de résolveur.</summary>
    public IDnsProvider Dns { get; } = dns ?? EmptyDns.Instance;

    /// <summary>Absent, le fichier hosts est vu vide — pas d'invention de correspondance.</summary>
    public IHostsFileProvider HostsFile { get; } = hostsFile ?? EmptyHostsFile.Instance;

    /// <summary>Absent, aucune configuration proxy n'est inventée — config vide.</summary>
    public IProxyProvider Proxy { get; } = proxy ?? EmptyProxy.Instance;

    /// <summary>Absent, aucun profil Wi-Fi n'est énuméré — pas d'invention de réseau.</summary>
    public IWifiProfileProvider Wifi { get; } = wifi ?? EmptyWifi.Instance;
}

internal sealed class EmptyDns : IDnsProvider
{
    public static readonly EmptyDns Instance = new();

    public IReadOnlyList<DnsInterface> Read() => [];
}

internal sealed class EmptyHostsFile : IHostsFileProvider
{
    public static readonly EmptyHostsFile Instance = new();

    public IReadOnlyList<string> ReadLines() => [];
}

internal sealed class EmptyProxy : IProxyProvider
{
    public static readonly EmptyProxy Instance = new();

    public ProxyConfiguration Read() => ProxyConfiguration.Empty;
}

internal sealed class EmptyWifi : IWifiProfileProvider
{
    public static readonly EmptyWifi Instance = new();

    public IReadOnlyList<WifiProfile> Read() => [];
}

internal sealed class UnreadFirewall : IFirewallProvider
{
    public static readonly UnreadFirewall Instance = new();

    public FirewallState Read() => FirewallState.Unread;
}

internal sealed class EmptyListeningPorts : IListeningPortProvider
{
    public static readonly EmptyListeningPorts Instance = new();

    public IReadOnlyList<ListeningPort> Enumerate() => [];
}

internal sealed class EmptyProcesses : IProcessProvider
{
    public static readonly EmptyProcesses Instance = new();

    public IReadOnlyList<RunningProcess> Enumerate() => [];
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
