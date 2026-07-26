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
    /// Machine joined to an Active Directory domain.
    ///
    /// Serves as an applicability condition: several hardenings only make sense under
    /// central group policy, and applying them to a standalone workstation removes
    /// functionality without gaining anything.
    /// </summary>
    bool IsDomainJoined = false);

/// <summary>
/// System information that does not come from the registry. Abstracted for the same
/// reason as <see cref="IRegistryProvider"/>: a snapshot must be replayable exactly,
/// including for volatile values such as uptime.
/// </summary>
public interface ISystemInfoProvider
{
    SystemInfo Read();
}

/// <summary>The providers available to collectors and rules.</summary>
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
    IWifiProfileProvider? wifi = null,
    ISoftwareInventoryProvider? softwareInventory = null,
    IBrowserExtensionProvider? browserExtensions = null,
    IComponentStoreProvider? componentStore = null)
{
    public IRegistryProvider Registry { get; } = registry;

    public ISystemInfoProvider SystemInfo { get; } = systemInfo;

    /// <summary>
    /// Absent until a caller supplies one: checks that look at services then yield
    /// "not verifiable" instead of failing. A missing provider is a coverage gap,
    /// not a non-compliance of the machine.
    /// </summary>
    public IServiceStateProvider Services { get; } = services ?? UnavailableServices.Instance;

    /// <summary>Same principle: absent, policy checks are left without a verdict.</summary>
    public ISecurityPolicyProvider Policy { get; } = policy ?? UnavailablePolicy.Instance;

    /// <summary>Same principle: absent, WMI checks are left without a verdict.</summary>
    public IWmiProvider Wmi { get; } = wmi ?? UnavailableWmi.Instance;

    /// <summary>Absent, every signature stays undetermined — never "unsigned".</summary>
    public ISignatureProvider Signatures { get; } = signatures ?? UnavailableSignatures.Instance;

    /// <summary>Absent, no directory is enumerated — no content is invented.</summary>
    public IFileSystemProvider Files { get; } = files ?? EmptyFileSystem.Instance;

    /// <summary>
    /// Absent, enumeration yields "denied" rather than "no tasks". Returning an
    /// empty list would make a missing provider look like a clean scheduler.
    /// </summary>
    public IScheduledTaskProvider ScheduledTasks { get; } =
        scheduledTasks ?? UnavailableScheduledTasks.Instance;

    /// <summary>Absent, no driver is enumerated — no loading is invented.</summary>
    public IDriverProvider Drivers { get; } = drivers ?? EmptyDrivers.Instance;

    /// <summary>Absent, no process is enumerated — no execution is invented.</summary>
    public IProcessProvider Processes { get; } = processes ?? EmptyProcesses.Instance;

    /// <summary>Absent, no port is enumerated — no listening is invented.</summary>
    public IListeningPortProvider ListeningPorts { get; } =
        listeningPorts ?? EmptyListeningPorts.Instance;

    /// <summary>Absent, the firewall state stays "unknown" — the cross-check rule stands down.</summary>
    public IFirewallProvider Firewall { get; } = firewall ?? UnreadFirewall.Instance;

    /// <summary>Absent, no DNS interface is enumerated — no resolver is invented.</summary>
    public IDnsProvider Dns { get; } = dns ?? EmptyDns.Instance;

    /// <summary>Absent, the hosts file is seen as empty — no mapping is invented.</summary>
    public IHostsFileProvider HostsFile { get; } = hostsFile ?? EmptyHostsFile.Instance;

    /// <summary>Absent, no proxy configuration is invented — empty config.</summary>
    public IProxyProvider Proxy { get; } = proxy ?? EmptyProxy.Instance;

    /// <summary>Absent, no Wi-Fi profile is enumerated — no network is invented.</summary>
    public IWifiProfileProvider Wifi { get; } = wifi ?? EmptyWifi.Instance;

    /// <summary>Absent, no software is enumerated — no inventory is invented.</summary>
    public ISoftwareInventoryProvider SoftwareInventory { get; } =
        softwareInventory ?? EmptySoftwareInventory.Instance;

    /// <summary>Absent, no extension is enumerated — no install is invented.</summary>
    public IBrowserExtensionProvider BrowserExtensions { get; } =
        browserExtensions ?? EmptyBrowserExtensions.Instance;

    /// <summary>
    /// Absent, the store analysis is reported as not run — never as zero bytes to
    /// reclaim, which would be an answer where there is none.
    /// </summary>
    public IComponentStoreProvider ComponentStore { get; } =
        componentStore ?? UnanalysedComponentStore.Instance;
}

internal sealed class UnanalysedComponentStore : IComponentStoreProvider
{
    public static readonly UnanalysedComponentStore Instance = new();

    public ComponentStoreRead Read() => ComponentStoreRead.Failed(
        "Analyse du magasin de composants non effectuée : aucun fournisseur câblé.");
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

internal sealed class EmptySoftwareInventory : ISoftwareInventoryProvider
{
    public static readonly EmptySoftwareInventory Instance = new();

    public IReadOnlyList<InstalledSoftware> Read() => [];
}

internal sealed class EmptyBrowserExtensions : IBrowserExtensionProvider
{
    public static readonly EmptyBrowserExtensions Instance = new();

    public IReadOnlyList<BrowserExtension> Read() => [];
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

/// <summary>Answers "access denied" to every question: no conclusion can be drawn from it.</summary>
internal sealed class UnavailableServices : IServiceStateProvider
{
    public static readonly UnavailableServices Instance = new();

    public ServiceRead Read(string serviceName) => ServiceRead.AccessDenied;
}
