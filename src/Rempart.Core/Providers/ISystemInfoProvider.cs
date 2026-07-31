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
    IComponentStoreProvider? componentStore = null,
    IDynamicPortRangeProvider? dynamicPortRange = null)
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

    /// <summary>
    /// Absent, every directory comes back as a read that did not complete rather than as an
    /// empty one: a startup folder nobody enumerated is not a startup folder with nothing in
    /// it, and the report has to say which of the two it is looking at.
    ///
    /// <para>
    /// « Illisible » and no longer « refusé », which is what this said until #173 and what
    /// <c>UnavailableFileSystem</c> then answered: nobody denied anything here, and a reader
    /// sent to re-run elevated over a provider that was never wired gets advice that cannot
    /// work. The same correction the policy provider had in #160, one channel later.
    /// </para>
    /// </summary>
    public IFileSystemProvider Files { get; } = files ?? UnavailableFileSystem.Instance;

    /// <summary>
    /// Absent, enumeration yields "denied" rather than "no tasks". Returning an
    /// empty list would make a missing provider look like a clean scheduler.
    /// </summary>
    public IScheduledTaskProvider ScheduledTasks { get; } =
        scheduledTasks ?? UnavailableScheduledTasks.Instance;

    /// <summary>
    /// Absent, enumeration yields "denied" rather than "no drivers" — same reasoning as
    /// the scheduler above. An empty list would make a missing provider look like a
    /// machine with nothing loaded, on the surface that carries the LOLDrivers check.
    /// </summary>
    public IDriverProvider Drivers { get; } = drivers ?? UnavailableDrivers.Instance;

    /// <summary>Absent, enumeration yields "denied" rather than "no processes": no
    /// machine runs none, so an empty list could only ever be a failure to look.</summary>
    public IProcessProvider Processes { get; } = processes ?? UnavailableProcesses.Instance;

    /// <summary>
    /// Absent, enumeration yields "denied" rather than "no port": no running machine
    /// listens on none, so an empty list could only ever be a failure to look — the same
    /// reasoning as drivers and processes above.
    /// </summary>
    public IListeningPortProvider ListeningPorts { get; } =
        listeningPorts ?? UnavailableListeningPorts.Instance;

    /// <summary>Absent, the firewall state stays "unknown" — the cross-check rule stands down.</summary>
    public IFirewallProvider Firewall { get; } = firewall ?? UnreadFirewall.Instance;

    /// <summary>
    /// Absent, the DNS read comes back as one that did not happen — never as a machine that
    /// resolves through nothing.
    ///
    /// <para>
    /// « Nothing was asked, so there is nothing to report » is what this said until #192, and
    /// what <c>EmptyDns</c> then answered: <c>DnsRead.Found([])</c>, a successful and empty
    /// read, indistinguishable from an adapter carrying no resolver. The premise is the false
    /// one — a scan that asked nothing has a hole in its coverage, and the surface it has a hole
    /// on is the one a hijacked resolver sits on. The startup folders four properties up carried
    /// the correction in writing for three milestones: a startup folder nobody enumerated is not
    /// a startup folder with nothing in it.
    /// </para>
    /// </summary>
    public IDnsProvider Dns { get; } = dns ?? UnreadDns.Instance;

    /// <summary>
    /// Absent, the <c>hosts</c> file is reported as unread — never as a file holding no mapping.
    ///
    /// <para>
    /// The same correction as the DNS above and for the same reason (#192). A <c>hosts</c> file
    /// with no entry is the ordinary state of Windows and stays silent; a <c>hosts</c> file
    /// nobody opened is not that file, and a redirection written into the real one would have
    /// left no trace in the report.
    /// </para>
    /// </summary>
    public IHostsFileProvider HostsFile { get; } = hostsFile ?? UnreadHostsFile.Instance;

    /// <summary>Absent, no proxy configuration is invented — empty config.</summary>
    public IProxyProvider Proxy { get; } = proxy ?? EmptyProxy.Instance;

    /// <summary>Absent, no Wi-Fi profile is enumerated — no network is invented.</summary>
    public IWifiProfileProvider Wifi { get; } = wifi ?? EmptyWifi.Instance;

    /// <summary>
    /// Absent, the inventory is reported as unread — never as a machine with nothing installed,
    /// which is a state no machine has (#192).
    /// </summary>
    public ISoftwareInventoryProvider SoftwareInventory { get; } =
        softwareInventory ?? UnreadSoftwareInventory.Instance;

    /// <summary>
    /// Absent, the profiles are reported as unwalked — never as profiles carrying no extension.
    ///
    /// <para>
    /// Zero extension stays a plausible machine state and stays silent when a walk actually
    /// happened; what may not stay silent is a walk that did not (#192). The profile nobody
    /// opened is the one a sideloaded extension is installed into.
    /// </para>
    /// </summary>
    public IBrowserExtensionProvider BrowserExtensions { get; } =
        browserExtensions ?? UnreadBrowserExtensions.Instance;

    /// <summary>
    /// Absent, the store analysis is reported as not run — never as zero bytes to
    /// reclaim, which would be an answer where there is none.
    /// </summary>
    public IComponentStoreProvider ComponentStore { get; } =
        componentStore ?? UnanalysedComponentStore.Instance;

    /// <summary>
    /// Absent, the range is reported as unread — never as the Windows default, which the
    /// judgement then falls back to <em>while saying that is what it did</em>. The two are
    /// the same numbers and not the same claim.
    /// </summary>
    public IDynamicPortRangeProvider DynamicPortRange { get; } =
        dynamicPortRange ?? UnreadDynamicPortRange.Instance;
}

internal sealed class UnreadDynamicPortRange : IDynamicPortRangeProvider
{
    public static readonly UnreadDynamicPortRange Instance = new();

    public DynamicPortRangeRead Read() => DynamicPortRangeRead.Failed(
        "Aucun fournisseur de plage de ports dynamique n'a été fourni à ce scan.");
}

internal sealed class UnanalysedComponentStore : IComponentStoreProvider
{
    public static readonly UnanalysedComponentStore Instance = new();

    public ComponentStoreRead Read() => ComponentStoreRead.Failed(
        "Analyse du magasin de composants non effectuée : aucun fournisseur câblé.");
}

// Failed and not Found, since #192. « Personne n'a regardé » is indeed not « j'ai regardé et on
// m'a refusé » — that much of the sentence this class used to carry was true, and the status it
// chose was the third one it did not consider. A read nobody performed is neither a refusal nor a
// success: it is a hole in the coverage, and #187 gave this read the channel to say so. What made
// the old answer wrong is that Found is the one member a rule reads as a state of the machine, so
// an unwired provider printed « rien à signaler » over the surface a hijacked resolver sits on.
internal sealed class UnreadDns : IDnsProvider
{
    public static readonly UnreadDns Instance = new();

    public DnsRead Read() => DnsRead.Failed(
        "Aucun fournisseur de résolveurs DNS n'a été fourni à ce scan : les interfaces de la "
        + "machine n'ont pas été énumérées.");
}

internal sealed class UnreadHostsFile : IHostsFileProvider
{
    public static readonly UnreadHostsFile Instance = new();

    // The neighbour's correction, one interface over (#192). A hosts file with no entry is the
    // ordinary state of Windows and is why this read is allowed to be silent on zero lines; a
    // hosts file nobody opened is not that state, and it was answering as if it were.
    public HostsFileRead ReadLines() => HostsFileRead.Failed(
        "Aucun fournisseur de fichier hosts n'a été fourni à ce scan : le fichier n'a pas été lu.");
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

internal sealed class UnreadSoftwareInventory : ISoftwareInventoryProvider
{
    public static readonly UnreadSoftwareInventory Instance = new();

    // Found and empty until #192, « for the reason its DNS neighbour gives » — and the reason
    // moved. « An empty inventory triggers no rule and accuses nobody » is true and is not the
    // question: what the report printed was that this machine has nothing installed, which no
    // machine does, over four sources nobody had opened.
    public SoftwareInventoryRead Read() => SoftwareInventoryRead.Failed(
        "Aucun fournisseur d'inventaire logiciel n'a été fourni à ce scan : aucune des quatre "
        + "sources n'a été lue.");
}

internal sealed class UnreadBrowserExtensions : IBrowserExtensionProvider
{
    public static readonly UnreadBrowserExtensions Instance = new();

    // Found until #192, on the argument that a machine with no browser extension is ordinary.
    // It is, and that argument holds for a walk that took place and found none — the answer
    // this read still gives there. It never held for a walk that did not: no profile was opened,
    // so nothing distinguishes this from the corrupt profile the channel exists to name.
    public BrowserExtensionRead Read() => BrowserExtensionRead.Failed(
        "Aucun fournisseur d'extensions de navigateur n'a été fourni à ce scan : aucun profil "
        + "n'a été parcouru.");
}

internal sealed class UnreadFirewall : IFirewallProvider
{
    public static readonly UnreadFirewall Instance = new();

    public FirewallState Read() => FirewallState.Unread;
}

internal sealed class UnavailableListeningPorts : IListeningPortProvider
{
    public static readonly UnavailableListeningPorts Instance = new();

    public ListeningPortRead Enumerate() =>
        ListeningPortRead.Failed("Aucun fournisseur de points d'écoute n'a été fourni à ce scan.");
}

internal sealed class UnavailableProcesses : IProcessProvider
{
    public static readonly UnavailableProcesses Instance = new();

    public ProcessRead Enumerate() =>
        ProcessRead.Failed("Aucun fournisseur de processus n'a été fourni à ce scan.");
}

internal sealed class UnavailableDrivers : IDriverProvider
{
    public static readonly UnavailableDrivers Instance = new();

    public DriverRead Enumerate() =>
        DriverRead.Failed("Aucun fournisseur de pilotes n'a été fourni à ce scan.");
}

internal sealed class UnavailableScheduledTasks : IScheduledTaskProvider
{
    public static readonly UnavailableScheduledTasks Instance = new();

    // A failure and not a denial, the correction #175 made one interface over for the same
    // sentence: no privilege supplies an enumerator nobody wired, and this call answered
    // « accès refusé » until #177 gave the factory the status its name had always claimed.
    public ScheduledTaskRead Enumerate() =>
        ScheduledTaskRead.Failed("Aucun énumérateur de tâches planifiées n'est disponible.");
}

internal sealed class UnavailableFileSystem : IFileSystemProvider
{
    public static readonly UnavailableFileSystem Instance = new();

    // Named, not empty: a scan wired without a file provider has looked at no startup folder
    // at all, and answering [] made the autoruns collector conclude « aucun autorun » over a
    // surface nobody had opened (DET-FICHIERS-MUET).
    //
    // A failure and not a denial, which is what this call changed to mean in #173 — the same
    // factory, a different state. It said « accès refusé » before, so a scan with no file
    // provider came back « droits insuffisants » and sent its reader to elevate; no privilege
    // supplies a provider nobody wired. « Audit partiel » is the true answer and the one the
    // sibling above already gave for a missing policy provider.
    public DirectoryRead ListFiles(string directory) => DirectoryRead.Failed(
        $"Aucun fournisseur de système de fichiers n'a été fourni à ce scan : le contenu de "
        + $"« {directory} » n'a pas été regardé.");
}

internal sealed class UnavailableSignatures : ISignatureProvider
{
    public static readonly UnavailableSignatures Instance = new();

    public FileSignature Verify(string path) => new(SignatureStatus.Unknown);
}

internal sealed class UnavailableWmi : IWmiProvider
{
    public static readonly UnavailableWmi Instance = new();

    // A failure and not a denial, which is the correction #177 made to the twin of this line in
    // SnapshotWmiProvider and did not make here (#192). WmiRead.AccessDenied carries no reason,
    // Finding.WmiGap reads exactly that as the refusal, and the two WMI-backed collectors then
    // printed « Relancer en administrateur » — over a scan that had supplied no WMI provider at
    // all. No privilege supplies one, so that advice cannot work; the fifth interface to receive
    // the same fix, after the policy (#160), the file system (#173), the scheduler (#175) and
    // the snapshot (#177).
    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties) =>
        WmiRead.Failed(
            $"Aucun fournisseur WMI n'a été fourni à ce scan : {className} sous "
            + $"{namespacePath} n'a pas été interrogé.");
}

internal sealed class UnavailablePolicy : ISecurityPolicyProvider
{
    public static readonly UnavailablePolicy Instance = new();

    // Named, not denied: a scan wired without a policy provider asked netapi32 nothing at
    // all, and answering « accès refusé » put the six shipped type: policy controls under
    // « relancer en administrateur » — the one advice that cannot help with a provider nobody
    // supplied. The shape the five neighbours above already had, and the one this interface
    // could not have until PolicyFacts carried its gaps (#160).
    public PolicyFacts Read() => PolicyFacts.Unread(
        "Aucun fournisseur de politique de sécurité n'a été fourni à ce scan.");
}

/// <summary>
/// Answers "the service was not read" to every question: no conclusion can be drawn from it.
///
/// <para>
/// It answered « accès refusé » until #192, and that is the inversion CONTRIBUTING forbids read
/// the other way round: nobody denied anything, no provider was supplied. Every
/// <c>type: service</c> rule of a scan wired without one landed under « relancer en
/// administrateur » at once — the exact shape #160 corrected for the policy provider, #173 for
/// the file system and #175 for the scheduler, three siblings above in this file, each of them
/// leaving this line as it was.
/// </para>
///
/// <para>
/// The verdict is deliberately unchanged: <c>Unknown</c>, excluded from the score, never
/// <c>Fail</c>. What changes is the remedy the report offers, and the reason now reaches
/// <c>Verdict.Observed</c> instead of an empty « accès refusé » heading.
/// </para>
/// </summary>
internal sealed class UnavailableServices : IServiceStateProvider
{
    public static readonly UnavailableServices Instance = new();

    public ServiceRead Read(string serviceName) => ServiceRead.Failed(
        $"Aucun fournisseur d'état de service n'a été fourni à ce scan : « {serviceName} » n'a "
        + "pas été interrogé.");
}
