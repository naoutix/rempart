using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Wraps a real provider and records every read into a snapshot.
///
/// Capture is thus a by-product of the scan, not a hand-maintained list of keys:
/// a fixture cannot be incomplete for the collectors that produced it.
/// </summary>
public sealed class RecordingRegistryProvider(IRegistryProvider inner, MachineSnapshot snapshot)
    : IRegistryProvider
{
    public RegistryRead ReadValue(string keyPath, string valueName)
    {
        var read = inner.ReadValue(keyPath, valueName);
        // Unsuccessful reads are recorded too: without them, replay would diverge
        // on exactly the cases we are trying to test.
        snapshot.Registry[SnapshotKeys.Value(keyPath, valueName)] = read;
        return read;
    }

    public ReadStatus KeyExists(string keyPath)
    {
        var status = inner.KeyExists(keyPath);
        snapshot.Registry[SnapshotKeys.Existence(keyPath)] = new RegistryRead(status, null);
        return status;
    }

    public IReadOnlyDictionary<string, RegistryValue> ListValues(string keyPath)
    {
        var values = inner.ListValues(keyPath);

        // The list of names is recorded separately: without it, replay would not
        // know what to enumerate, and would find an empty location instead of the
        // content the machine had.
        snapshot.RegistryLists[keyPath] = [.. values.Keys];

        foreach (var (name, value) in values)
        {
            snapshot.Registry[SnapshotKeys.Value(keyPath, name)] = RegistryRead.Found(value);
        }

        return values;
    }

    public IReadOnlyList<string> ListSubKeys(string keyPath)
    {
        var names = inner.ListSubKeys(keyPath);
        snapshot.SubKeyLists[keyPath] = [.. names];
        return names;
    }
}

public sealed class RecordingSystemInfoProvider(ISystemInfoProvider inner, MachineSnapshot snapshot)
    : ISystemInfoProvider
{
    public SystemInfo Read()
    {
        var info = inner.Read();
        snapshot.SystemInfo = info;
        return info;
    }
}

/// <summary>
/// Thrown when a replay asks for data absent from the snapshot. A loud failure is
/// preferable to a default value that would make a test pass for the wrong reason.
/// </summary>
public sealed class SnapshotIncompleteException(string message) : Exception(message);

public sealed class SnapshotRegistryProvider(MachineSnapshot snapshot) : IRegistryProvider
{
    public RegistryRead ReadValue(string keyPath, string valueName)
    {
        var key = SnapshotKeys.Value(keyPath, valueName);
        return snapshot.Registry.TryGetValue(key, out var read)
            ? read
            : throw new SnapshotIncompleteException(
                $"Lecture non enregistrée dans l'instantané : {key}. " +
                "La fixture a probablement été capturée avec un jeu de collecteurs différent.");
    }

    public ReadStatus KeyExists(string keyPath)
    {
        var key = SnapshotKeys.Existence(keyPath);
        return snapshot.Registry.TryGetValue(key, out var read)
            ? read.Status
            : throw new SnapshotIncompleteException($"Test d'existence non enregistré : {key}.");
    }

    public IReadOnlyDictionary<string, RegistryValue> ListValues(string keyPath)
    {
        var values = new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);

        // Location never enumerated at capture time: return an empty list rather
        // than throw. A fixture predating this batch stays replayable, it simply
        // produces fewer findings.
        if (!snapshot.RegistryLists.TryGetValue(keyPath, out var names))
        {
            return values;
        }

        foreach (var name in names)
        {
            if (snapshot.Registry.TryGetValue(SnapshotKeys.Value(keyPath, name), out var read)
                && read.Value is { } value)
            {
                values[name] = value;
            }
        }

        return values;
    }

    public IReadOnlyList<string> ListSubKeys(string keyPath) =>
        snapshot.SubKeyLists.TryGetValue(keyPath, out var names) ? names : [];
}

public sealed class RecordingServiceStateProvider(
    IServiceStateProvider inner, MachineSnapshot snapshot) : IServiceStateProvider
{
    public ServiceRead Read(string serviceName)
    {
        var read = inner.Read(serviceName);
        snapshot.Services[serviceName] = read;
        return read;
    }
}

public sealed class SnapshotServiceStateProvider(MachineSnapshot snapshot) : IServiceStateProvider
{
    public ServiceRead Read(string serviceName) =>
        snapshot.Services.TryGetValue(serviceName, out var read)
            ? read
            : throw new SnapshotIncompleteException(
                $"Service non enregistré dans l'instantané : {serviceName}. " +
                "La fixture a probablement été capturée avec un jeu de règles différent.");
}

public sealed class RecordingSecurityPolicyProvider(
    ISecurityPolicyProvider inner, MachineSnapshot snapshot) : ISecurityPolicyProvider
{
    public PolicyFacts Read() => snapshot.Policy ??= inner.Read();
}

public sealed class SnapshotSecurityPolicyProvider(MachineSnapshot snapshot) : ISecurityPolicyProvider
{
    // Absent from an old capture: treated as a denial, hence "not verifiable".
    // A fixture predating this batch stays replayable, it simply yields fewer verdicts.
    public PolicyFacts Read() => snapshot.Policy ?? PolicyFacts.AccessDenied;
}

public sealed class RecordingSignatureProvider(
    ISignatureProvider inner, MachineSnapshot snapshot) : ISignatureProvider
{
    public FileSignature Verify(string path)
    {
        var signature = inner.Verify(path);
        snapshot.Signatures[path] = signature;
        return signature;
    }
}

public sealed class SnapshotSignatureProvider(MachineSnapshot snapshot) : ISignatureProvider
{
    public FileSignature Verify(string path) =>
        snapshot.Signatures.TryGetValue(path, out var signature)
            ? signature
            : new FileSignature(SignatureStatus.Unknown);
}

public sealed class RecordingFileSystemProvider(
    IFileSystemProvider inner, MachineSnapshot snapshot) : IFileSystemProvider
{
    public IReadOnlyList<string> ListFiles(string directory)
    {
        var files = inner.ListFiles(directory);
        snapshot.Directories[directory] = [.. files];
        return files;
    }
}

public sealed class SnapshotFileSystemProvider(MachineSnapshot snapshot) : IFileSystemProvider
{
    public IReadOnlyList<string> ListFiles(string directory) =>
        snapshot.Directories.TryGetValue(directory, out var files) ? files : [];
}

public sealed class RecordingScheduledTaskProvider(
    IScheduledTaskProvider inner, MachineSnapshot snapshot) : IScheduledTaskProvider
{
    public ScheduledTaskRead Enumerate() => snapshot.ScheduledTasks ??= inner.Enumerate();
}

// The four status-carrying reads below share their whole capture path — the three-way
// reading of a snapshot, and the "already recorded means already read" of the recording
// side. Both live in StatusChannel, written once. What stays here, one pair at a time, is
// what genuinely differs: the three snapshot fields the read is stored in (they cannot be
// named generically — they are separate properties because the JSON shape says so), and the
// answer to "this capture never collected this surface", which is a judgement rather than a
// shape. Zero driver cannot be true of a running machine; zero browser extension is
// ordinary. Phase 2 settled that asymmetry and it is the one thing a generalisation here
// must not flatten.

public sealed class RecordingDriverProvider(
    IDriverProvider inner, MachineSnapshot snapshot) : IDriverProvider
{
    public DriverRead Enumerate() => StatusChannel.Record(
        snapshot.DriversStatus, snapshot.Drivers, snapshot.DriversDiagnostic,
        inner.Enumerate,
        // The status is recorded alongside the list: a capture taken while WMI was mute
        // must replay as "could not look", not as a machine without drivers.
        read =>
        {
            snapshot.Drivers = [.. read.Drivers];
            snapshot.DriversStatus = read.Status;
            snapshot.DriversDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotDriverProvider(MachineSnapshot snapshot) : IDriverProvider
{
    public DriverRead Enumerate() => StatusChannel.Replay(
        snapshot.DriversStatus, snapshot.Drivers, snapshot.DriversDiagnostic,
        // Never an empty list: a fixture predating driver collection produces a "not
        // enumerated" finding, exactly as the scheduled tasks already do.
        static () => DriverRead.Failed("Pilotes chargés absents de l'instantané."));
}

public sealed class RecordingProcessProvider(
    IProcessProvider inner, MachineSnapshot snapshot) : IProcessProvider
{
    public ProcessRead Enumerate() => StatusChannel.Record(
        snapshot.ProcessesStatus, snapshot.Processes, snapshot.ProcessesDiagnostic,
        inner.Enumerate,
        read =>
        {
            snapshot.Processes = [.. read.Processes];
            snapshot.ProcessesStatus = read.Status;
            snapshot.ProcessesDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotProcessProvider(MachineSnapshot snapshot) : IProcessProvider
{
    public ProcessRead Enumerate() => StatusChannel.Replay(
        snapshot.ProcessesStatus, snapshot.Processes, snapshot.ProcessesDiagnostic,
        static () => ProcessRead.Failed("Processus courants absents de l'instantané."));
}

public sealed class RecordingListeningPortProvider(
    IListeningPortProvider inner, MachineSnapshot snapshot) : IListeningPortProvider
{
    public ListeningPortRead Enumerate() => StatusChannel.Record(
        snapshot.ListeningPortsStatus, snapshot.ListeningPorts, snapshot.ListeningPortsDiagnostic,
        inner.Enumerate,
        read =>
        {
            snapshot.ListeningPorts = [.. read.Ports];
            snapshot.ListeningPortsStatus = read.Status;
            snapshot.ListeningPortsDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotListeningPortProvider(MachineSnapshot snapshot) : IListeningPortProvider
{
    public ListeningPortRead Enumerate() => StatusChannel.Replay(
        snapshot.ListeningPortsStatus, snapshot.ListeningPorts, snapshot.ListeningPortsDiagnostic,
        // Never an empty list: this used to answer [] and the collector concluded « aucun
        // port en écoute » over a capture that had simply never looked (DET-PORTS-MUET).
        static () => ListeningPortRead.Failed("Points d'écoute absents de l'instantané."));
}

public sealed class RecordingDynamicPortRangeProvider(
    IDynamicPortRangeProvider inner, MachineSnapshot snapshot) : IDynamicPortRangeProvider
{
    public DynamicPortRangeRead Read() => snapshot.DynamicPortRange ??= inner.Read();
}

public sealed class SnapshotDynamicPortRangeProvider(MachineSnapshot snapshot)
    : IDynamicPortRangeProvider
{
    // Absent from an earlier capture: the range was never asked for. Said as a failed read
    // rather than as the Windows default, so the finding falls back to that default while
    // naming it as an assumption — the whole of DET-PLAGE-DYNAMIQUE in one branch.
    public DynamicPortRangeRead Read() => snapshot.DynamicPortRange
        ?? DynamicPortRangeRead.Failed(
            "Cet instantané ne relève pas la plage de ports dynamique de la machine.");
}

public sealed class RecordingFirewallProvider(
    IFirewallProvider inner, MachineSnapshot snapshot) : IFirewallProvider
{
    public FirewallState Read() => snapshot.Firewall ??= inner.Read();
}

public sealed class SnapshotFirewallProvider(MachineSnapshot snapshot) : IFirewallProvider
{
    // Absent from an earlier capture: state unread, hence "unknown". The cross-check
    // rule then stands down without asserting anything, and the collector falls back
    // to the signature judgement alone.
    public FirewallState Read() => snapshot.Firewall ?? FirewallState.Unread;
}

public sealed class RecordingDnsProvider(IDnsProvider inner, MachineSnapshot snapshot) : IDnsProvider
{
    public IReadOnlyList<DnsInterface> Read() => snapshot.Dns ??= [.. inner.Read()];
}

public sealed class SnapshotDnsProvider(MachineSnapshot snapshot) : IDnsProvider
{
    // Absent from an earlier capture: empty list, the fixture stays replayable.
    public IReadOnlyList<DnsInterface> Read() => snapshot.Dns ?? [];
}

public sealed class RecordingHostsFileProvider(
    IHostsFileProvider inner, MachineSnapshot snapshot) : IHostsFileProvider
{
    public IReadOnlyList<string> ReadLines() => snapshot.HostsFile ??= [.. inner.ReadLines()];
}

public sealed class SnapshotHostsFileProvider(MachineSnapshot snapshot) : IHostsFileProvider
{
    // Absent from an earlier capture: no lines, the fixture stays replayable.
    public IReadOnlyList<string> ReadLines() => snapshot.HostsFile ?? [];
}

public sealed class RecordingProxyProvider(IProxyProvider inner, MachineSnapshot snapshot) : IProxyProvider
{
    public ProxyConfiguration Read() => snapshot.Proxy ??= inner.Read();
}

public sealed class SnapshotProxyProvider(MachineSnapshot snapshot) : IProxyProvider
{
    // Absent from an earlier capture: empty config, the fixture stays replayable and
    // simply produces no proxy findings.
    public ProxyConfiguration Read() => snapshot.Proxy ?? ProxyConfiguration.Empty;
}

public sealed class RecordingSoftwareInventoryProvider(
    ISoftwareInventoryProvider inner, MachineSnapshot snapshot) : ISoftwareInventoryProvider
{
    public IReadOnlyList<InstalledSoftware> Read() => snapshot.Software ??= [.. inner.Read()];
}

public sealed class SnapshotSoftwareInventoryProvider(MachineSnapshot snapshot) : ISoftwareInventoryProvider
{
    // Absent from an earlier capture: empty list, the fixture stays replayable.
    public IReadOnlyList<InstalledSoftware> Read() => snapshot.Software ?? [];
}

public sealed class RecordingWifiProfileProvider(
    IWifiProfileProvider inner, MachineSnapshot snapshot) : IWifiProfileProvider
{
    public IReadOnlyList<WifiProfile> Read() => snapshot.Wifi ??= [.. inner.Read()];
}

public sealed class SnapshotWifiProfileProvider(MachineSnapshot snapshot) : IWifiProfileProvider
{
    // Absent from an earlier capture: empty list, the fixture stays replayable.
    public IReadOnlyList<WifiProfile> Read() => snapshot.Wifi ?? [];
}

public sealed class RecordingBrowserExtensionProvider(
    IBrowserExtensionProvider inner, MachineSnapshot snapshot) : IBrowserExtensionProvider
{
    public BrowserExtensionRead Read() => StatusChannel.Record(
        snapshot.BrowserExtensionsStatus, snapshot.BrowserExtensions,
        snapshot.BrowserExtensionsDiagnostic,
        inner.Read,
        read =>
        {
            snapshot.BrowserExtensions = [.. read.Extensions];
            snapshot.BrowserExtensionsStatus = read.Status;
            snapshot.BrowserExtensionsDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotBrowserExtensionProvider(MachineSnapshot snapshot)
    : IBrowserExtensionProvider
{
    public BrowserExtensionRead Read() => StatusChannel.Replay(
        snapshot.BrowserExtensionsStatus, snapshot.BrowserExtensions,
        snapshot.BrowserExtensionsDiagnostic,
        // Absent from an earlier capture: an empty, successful read. Unlike drivers, no
        // extension is a plausible state, so a fixture predating this collection replays as
        // "nothing to report" rather than as a failure it never had. This is the line the
        // shared shape must not standardise away.
        static () => BrowserExtensionRead.Found([]));
}

public sealed class RecordingComponentStoreProvider(
    IComponentStoreProvider inner, MachineSnapshot snapshot) : IComponentStoreProvider
{
    public ComponentStoreRead Read() => snapshot.ComponentStore ??= inner.Read();
}

public sealed class SnapshotComponentStoreProvider(MachineSnapshot snapshot)
    : IComponentStoreProvider
{
    // Absent from a capture taken without --analyze-store: say the analysis was not
    // run. An empty reading would replay as a store of zero bytes, which is a claim
    // the capture never made.
    public ComponentStoreRead Read() => snapshot.ComponentStore
        ?? ComponentStoreRead.Failed(
            "Cet instantané ne contient pas d'analyse du magasin de composants : "
            + "capturé sans --analyze-store.");
}

public sealed class SnapshotScheduledTaskProvider(MachineSnapshot snapshot)
    : IScheduledTaskProvider
{
    // Absent from an earlier capture: treated as a denial, never as an absence of
    // tasks. A fixture predating this batch stays replayable, it simply produces a
    // "not enumerated" finding instead of the inventory.
    public ScheduledTaskRead Enumerate() =>
        snapshot.ScheduledTasks
        ?? ScheduledTaskRead.Failed("Tâches planifiées absentes de l'instantané.");
}

public sealed class RecordingWmiProvider(IWmiProvider inner, MachineSnapshot snapshot) : IWmiProvider
{
    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties)
    {
        var read = inner.Query(namespacePath, className, properties);
        snapshot.Wmi[Key(namespacePath, className, properties)] = read;
        return read;
    }

    internal static string Key(string ns, string className, IReadOnlyList<string> properties) =>
        $"{ns}:{className}||{string.Join(",", properties)}";
}

public sealed class SnapshotWmiProvider(MachineSnapshot snapshot) : IWmiProvider
{
    // Absent from an earlier capture: treated as a denial, hence "not verifiable".
    // A fixture predating this batch stays replayable, it simply yields fewer verdicts.
    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties) =>
        snapshot.Wmi.TryGetValue(
            RecordingWmiProvider.Key(namespacePath, className, properties), out var read)
            ? read
            : WmiRead.AccessDenied;
}

public sealed class SnapshotSystemInfoProvider(MachineSnapshot snapshot) : ISystemInfoProvider
{
    public SystemInfo Read() =>
        snapshot.SystemInfo
        ?? throw new SnapshotIncompleteException("Aucune information système dans l'instantané.");
}
