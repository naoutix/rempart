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

public sealed class RecordingDriverProvider(
    IDriverProvider inner, MachineSnapshot snapshot) : IDriverProvider
{
    public IReadOnlyList<LoadedDriver> Enumerate() =>
        snapshot.Drivers ??= [.. inner.Enumerate()];
}

public sealed class SnapshotDriverProvider(MachineSnapshot snapshot) : IDriverProvider
{
    // Absent from an earlier capture: empty list, the fixture stays replayable and
    // simply produces fewer findings.
    public IReadOnlyList<LoadedDriver> Enumerate() => snapshot.Drivers ?? [];
}

public sealed class RecordingProcessProvider(
    IProcessProvider inner, MachineSnapshot snapshot) : IProcessProvider
{
    public IReadOnlyList<RunningProcess> Enumerate() =>
        snapshot.Processes ??= [.. inner.Enumerate()];
}

public sealed class SnapshotProcessProvider(MachineSnapshot snapshot) : IProcessProvider
{
    public IReadOnlyList<RunningProcess> Enumerate() => snapshot.Processes ?? [];
}

public sealed class RecordingListeningPortProvider(
    IListeningPortProvider inner, MachineSnapshot snapshot) : IListeningPortProvider
{
    public IReadOnlyList<ListeningPort> Enumerate() =>
        snapshot.ListeningPorts ??= [.. inner.Enumerate()];
}

public sealed class SnapshotListeningPortProvider(MachineSnapshot snapshot) : IListeningPortProvider
{
    // Absent from an earlier capture: empty list, the fixture stays replayable and
    // simply produces fewer findings.
    public IReadOnlyList<ListeningPort> Enumerate() => snapshot.ListeningPorts ?? [];
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
