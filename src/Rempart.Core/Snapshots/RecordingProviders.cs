using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Enveloppe un provider réel et consigne chaque lecture dans un instantané.
///
/// La capture est donc un sous-produit du scan, pas une liste de clés maintenue à la main :
/// une fixture ne peut pas être incomplète pour les collecteurs qui l'ont produite.
/// </summary>
public sealed class RecordingRegistryProvider(IRegistryProvider inner, MachineSnapshot snapshot)
    : IRegistryProvider
{
    public RegistryRead ReadValue(string keyPath, string valueName)
    {
        var read = inner.ReadValue(keyPath, valueName);
        // Les lectures infructueuses sont consignées aussi : sans elles, le rejeu
        // divergerait sur exactement les cas qu'on cherche à tester.
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

        // La liste des noms est enregistree a part : sans elle, le rejeu ne saurait
        // pas quoi enumerer, et decouvrirait un emplacement vide au lieu du contenu
        // qu'avait la machine.
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
/// Levée quand un rejeu demande une donnée absente de l'instantané. Un échec bruyant
/// est préférable à une valeur par défaut qui ferait passer un test pour la mauvaise raison.
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

        // Emplacement jamais enumere a la capture : rendre une liste vide plutot que
        // lever. Une fixture anterieure a ce lot reste rejouable, elle produit
        // simplement moins de constats.
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
    // Absent d'une capture ancienne : traité comme un refus, donc « non vérifiable ».
    // Une fixture d'avant ce lot reste rejouable, elle rend simplement moins de verdicts.
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
    // Absent d'une capture anterieure : liste vide, la fixture reste rejouable et
    // produit simplement moins de constats.
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
    // Absent d'une capture anterieure : liste vide, la fixture reste rejouable et
    // produit simplement moins de constats.
    public IReadOnlyList<ListeningPort> Enumerate() => snapshot.ListeningPorts ?? [];
}

public sealed class RecordingFirewallProvider(
    IFirewallProvider inner, MachineSnapshot snapshot) : IFirewallProvider
{
    public FirewallState Read() => snapshot.Firewall ??= inner.Read();
}

public sealed class SnapshotFirewallProvider(MachineSnapshot snapshot) : IFirewallProvider
{
    // Absent d'une capture anterieure : etat non lu, donc « inconnu ». La regle croisee
    // se retire alors sans rien affirmer, et le collecteur retombe sur le jugement de
    // signature seul.
    public FirewallState Read() => snapshot.Firewall ?? FirewallState.Unread;
}

public sealed class RecordingDnsProvider(IDnsProvider inner, MachineSnapshot snapshot) : IDnsProvider
{
    public IReadOnlyList<DnsInterface> Read() => snapshot.Dns ??= [.. inner.Read()];
}

public sealed class SnapshotDnsProvider(MachineSnapshot snapshot) : IDnsProvider
{
    // Absent d'une capture anterieure : liste vide, la fixture reste rejouable.
    public IReadOnlyList<DnsInterface> Read() => snapshot.Dns ?? [];
}

public sealed class RecordingHostsFileProvider(
    IHostsFileProvider inner, MachineSnapshot snapshot) : IHostsFileProvider
{
    public IReadOnlyList<string> ReadLines() => snapshot.HostsFile ??= [.. inner.ReadLines()];
}

public sealed class SnapshotHostsFileProvider(MachineSnapshot snapshot) : IHostsFileProvider
{
    // Absent d'une capture anterieure : aucune ligne, la fixture reste rejouable.
    public IReadOnlyList<string> ReadLines() => snapshot.HostsFile ?? [];
}

public sealed class RecordingProxyProvider(IProxyProvider inner, MachineSnapshot snapshot) : IProxyProvider
{
    public ProxyConfiguration Read() => snapshot.Proxy ??= inner.Read();
}

public sealed class SnapshotProxyProvider(MachineSnapshot snapshot) : IProxyProvider
{
    // Absent d'une capture antérieure : config vide, la fixture reste rejouable et
    // produit simplement aucun constat proxy.
    public ProxyConfiguration Read() => snapshot.Proxy ?? ProxyConfiguration.Empty;
}

public sealed class SnapshotScheduledTaskProvider(MachineSnapshot snapshot)
    : IScheduledTaskProvider
{
    // Absent d'une capture anterieure : traite comme un refus, jamais comme une
    // absence de taches. Une fixture d'avant ce lot reste rejouable, elle produit
    // simplement un constat « non enumere » au lieu de l'inventaire.
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
    // Absent d'une capture anterieure : traite comme un refus, donc « non verifiable ».
    // Une fixture d'avant ce lot reste rejouable, elle rend simplement moins de verdicts.
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
