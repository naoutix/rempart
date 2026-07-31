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

    public RegistryValueList ListValues(string keyPath)
    {
        var read = inner.ListValues(keyPath);

        // The list of names is recorded separately: without it, replay would not
        // know what to enumerate, and would find an empty location instead of the
        // content the machine had.
        snapshot.RegistryLists[keyPath] = [.. read.Values.Keys];

        // And the status beside it, in the same statement: a capture taken on a key the scan
        // was refused must replay as « je n'ai pas pu regarder », not as a key holding
        // nothing. The two were the same empty list until REV-11.
        snapshot.RegistryListsStatus[keyPath] = read.Status;

        foreach (var (name, value) in read.Values)
        {
            snapshot.Registry[SnapshotKeys.Value(keyPath, name)] = RegistryRead.Found(value);
        }

        return read;
    }

    public RegistrySubKeyList ListSubKeys(string keyPath)
    {
        var read = inner.ListSubKeys(keyPath);
        snapshot.SubKeyLists[keyPath] = [.. read.Names];
        snapshot.SubKeyListsStatus[keyPath] = read.Status;
        return read;
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

    public RegistryValueList ListValues(string keyPath)
    {
        var values = new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);

        // Location never enumerated at capture time: NotFound rather than a throw, and
        // deliberately not a refusal. A fixture predating this batch stays replayable and
        // just as silent as before — this is the degradation AutorunsCollector reads
        // ListValues for instead of ReadValue, which throws on that same capture. Claiming
        // « on m'a refusé » about a key nobody asked would put a finding on every old
        // fixture; the capture never said the key was absent either, and NotFound is the
        // reading that keeps the silence it had.
        if (!snapshot.RegistryLists.TryGetValue(keyPath, out var names))
        {
            return RegistryValueList.NotFound;
        }

        foreach (var name in names)
        {
            if (snapshot.Registry.TryGetValue(SnapshotKeys.Value(keyPath, name), out var read)
                && read.Value is { } value)
            {
                values[name] = value;
            }
        }

        return new RegistryValueList(Status(snapshot.RegistryListsStatus, keyPath), values);
    }

    public RegistrySubKeyList ListSubKeys(string keyPath) =>
        snapshot.SubKeyLists.TryGetValue(keyPath, out var names)
            ? new RegistrySubKeyList(Status(snapshot.SubKeyListsStatus, keyPath), names)
            : RegistrySubKeyList.NotFound;

    /// <summary>
    /// The status recorded beside a listing, or <c>Found</c> when the capture carries the
    /// listing and no status — a capture predating the field, read as the enumeration it was
    /// taken to be. The two-way version of what <see cref="StatusChannel.Replay"/> decides
    /// three ways; the third case cannot arise here, because a key absent from the listing
    /// map has already been answered above.
    /// </summary>
    private static ReadStatus Status(Dictionary<string, ReadStatus> statuses, string keyPath) =>
        statuses.TryGetValue(keyPath, out var recorded) ? recorded : ReadStatus.Found;
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
    // Absent from an old capture: still "not verifiable", and now with the reason. A fixture
    // predating this batch stays replayable and simply yields fewer verdicts — but the
    // verdicts it loses used to read « accès refusé », which said the machine had locked the
    // scan out when what happened is that the capture never held the block (#160).
    public PolicyFacts Read() => snapshot.Policy ?? PolicyFacts.Unread(
        "La capture rejouée ne porte aucun bloc de politique de sécurité.");
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

// The fifth read to carry the status channel, and the only one keyed by an argument: the
// three snapshot fields are three maps instead of three properties, but the reading of them
// is the same three-way decision StatusChannel holds — which is exactly why it is reused
// here rather than copied a fifth time (DET-FICHIERS-MUET, DET-RECPROV).
public sealed class RecordingFileSystemProvider(
    IFileSystemProvider inner, MachineSnapshot snapshot) : IFileSystemProvider
{
    public DirectoryRead ListFiles(string directory) => StatusChannel.Record(
        snapshot.DirectoriesStatus.TryGetValue(directory, out var status) ? status : null,
        snapshot.Directories.TryGetValue(directory, out var files) ? files : null,
        snapshot.DirectoriesDiagnostic.TryGetValue(directory, out var diagnostic)
            ? diagnostic
            : null,
        () => inner.ListFiles(directory),
        // The status is recorded alongside the listing: a capture taken on a folder the scan
        // was refused must replay as « je n'ai pas pu regarder », not as a folder with
        // nothing in it.
        read =>
        {
            snapshot.Directories[directory] = [.. read.Files];
            snapshot.DirectoriesStatus[directory] = read.Status;

            if (read.Diagnostic is { } reason)
            {
                snapshot.DirectoriesDiagnostic[directory] = reason;
            }
        });
}

public sealed class SnapshotFileSystemProvider(MachineSnapshot snapshot) : IFileSystemProvider
{
    public DirectoryRead ListFiles(string directory) => StatusChannel.Replay(
        snapshot.DirectoriesStatus.TryGetValue(directory, out var status) ? status : null,
        snapshot.Directories.TryGetValue(directory, out var files) ? files : null,
        snapshot.DirectoriesDiagnostic.TryGetValue(directory, out var diagnostic)
            ? diagnostic
            : null,
        // Never an empty list. A directory the capture holds nothing about is a directory
        // this capture never walked — the key it recorded and the key being asked for differ
        // — and answering [] would let the collector report « aucun autorun » over it. Not
        // NotFound either: that would claim the folder was absent from the machine, which
        // the capture never said.
        //
        // Nor AccessDenied, which is what this call produced until #173 and which asked the
        // reader of a replay to re-run elevated against a file that had already been written.
        // A capture that never held the path is the machine's own state as far as the caller
        // is concerned: « audit partiel », the answer AuditGap.Unreadable already names for
        // « a capture replayed for a surface it never recorded ».
        () => DirectoryRead.Failed(
            $"Dossier « {directory} » absent de l'instantané : cette capture n'a rien "
            + "enregistré à ce chemin, son contenu n'est donc pas rejouable."));
}

public sealed class RecordingScheduledTaskProvider(
    IScheduledTaskProvider inner, MachineSnapshot snapshot) : IScheduledTaskProvider
{
    public ScheduledTaskRead Enumerate() => snapshot.ScheduledTasks ??= inner.Enumerate();
}

// The four status-carrying reads below — five with the directory pair above — share their
// whole capture path: the three-way reading of a snapshot, and the "already recorded means
// already read" of the recording side. Both live in StatusChannel, written once. What stays
// here, one pair at a time, is what genuinely differs: the three snapshot fields the read is
// stored in (they cannot be named generically — they are separate properties because the
// JSON shape says so), and the sentence naming the surface a capture holds nothing about.
//
// That last one used to be a judgement about emptiness as well — zero driver cannot be true of
// a running machine, zero browser extension is ordinary — and the judgement was applied to the
// wrong branch (#192). It decides what an empty read that happened means, which is a question
// the recorded status and the recorded list already answer above; a capture holding no block at
// all read nothing, and the eight reads say so alike. What a generalisation here must still not
// flatten is the sentence: a reader of a replay is told which surface the capture never held.

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
    public DnsRead Read() => StatusChannel.Record(
        snapshot.DnsStatus, snapshot.Dns, snapshot.DnsDiagnostic,
        inner.Read,
        // The status is recorded alongside the list: a capture taken on a machine that refused
        // one of the two Parameters\Interfaces keys must replay as « je n'ai pas pu regarder »,
        // not as a machine that resolves through nothing — which is what a refusal laid there
        // is for. The interfaces carry the stack each was read on, so the capture says which
        // half of the machine it saw.
        read =>
        {
            snapshot.Dns = [.. read.Interfaces];
            snapshot.DnsStatus = read.Status;
            snapshot.DnsDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotDnsProvider(MachineSnapshot snapshot) : IDnsProvider
{
    public DnsRead Read() => StatusChannel.Replay(
        snapshot.DnsStatus, snapshot.Dns, snapshot.DnsDiagnostic,
        // Absent from a capture: a read that did not happen, since #192. It was an empty and
        // successful read, on the argument that zero is a state this surface may answer — which
        // is true of an enumeration that ran and found no configured interface, and is the
        // answer that surface still gets. It was never true of a capture holding no dns block:
        // nothing was enumerated, so « zéro interface » was a claim the capture never made.
        //
        // That judgement was left open in writing on this very line — « whether jamais capturé
        // should itself speak on this surface is a separate judgement » — and it is settled the
        // same way as the seven neighbours that already speak: the listening ports two classes
        // up answer Failed on exactly this branch, and three of the four versioned fixtures hit
        // it. It costs those captures a line saying what they cannot answer, and no verdict:
        // AuditGap.Unreadable is exit 5, « non déterminé », never a Fail against the machine.
        static () => DnsRead.Failed(
            "Cette capture ne contient aucun bloc DNS : les interfaces de la machine n'ont pas "
            + "été énumérées au moment où elle a été prise."));
}

public sealed class RecordingHostsFileProvider(
    IHostsFileProvider inner, MachineSnapshot snapshot) : IHostsFileProvider
{
    public HostsFileRead ReadLines() => StatusChannel.Record(
        snapshot.HostsFileStatus, snapshot.HostsFile, snapshot.HostsFileDiagnostic,
        inner.ReadLines,
        // The status is recorded alongside the lines: a capture taken on a hosts file the
        // scan was refused must replay as « je n'ai pas pu lire », not as a machine whose
        // resolution nothing overrides — which is what a refusal is laid there to look like.
        read =>
        {
            snapshot.HostsFile = [.. read.Lines];
            snapshot.HostsFileStatus = read.Status;
            snapshot.HostsFileDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotHostsFileProvider(MachineSnapshot snapshot) : IHostsFileProvider
{
    public HostsFileRead ReadLines() => StatusChannel.Replay(
        snapshot.HostsFileStatus, snapshot.HostsFile, snapshot.HostsFileDiagnostic,
        // Absent from a capture: a read that did not happen, since #192. « A hosts file with no
        // entry is a plausible state — the default one, in fact » is the argument this line
        // carried, and it holds for a file that was read: that is still Found on an empty list.
        // A capture with no hostsFile block is not that file. All four versioned fixtures land
        // here, and what they gain is the sentence below rather than a verdict.
        static () => HostsFileRead.Failed(
            "Cette capture ne contient aucun bloc hosts : le fichier n'a pas été lu au moment "
            + "où elle a été prise."));
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
    public SoftwareInventoryRead Read() => StatusChannel.Record(
        snapshot.SoftwareStatus, snapshot.Software, snapshot.SoftwareDiagnostic,
        inner.Read,
        // The status is recorded alongside the list: a capture taken while an uninstall key
        // was refused must replay as a partial inventory, not as a machine with nothing
        // installed under it.
        read =>
        {
            snapshot.Software = [.. read.Software];
            snapshot.SoftwareStatus = read.Status;
            snapshot.SoftwareDiagnostic = read.Diagnostic;
        });
}

public sealed class SnapshotSoftwareInventoryProvider(MachineSnapshot snapshot)
    : ISoftwareInventoryProvider
{
    public SoftwareInventoryRead Read() => StatusChannel.Replay(
        snapshot.SoftwareStatus, snapshot.Software, snapshot.SoftwareDiagnostic,
        // Absent from a capture: a read that did not happen, for the reason its DNS neighbour
        // gives — the reason having changed with it (#192). An empty inventory accuses no
        // machine, which is why an inventory that ran and found nothing stays silent; a capture
        // holding no software block replayed as a machine with nothing installed, which is a
        // claim rather than a silence.
        static () => SoftwareInventoryRead.Failed(
            "Cette capture ne contient aucun bloc logiciel : aucune des quatre sources n'a été "
            + "lue au moment où elle a été prise."));
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
        // Absent from a capture: a read that did not happen, since #192. « No extension is a
        // plausible state » is the argument this line carried and it is the reason a walk that
        // found none is still Found on an empty list — the line the shared shape must not
        // standardise away, and it is not standardised away. What was folded into it is the
        // capture that walked no profile at all, which is the state the channel here exists to
        // name: the profile nobody opened is where a sideloaded extension sits.
        static () => BrowserExtensionRead.Failed(
            "Cette capture ne contient aucun bloc d'extensions : aucun profil de navigateur "
            + "n'a été parcouru au moment où elle a été prise."));
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
    // Absent from an earlier capture: a failed read, never an absence of tasks. A fixture
    // predating this batch stays replayable, it simply produces a "not enumerated" finding
    // instead of the inventory.
    //
    // « Treated as a denial » is what this line said, and did, until #177 — the factory it
    // calls carried AccessDenied and the collector turned that into « relancer en
    // administrateur ». Re-running a replay elevated repairs nothing; the answer is to
    // re-capture, which is what AuditGap.Unreadable names and what the status now says.
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
    // Absent from an earlier capture: a query that was never asked, never a denial. A fixture
    // predating this batch stays replayable, it simply yields fewer verdicts.
    //
    // « Treated as a denial » is what this line said, and did, until #177's second round — the
    // twin of the scheduler's, ten lines above, and left standing when that one was corrected.
    // WmiRead.AccessDenied carries no reason, Finding.WmiGap reads exactly that as the refusal,
    // and the two WMI-backed collectors printed « Relancer en administrateur » over a capture
    // already written, exit 3. Re-running a replay elevated repairs nothing; the answer is to
    // re-capture, which is what AuditGap.Unreadable names and what this status now says.
    //
    // Latent rather than academic: the key embeds the property list, so the next property added
    // to a query moves every capture ever taken — the fixtures here and the real ones outside
    // the repository that StatusChannel promises to keep replayable — onto this line at once.
    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties) =>
        snapshot.Wmi.TryGetValue(
            RecordingWmiProvider.Key(namespacePath, className, properties), out var read)
            ? read
            : WmiRead.Failed(
                $"Requête WMI absente de l'instantané : {className} sous {namespacePath}.");
}

public sealed class SnapshotSystemInfoProvider(MachineSnapshot snapshot) : ISystemInfoProvider
{
    public SystemInfo Read() =>
        snapshot.SystemInfo
        ?? throw new SnapshotIncompleteException("Aucune information système dans l'instantané.");
}
