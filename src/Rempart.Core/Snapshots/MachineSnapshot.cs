using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Raw state of a machine, replayable offline. Every audited machine becomes a
/// permanent test fixture — a pristine VM has no OEM bloatware, so real machines are
/// the only valid test bench.
/// </summary>
public sealed class MachineSnapshot
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public string CapturedAtUtc { get; set; } = string.Empty;

    /// <summary>
    /// True if hostname, serial numbers and owner have been replaced with digests.
    /// Versioned fixtures must be (see .gitignore).
    /// </summary>
    public bool Anonymised { get; set; }

    /// <summary>Key: <c>keyPath||valueName</c>. See <see cref="SnapshotKeys"/>.</summary>
    public Dictionary<string, RegistryRead> Registry { get; set; } = [];

    public SystemInfo? SystemInfo { get; set; }

    /// <summary>Key: service name.</summary>
    public Dictionary<string, ServiceRead> Services { get; set; } = [];

    /// <summary>Local policy facts, or null if they could not be read.</summary>
    public PolicyFacts? Policy { get; set; }

    /// <summary>Key: <c>namespace:Class||properties</c>.</summary>
    public Dictionary<string, WmiRead> Wmi { get; set; } = [];

    /// <summary>
    /// Names of the values present in an enumerated key. Distinct from
    /// <see cref="Registry"/>, which says nothing about what was never looked up.
    /// </summary>
    public Dictionary<string, List<string>> RegistryLists { get; set; } = [];

    /// <summary>
    /// Whether each of those keys could be enumerated, or absent from this map on a capture
    /// predating the field.
    ///
    /// <para>
    /// A map beside the listing rather than a read object in its place, for the reason
    /// <see cref="DirectoriesStatus"/> gives and this repository has now re-taken five times:
    /// turning a <c>registryLists</c> entry from a JSON array into an object would make every
    /// existing capture unreadable, the real-machine ones kept outside the repository
    /// included. A key carrying a list and no status replays as the enumeration it was taken
    /// to be — which is exactly what such a capture used to claim, and all it could claim.
    /// </para>
    ///
    /// <para>
    /// Keyed per key path because the read is: a refused <c>Run</c> key must not describe the
    /// four beside it that answered. No diagnostic map next to it — the key path <em>is</em>
    /// the diagnostic, and the provider calls nothing a denial but a denial.
    /// </para>
    /// </summary>
    public Dictionary<string, ReadStatus> RegistryListsStatus { get; set; } = [];

    /// <summary>Names of the subkeys of an enumerated key. Distinct from
    /// <see cref="RegistryLists"/>, which carries value names.</summary>
    public Dictionary<string, List<string>> SubKeyLists { get; set; } = [];

    /// <summary>Whether each of those keys could be enumerated. Same reasoning as
    /// <see cref="RegistryListsStatus"/>, and a separate map because the two enumerations are
    /// asked separately: a key can answer one and refuse the other.</summary>
    public Dictionary<string, ReadStatus> SubKeyListsStatus { get; set; } = [];

    /// <summary>Verified signatures, indexed by file path.</summary>
    public Dictionary<string, FileSignature> Signatures { get; set; } = [];

    /// <summary>Contents of the enumerated directories.</summary>
    public Dictionary<string, List<string>> Directories { get; set; } = [];

    /// <summary>
    /// Whether each of those directories could be listed, or absent from this map on a
    /// capture predating the field.
    ///
    /// <para>
    /// Three parallel maps on the same key rather than a map of read objects, for the reason
    /// <see cref="DriversStatus"/> gives and this repository has now re-taken four times:
    /// turning a <c>directories</c> entry from a JSON array into an object would make every
    /// existing capture unreadable, the real-machine ones kept outside the repository
    /// included. A directory carrying a list and no status replays as the success it was
    /// taken to be.
    /// </para>
    ///
    /// <para>
    /// Keyed per directory because the read is: <c>ListFiles</c> takes one, so the machine
    /// startup folder can be refused while the user one answers, and a single status for the
    /// whole map would have to lie about one of them.
    /// </para>
    /// </summary>
    public Dictionary<string, ReadStatus> DirectoriesStatus { get; set; } = [];

    /// <summary>Why a directory could not be listed, for those that could not.</summary>
    public Dictionary<string, string> DirectoriesDiagnostic { get; set; } = [];

    /// <summary>
    /// Scheduled tasks, or null if the snapshot predates their collection. The null
    /// matters: it distinguishes "not yet captured" from "empty scheduler".
    /// </summary>
    public ScheduledTaskRead? ScheduledTasks { get; set; }

    /// <summary>Loaded kernel drivers, or null if the snapshot predates their collection.</summary>
    public List<LoadedDriver>? Drivers { get; set; }

    /// <summary>
    /// Whether the driver enumeration succeeded, or null on a capture predating this
    /// field.
    ///
    /// <para>
    /// Added beside the list rather than replacing it with a read record, deliberately:
    /// changing <see cref="Drivers"/> from a JSON array to an object would make every
    /// existing capture unreadable, including the real-machine ones kept outside the
    /// repository. A capture that carries a list and no status is replayed as a success —
    /// the best available reading of what it recorded, and no worse than before.
    /// </para>
    /// </summary>
    public ReadStatus? DriversStatus { get; set; }

    /// <summary>Why the driver enumeration failed, when it did.</summary>
    public string? DriversDiagnostic { get; set; }

    /// <summary>Running processes, or null if the snapshot predates their collection.</summary>
    public List<RunningProcess>? Processes { get; set; }

    /// <summary>Whether the process enumeration succeeded. Same reasoning as
    /// <see cref="DriversStatus"/>.</summary>
    public ReadStatus? ProcessesStatus { get; set; }

    /// <summary>Why the process enumeration failed, when it did.</summary>
    public string? ProcessesDiagnostic { get; set; }

    /// <summary>Network listening endpoints, or null if the snapshot predates their collection.</summary>
    public List<ListeningPort>? ListeningPorts { get; set; }

    /// <summary>Whether the listening tables could be read. Same reasoning as
    /// <see cref="DriversStatus"/>, and the same shape for the same reason: an object in
    /// place of the <c>listeningPorts</c> array would make every existing capture
    /// unreadable, including the real ones kept outside the repository.</summary>
    public ReadStatus? ListeningPortsStatus { get; set; }

    /// <summary>Which listening table could not be read, when one could not.</summary>
    public string? ListeningPortsDiagnostic { get; set; }

    /// <summary>
    /// The dynamic port range the machine declared, or null on a capture that never asked —
    /// which is every capture taken before DET-PLAGE-DYNAMIQUE was closed.
    ///
    /// <para>
    /// The null is the useful part, and it is why the range is stored as its own field
    /// rather than folded into <see cref="ListeningPorts"/>: replaying it has to be able to
    /// say « cette capture n'a pas relevé la plage », so that the finding falls back to the
    /// Windows default <em>and admits it</em>. A capture that recorded nothing would
    /// otherwise be replayed as one that measured the default, which is the assertion the
    /// debt was about.
    /// </para>
    /// </summary>
    public DynamicPortRangeRead? DynamicPortRange { get; set; }

    /// <summary>Firewall state, or null if the snapshot predates its collection.</summary>
    public FirewallState? Firewall { get; set; }

    /// <summary>Per-interface DNS configuration, or null if the snapshot predates it.</summary>
    public List<DnsInterface>? Dns { get; set; }

    /// <summary>
    /// Whether the DNS interfaces could be enumerated, or null on a capture predating this
    /// field. Same reasoning and same shape as <see cref="DriversStatus"/>: an object in place
    /// of the <c>dns</c> array would make every existing capture unreadable, the real-machine
    /// ones kept outside the repository included.
    ///
    /// <para>
    /// The status is stored and the <em>state it implies</em> is not, which is the trap #182
    /// named: a capture carrying a status it never wrote would replay as a file contradicting
    /// itself. A capture holding a list and no status replays as the enumeration it was taken
    /// to be, and one holding neither replays as the silence it always produced — this surface
    /// is allowed to be silent about zero.
    /// </para>
    /// </summary>
    public ReadStatus? DnsStatus { get; set; }

    /// <summary>Which key refused, when one did.</summary>
    public string? DnsDiagnostic { get; set; }

    /// <summary>Lines of the hosts file, or null if the snapshot predates its collection.</summary>
    public List<string>? HostsFile { get; set; }

    /// <summary>Whether the hosts file could be read. Added beside the lines for the same
    /// compatibility reason as <see cref="DriversStatus"/>: a capture carrying lines and no
    /// status replays as the read it was taken to be.</summary>
    public ReadStatus? HostsFileStatus { get; set; }

    /// <summary>Why the hosts file could not be read, when it could not.</summary>
    public string? HostsFileDiagnostic { get; set; }

    /// <summary>Decoded proxy configuration, or null if the snapshot predates its collection.</summary>
    public ProxyConfiguration? Proxy { get; set; }

    /// <summary>Saved Wi-Fi profiles, or null if the snapshot predates their collection.</summary>
    public List<WifiProfile>? Wifi { get; set; }

    /// <summary>Installed software, or null if the snapshot predates its collection.</summary>
    public List<InstalledSoftware>? Software { get; set; }

    /// <summary>Whether every inventory source could be read. Same reasoning as
    /// <see cref="DriversStatus"/>, and one status for the four sources because one list is
    /// what they fill: the diagnostic beside it names which of them was lost.</summary>
    public ReadStatus? SoftwareStatus { get; set; }

    /// <summary>Which inventory sources could not be read, when some could not.</summary>
    public string? SoftwareDiagnostic { get; set; }

    /// <summary>Browser extensions, or null if the snapshot predates their collection.</summary>
    public List<BrowserExtension>? BrowserExtensions { get; set; }

    /// <summary>Whether every browser profile could be read. Added beside the list for
    /// the same compatibility reason as <see cref="DriversStatus"/>.</summary>
    public ReadStatus? BrowserExtensionsStatus { get; set; }

    /// <summary>Which profiles could not be read, when some could not.</summary>
    public string? BrowserExtensionsDiagnostic { get; set; }

    /// <summary>
    /// Component store analysis, or null when it was not requested — it is opt-in
    /// (<c>--analyze-store</c>), because the servicing stack takes tens of seconds to
    /// answer and demands elevation.
    /// </summary>
    public ComponentStoreRead? ComponentStore { get; set; }
}

public static class SnapshotKeys
{
    private const string Separator = "||";

    /// <summary>Existence-check marker, distinct from any real named value.</summary>
    public const string ExistenceMarker = "#exists";

    public static string Value(string keyPath, string valueName) =>
        string.Concat(keyPath, Separator, valueName);

    public static string Existence(string keyPath) => Value(keyPath, ExistenceMarker);
}
