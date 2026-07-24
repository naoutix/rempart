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

    /// <summary>Names of the subkeys of an enumerated key. Distinct from
    /// <see cref="RegistryLists"/>, which carries value names.</summary>
    public Dictionary<string, List<string>> SubKeyLists { get; set; } = [];

    /// <summary>Verified signatures, indexed by file path.</summary>
    public Dictionary<string, FileSignature> Signatures { get; set; } = [];

    /// <summary>Contents of the enumerated directories.</summary>
    public Dictionary<string, List<string>> Directories { get; set; } = [];

    /// <summary>
    /// Scheduled tasks, or null if the snapshot predates their collection. The null
    /// matters: it distinguishes "not yet captured" from "empty scheduler".
    /// </summary>
    public ScheduledTaskRead? ScheduledTasks { get; set; }

    /// <summary>Loaded kernel drivers, or null if the snapshot predates their collection.</summary>
    public List<LoadedDriver>? Drivers { get; set; }

    /// <summary>Running processes, or null if the snapshot predates their collection.</summary>
    public List<RunningProcess>? Processes { get; set; }

    /// <summary>Network listening endpoints, or null if the snapshot predates their collection.</summary>
    public List<ListeningPort>? ListeningPorts { get; set; }

    /// <summary>Firewall state, or null if the snapshot predates its collection.</summary>
    public FirewallState? Firewall { get; set; }

    /// <summary>Per-interface DNS configuration, or null if the snapshot predates it.</summary>
    public List<DnsInterface>? Dns { get; set; }

    /// <summary>Lines of the hosts file, or null if the snapshot predates its collection.</summary>
    public List<string>? HostsFile { get; set; }

    /// <summary>Decoded proxy configuration, or null if the snapshot predates its collection.</summary>
    public ProxyConfiguration? Proxy { get; set; }

    /// <summary>Saved Wi-Fi profiles, or null if the snapshot predates their collection.</summary>
    public List<WifiProfile>? Wifi { get; set; }

    /// <summary>Installed software, or null if the snapshot predates its collection.</summary>
    public List<InstalledSoftware>? Software { get; set; }

    /// <summary>Browser extensions, or null if the snapshot predates their collection.</summary>
    public List<BrowserExtension>? BrowserExtensions { get; set; }
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
