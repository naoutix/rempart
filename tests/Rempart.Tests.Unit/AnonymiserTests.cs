using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// Fixtures end up under version control. A raw snapshot carries the hostname, serial
/// number and registered owner: that is machine identification, not test data.
/// </summary>
public sealed class AnonymiserTests
{
    /// <summary>
    /// The account name's newest way out of a capture, opened by DET-FICHIERS-MUET.
    ///
    /// <para>
    /// A refused directory now records a sentence beside its listing, and that sentence
    /// <em>quotes the directory</em> so the report can say which folder went unseen. The
    /// startup folder of a user is <c>C:\Users\&lt;compte&gt;\AppData\…</c>, so the
    /// diagnostic carries the account name into a field the anonymiser had never had to
    /// look at. Scrubbing the keys of the three maps and forgetting their values would leave
    /// the name in a capture that calls itself anonymised — and the map keys would still
    /// look perfectly clean.
    /// </para>
    /// </summary>
    [Fact]
    public void The_reason_a_directory_could_not_be_read_is_scrubbed_like_the_directory()
    {
        const string Startup =
            @"C:\Users\leoar\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Directories = { [Startup] = [] },
            DirectoriesStatus = { [Startup] = ReadStatus.AccessDenied },
            DirectoriesDiagnostic =
            {
                [Startup] = $"Dossier « {Startup} » illisible : accès refusé.",
            },
        };

        var result = Anonymiser.Apply(snapshot);

        Assert.DoesNotContain("leoar", RempartJson.Serialise(result), StringComparison.Ordinal);

        // And the three maps still agree on the key, or the status stops describing the
        // listing it was written beside.
        var scrubbed = Assert.Single(result.Directories.Keys);
        Assert.Equal(ReadStatus.AccessDenied, result.DirectoriesStatus[scrubbed]);
        Assert.Contains(scrubbed, result.DirectoriesDiagnostic[scrubbed], StringComparison.Ordinal);
    }

    [Fact]
    public void Firewall_rule_application_paths_are_scrubbed()
    {
        // A firewall rule can target an application installed under a user profile: its
        // path then names someone, and a capture meant to travel would carry it. System
        // paths (%SystemRoot%) have nothing to hide and stay readable.
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Firewall = new FirewallState(
                [
                    new FirewallRule(true, "In", "Allow", 6, "5000", ["Public"],
                        @"C:\Users\leoar\AppData\Local\App\app.exe"),
                    new FirewallRule(true, "In", "Allow", 6, "445", ["Public"],
                        @"%SystemRoot%\system32\svchost.exe"),
                ],
                PublicFirewallEnabled: true, PublicDefaultInboundAllow: false),
        };

        var rules = Anonymiser.Apply(snapshot).Firewall!.Rules;

        Assert.DoesNotContain("leoar", rules[0].App, StringComparison.Ordinal);
        Assert.EndsWith(@"\App\app.exe", rules[0].App, StringComparison.Ordinal);
        Assert.Equal(@"%SystemRoot%\system32\svchost.exe", rules[1].App);
    }

    [Fact]
    public void Machine_name_is_replaced()
    {
        var snapshot = new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default };

        Anonymiser.Apply(snapshot);

        Assert.NotEqual("POSTE-TEST", snapshot.SystemInfo!.MachineName);
        Assert.StartsWith("anon:", snapshot.SystemInfo.MachineName, StringComparison.Ordinal);
        Assert.True(snapshot.Anonymised);
    }

    [Theory]
    [InlineData("SystemSerialNumber")]
    [InlineData("RegisteredOwner")]
    [InlineData("ProductId")]
    public void Identifying_values_are_replaced(string valueName)
    {
        var snapshot = WithValue(valueName, "ABC123");

        Anonymiser.Apply(snapshot);

        Assert.StartsWith("anon:", Text(snapshot, valueName), StringComparison.Ordinal);
    }

    [Fact]
    public void Ordinary_values_are_left_alone()
    {
        var snapshot = WithValue("ProductName", "Windows 11 Pro");

        Anonymiser.Apply(snapshot);

        // Anonymising beyond what is necessary would drain the fixtures of their value.
        Assert.Equal("Windows 11 Pro", Text(snapshot, "ProductName"));
    }

    [Fact]
    public void Hashing_is_stable_so_captures_stay_comparable()
    {
        Assert.Equal(Anonymiser.Hash("POSTE-A"), Anonymiser.Hash("POSTE-A"));
        Assert.NotEqual(Anonymiser.Hash("POSTE-A"), Anonymiser.Hash("POSTE-B"));
    }

    [Fact]
    public void Hash_is_truncated_beyond_reversal()
    {
        Assert.Equal(17, Anonymiser.Hash("POSTE-A").Length);
    }

    [Fact]
    public void Hashing_an_already_hashed_value_returns_it_unchanged()
    {
        // "Anonymised" has to mean "stays anonymised". A synthetic fixture is built from
        // a capture that was anonymised and is anonymised again on the way out; without
        // this, every hostname and every browser profile came out a digest of a digest,
        // no longer comparable with the capture it was derived from.
        var once = Anonymiser.Hash("POSTE-A");

        Assert.Equal(once, Anonymiser.Hash(once));
    }

    [Theory]
    [InlineData("SystemProductName", "MS-7E80")]
    [InlineData("BaseBoardProduct", "PRO B850-S WIFI6E (MS-7E80)")]
    [InlineData("BIOSVersion", "2.A41")]
    [InlineData("BIOSReleaseDate", "03/17/2026")]
    [InlineData("BaseBoardManufacturer", "Micro-Star International Co., Ltd.")]
    public void Hardware_identity_is_replaced(string valueName, string text)
    {
        // A board model, a BIOS version and its release date narrow a machine down about
        // as far as a serial number does, and no rule reads them: identity without
        // posture, which is exactly what this pass is for (DET-FIXTURE-MATERIEL).
        var snapshot = WithValue(BiosKey, valueName, text);

        Anonymiser.Apply(snapshot);

        Assert.StartsWith("anon:", Text(snapshot, BiosKey, valueName), StringComparison.Ordinal);
    }

    [Fact]
    public void The_same_value_name_outside_the_bios_key_is_left_alone()
    {
        // The scope is the key, not the value name: "ProductName" under CurrentVersion is
        // "Windows 11 Pro", the string the whole OS-version derivation rests on.
        var snapshot = WithValue(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "Windows 11 Pro");

        Anonymiser.Apply(snapshot);

        Assert.Equal("Windows 11 Pro",
            Text(snapshot, @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName"));
    }

    [Theory]
    [InlineData(@"\StartDVR", "StartDVR")]
    [InlineData(@"\NVIDIA App SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", "NVIDIA App SelfUpdate")]
    [InlineData(@"\SoftLanding\anon:0123456789ab\SoftLandingDeferralTask-{31a32128}", "SoftLandingDeferralTask")]
    public void Third_party_task_labels_are_replaced(string path, string name)
    {
        // The path of a task nobody at Microsoft created is an inventory line: it names
        // the product that installed it, sometimes with an install GUID on top.
        var task = Single(Task(path, name));

        Assert.StartsWith("anon:", task.Path, StringComparison.Ordinal);
        Assert.StartsWith("anon:", task.Name, StringComparison.Ordinal);
    }

    [Fact]
    public void A_task_borrowing_the_microsoft_folder_stays_readable()
    {
        // The criterion is the folder, and this is why. A task planted under Microsoft's
        // folder is what an intrusion does — the compromised fixture plants exactly this
        // one — and hashing it would remove the only thing that makes it legible as an
        // impostor.
        var task = Single(Task(
            @"\Microsoft\Windows\Maintenance\SystemMaintenance", "SystemMaintenance"));

        Assert.Equal(@"\Microsoft\Windows\Maintenance\SystemMaintenance", task.Path);
        Assert.Equal("SystemMaintenance", task.Name);
    }

    [Fact]
    public void The_executable_a_third_party_task_launches_stays_readable()
    {
        // It is what the signature ladder judges and what the report names, and the
        // collector reads its shape to tell a resolved path from a bare name: a digest
        // carries no separator, and hashing it would invent a "chemin non résolu" finding
        // on every third-party task.
        var task = Single(Task(@"\StartDVR", "StartDVR",
            @"C:\Program Files\AMD\CNext\CNext\RSServCmd.exe"));

        Assert.Equal(@"C:\Program Files\AMD\CNext\CNext\RSServCmd.exe", task.Actions[0].Path);
    }

    private const string BiosKey = @"HKLM\HARDWARE\DESCRIPTION\System\BIOS";

    private static ScheduledTask Single(ScheduledTask task)
    {
        var snapshot = new MachineSnapshot { ScheduledTasks = ScheduledTaskRead.Found([task]) };

        return Assert.Single(Anonymiser.Apply(snapshot).ScheduledTasks!.Tasks);
    }

    private static ScheduledTask Task(string path, string name, string executable = "") =>
        new(path, name, Enabled: true, State: "ready", Author: null, UserId: null,
            RunLevel: null, Actions: [new TaskAction("exec", executable, "")]);

    private static MachineSnapshot WithValue(string valueName, string text) =>
        WithValue(@"HKLM\SOFTWARE\Test", valueName, text);

    private static MachineSnapshot WithValue(string keyPath, string valueName, string text) => new()
    {
        Registry =
        {
            [SnapshotKeys.Value(keyPath, valueName)] = RegistryRead.Found(RegistryValue.OfText(text)),
        },
    };

    /// <summary>
    /// Anonymised has to mean <em>stays</em> anonymised: <c>Apply</c> must be a fixed
    /// point, or re-running the tool over its own output corrupts it. That is not a
    /// hypothetical loop — <c>SyntheticSnapshot</c> now anonymises a capture that was
    /// already anonymised at capture time.
    ///
    /// <para>
    /// <c>Hash</c> guards itself, but <c>ScrubHostPort</c> cut the value up before calling
    /// it, so the guard never saw the whole string. When the twelve hex characters of a
    /// digest happen to be all digits — about one host in three hundred — the result reads
    /// as <c>host:port</c> and a second pass hashes the <c>anon</c> prefix. The host below
    /// is one of those: its digest is <c>anon:388883164900</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void Anonymising_an_already_anonymised_snapshot_changes_nothing()
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Proxy = new ProxyConfiguration(
                new ProxyScope(true, "proxy92.corp.example", null, []),
                ProxyScope.Disabled,
                false),
        };

        // Snapshotted as text between the two passes, deliberately: Apply mutates its
        // argument and hands the same instance back, so comparing the two return values
        // would compare an object with itself and hold no matter what the second pass did.
        var once = RempartJson.Serialise(Anonymiser.Apply(snapshot));
        var hostAfterOnce = snapshot.Proxy!.WinInet.Server;

        var twice = RempartJson.Serialise(Anonymiser.Apply(snapshot));

        Assert.Equal("anon:388883164900", hostAfterOnce);
        Assert.Equal(hostAfterOnce, snapshot.Proxy!.WinInet.Server);
        Assert.Equal(once, twice);
    }

    /// <summary>
    /// The exclusion list names the internal domains a machine talks to directly, and
    /// very often the proxy itself — the same host the server field is hashed to hide.
    /// It sat three JSON fields from that hash, in the clear, in a capture whose
    /// <c>anonymised</c> flag read true.
    /// </summary>
    [Fact]
    public void The_proxy_exclusion_list_is_scrubbed_like_the_server_it_names()
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Proxy = new ProxyConfiguration(
                new ProxyScope(true, "proxy92.corp.example", null,
                    ["*.corp.example", "10.*", "proxy92.corp.example", "<local>"]),
                ProxyScope.Disabled,
                false),
        };

        var bypass = Anonymiser.Apply(snapshot).Proxy!.WinInet.Bypass;

        Assert.DoesNotContain(bypass, entry => entry.Contains("corp.example"));

        // A local token designates no one and is kept, exactly as ScrubHostPort keeps it
        // for the server: replaying must still see the same routing decision.
        Assert.Contains("<local>", bypass);
    }

    /// <summary>
    /// The same defect the project already fixed for <c>DirectoriesDiagnostic</c>, left on
    /// its four siblings: a read that failed explains itself in free text, and free text
    /// quotes what it failed on.
    ///
    /// <para>
    /// What is promised here is the account name in a path, which is what <c>ScrubProfile</c>
    /// can find. An identifier a diagnostic embeds in some other shape cannot be scrubbed
    /// reliably after the fact — that has to be fixed where the sentence is written, and the
    /// Firefox profile salt was.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("drivers")]
    [InlineData("processes")]
    [InlineData("ports")]
    [InlineData("extensions")]
    public void A_diagnostic_that_quotes_a_user_path_is_scrubbed_like_the_listing(string surface)
    {
        const string quoted = @"lecture refusée : C:\Users\claire\AppData\Local\x";

        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            DriversDiagnostic = surface == "drivers" ? quoted : null,
            ProcessesDiagnostic = surface == "processes" ? quoted : null,
            ListeningPortsDiagnostic = surface == "ports" ? quoted : null,
            BrowserExtensionsDiagnostic = surface == "extensions" ? quoted : null,
        };

        var after = Anonymiser.Apply(snapshot);
        var diagnostic = surface switch
        {
            "drivers" => after.DriversDiagnostic,
            "processes" => after.ProcessesDiagnostic,
            "ports" => after.ListeningPortsDiagnostic,
            _ => after.BrowserExtensionsDiagnostic,
        };

        Assert.DoesNotContain("claire", diagnostic);
        // The sentence still says what happened: scrubbing must not cost the diagnosis.
        Assert.Contains("refusée", diagnostic);
    }

    /// <summary>
    /// The guard that would have caught both, and will catch the next one.
    ///
    /// <para>
    /// Anonymisation covers a hand-maintained list of fields, so any field added to
    /// <see cref="MachineSnapshot"/> is unprotected by default and no property-by-property
    /// assertion can notice. This sweeps the <em>serialised</em> snapshot instead: plant one
    /// distinctive identifier everywhere a machine-chosen string can sit, and require that
    /// it survives nowhere.
    /// </para>
    /// </summary>
    [Fact]
    public void No_field_carries_a_planted_identifier_through_anonymisation()
    {
        const string marker = "identifiant-a-masquer";

        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default with { MachineName = marker },
            Proxy = new ProxyConfiguration(
                new ProxyScope(true, $"{marker}.example:8080", $"http://{marker}.example/p.pac",
                    [$"*.{marker}.example"]),
                ProxyScope.Disabled,
                false),
            DriversDiagnostic = $@"WMI muet : C:\Users\{marker}\pilote.sys",
            ProcessesDiagnostic = $@"énumération refusée : C:\Users\{marker}\p.exe",
            ListeningPortsDiagnostic = $@"table sans réponse : C:\Users\{marker}\s.exe",
            BrowserExtensionsDiagnostic = $@"profil illisible : C:\Users\{marker}\prefs.js",
            DirectoriesDiagnostic = { [$@"C:\Users\{marker}"] = $@"refusé : C:\Users\{marker}" },

            // The fifth sibling, and the one that shows why the sweep is written this way:
            // it was an unreachable field when the four above were fixed, and became a live
            // one the day a COM failure started naming itself instead of claiming a denial.
            Wmi = { ["root/cimv2:Win32_Service"] = WmiRead.Failed($@"COM 0x80041013 : C:\Users\{marker}\svc.exe") },
        };

        var serialised = RempartJson.Serialise(Anonymiser.Apply(snapshot));

        Assert.DoesNotContain(marker, serialised);
    }

    private static string? Text(MachineSnapshot snapshot, string valueName) =>
        Text(snapshot, @"HKLM\SOFTWARE\Test", valueName);

    private static string? Text(MachineSnapshot snapshot, string keyPath, string valueName) =>
        snapshot.Registry[SnapshotKeys.Value(keyPath, valueName)].Value?.Text;
}
