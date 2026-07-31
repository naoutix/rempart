using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Core.Software;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class AppxPackageNameTests
{
    [Fact]
    public void Parses_a_standard_full_name()
    {
        var (name, version) = AppxPackageName.Parse("AdobeNotificationClient_7.0.2.14_x64__enpm4xejd91yc");

        Assert.Equal("AdobeNotificationClient", name);
        Assert.Equal("7.0.2.14", version);
    }

    [Fact]
    public void Keeps_a_hyphenated_identity_name()
    {
        var (name, version) = AppxPackageName.Parse("AdvancedMicroDevicesInc-RSXCM_22.10.0.0_x64__v2es6h43hjn86");

        Assert.Equal("AdvancedMicroDevicesInc-RSXCM", name);
        Assert.Equal("22.10.0.0", version);
    }

    [Fact]
    public void An_atypical_name_without_underscores_is_kept_whole()
    {
        var (name, version) = AppxPackageName.Parse("SansSeparateur");

        Assert.Equal("SansSeparateur", name);
        Assert.Null(version);
    }

    [Fact]
    public void A_non_version_second_segment_yields_no_version()
    {
        var (name, version) = AppxPackageName.Parse("Nom_pasuneversion_x64");

        Assert.Equal("Nom", name);
        Assert.Null(version);
    }

    [Fact]
    public void Derives_the_package_family_name_from_a_full_name()
    {
        Assert.Equal(
            "AdobeNotificationClient_enpm4xejd91yc",
            AppxPackageName.FamilyName("AdobeNotificationClient_7.0.2.14_x64__enpm4xejd91yc"));
    }

    [Fact]
    public void A_name_without_separators_is_its_own_family_name()
    {
        Assert.Equal("SansSeparateur", AppxPackageName.FamilyName("SansSeparateur"));
    }

    // The cases below come from a real machine's Appx repository, not from the
    // documentation: the distinction they encode is the one the registry actually makes.

    [Fact]
    public void A_split_resource_entry_is_not_an_installed_package()
    {
        // Observed on the test machine: Microsoft.BingWeather leaves only this entry
        // behind, and Get-AppxPackage no longer lists the package at all.
        Assert.True(AppxPackageName.IsResourcePackage(
            "Microsoft.BingWeather_4.54.63040.0_neutral_split.scale-150_8wekyb3d8bbwe"));
    }

    [Fact]
    public void A_language_split_entry_is_not_an_installed_package_either()
    {
        Assert.True(AppxPackageName.IsResourcePackage(
            "Microsoft.WindowsStore_12.0.0.0_neutral_split.language-fr_8wekyb3d8bbwe"));
    }

    [Fact]
    public void A_main_package_with_an_empty_resource_segment_is_installed()
    {
        Assert.False(AppxPackageName.IsResourcePackage(
            "Microsoft.GamingApp_2607.1001.21.0_x64__8wekyb3d8bbwe"));
    }

    [Fact]
    public void A_neutral_resource_segment_is_a_real_package_not_a_split()
    {
        // The trap: 24 packages on the test machine carry "neutral" as their resource
        // segment — the Windows shell itself among them. Treating a non-empty resource
        // segment as a split would erase them from the inventory, which is worse than
        // the false positive this rule exists to remove.
        Assert.False(AppxPackageName.IsResourcePackage(
            "Microsoft.Windows.ShellExperienceHost_10.0.26100.8115_neutral_neutral_cw5n1h2txyewy"));
    }

    [Fact]
    public void An_atypical_name_is_not_taken_for_a_split_entry()
    {
        Assert.False(AppxPackageName.IsResourcePackage("SansSeparateur"));
    }

    // Cases below taken from the same real machine: three registered versions of one
    // package, and two architectures of another.

    [Fact]
    public void Only_the_highest_registered_version_of_a_package_is_kept()
    {
        string[] entries =
        [
            "Microsoft.ECApp_10.0.26100.8328_neutral__8wekyb3d8bbwe",
            "Microsoft.ECApp_10.0.26100.8737_neutral__8wekyb3d8bbwe",
            "Microsoft.ECApp_10.0.26100.8521_neutral__8wekyb3d8bbwe",
        ];

        Assert.Equal(
            ["Microsoft.ECApp_10.0.26100.8737_neutral__8wekyb3d8bbwe"],
            AppxPackageName.LatestPerIdentity(entries));
    }

    [Fact]
    public void Two_architectures_of_one_package_are_both_kept()
    {
        // They share a package family name, so collapsing on the family alone would
        // erase a genuinely installed package. Architecture is part of the identity.
        string[] entries =
        [
            "Microsoft.NET.Native.Framework.2.2_2.2.29512.0_x64__8wekyb3d8bbwe",
            "Microsoft.NET.Native.Framework.2.2_2.2.29512.0_x86__8wekyb3d8bbwe",
        ];

        Assert.Equal(2, AppxPackageName.LatestPerIdentity(entries).Count);
    }

    [Fact]
    public void Versions_are_compared_as_numbers_not_as_text()
    {
        // "10.0.26100.8737" sorts before "10.0.26100.900" as text, and after it as a
        // version. Ordinal comparison would keep the older build.
        string[] entries =
        [
            "Package_10.0.26100.900_x64__hash",
            "Package_10.0.26100.8737_x64__hash",
        ];

        Assert.Equal(
            ["Package_10.0.26100.8737_x64__hash"],
            AppxPackageName.LatestPerIdentity(entries));
    }

    [Fact]
    public void An_atypical_name_survives_deduplication()
    {
        // No version to compare and no identity to group on: dropping it would lose an
        // entry, which is the one outcome worse than reporting it twice.
        string[] entries = ["SansSeparateur", "SansSeparateur"];

        Assert.Single(AppxPackageName.LatestPerIdentity(entries));
    }
}

internal sealed class FakeSoftwareInventoryProvider(SoftwareInventoryRead read)
    : ISoftwareInventoryProvider
{
    public FakeSoftwareInventoryProvider(params InstalledSoftware[] software)
        : this(SoftwareInventoryRead.Found(software))
    {
    }

    public SoftwareInventoryRead Read() => read;
}

public class SoftwareInventoryCollectorTests
{
    private static Finding Collect(InstalledSoftware software) =>
        Assert.Single(new SoftwareInventoryCollector(BloatwareCatalog.Empty).Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider(software))));

    [Fact]
    public void No_software_yields_nothing() =>
        Assert.Empty(new SoftwareInventoryCollector(BloatwareCatalog.Empty).Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider())));

    [Fact]
    public void An_entry_is_a_benign_finding_carrying_its_source_and_version()
    {
        var finding = Collect(new InstalledSoftware(
            "7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall,
            Provisioned: false, SurvivesFeatureUpdate: true));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("software", finding.Kind);
        Assert.Equal("7-Zip", finding.Target);
        Assert.Equal("Uninstall", finding.Details["source"]);
        Assert.Equal("23.01", finding.Details["version"]);
        Assert.Equal("Igor Pavlov", finding.Details["éditeur"]);
        Assert.Equal("non", finding.Details["provisionné"]);
    }

    [Fact]
    public void A_provisioned_appx_package_is_marked_as_surviving_feature_updates()
    {
        var finding = Collect(new InstalledSoftware(
            "Microsoft.BingWeather", "4.0", null, SoftwareSource.Appx,
            Provisioned: true, SurvivesFeatureUpdate: true));

        Assert.Equal("oui", finding.Details["provisionné"]);
        Assert.Equal("oui", finding.Details["survives_feature_update"]);
        Assert.False(finding.Details.ContainsKey("éditeur"));   // no Appx publisher
    }

    private static Finding CollectWith(BloatwareCatalog catalog, InstalledSoftware software) =>
        Assert.Single(new SoftwareInventoryCollector(catalog).Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider(software))));

    private static BloatwareCatalog OneEntry(BloatwareEntry entry) =>
        BloatwareCatalog.Parse(RempartJson.SerialiseCompact(
            new BloatwareCatalogFile("2026-07-23T00:00:00Z", "test", [entry])));

    [Fact]
    public void An_unwanted_match_escalates_a_benign_finding_to_notable()
    {
        var finding = CollectWith(
            OneEntry(new BloatwareEntry("BLOAT-GAME", BloatwareMatch.Name, "candy crush",
                "game", BloatwareRisk.Unwanted, "Jeu préinstallé, désinstallable sans impact.")),
            new InstalledSoftware("Candy Crush Saga", null, null, SoftwareSource.Appx, true, true, "king.CandyCrush_x"));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("game", finding.Details["bloatware"]);
        Assert.Equal("BLOAT-GAME", finding.Details["catalogue"]);
        Assert.Contains("désinstallable", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void A_security_relevant_match_escalates_to_suspicious()
    {
        var finding = CollectWith(
            OneEntry(new BloatwareEntry("BLOAT-UPD", BloatwareMatch.Publisher, "acme",
                "security-relevant", BloatwareRisk.SecurityRelevant, "Updater OEM vulnérable connu.")),
            new InstalledSoftware("Acme Update", "1.0", "ACME Corp", SoftwareSource.Uninstall, false, true, "{acme}"));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    private static IReadOnlyList<Finding> Collect(SoftwareInventoryRead read) =>
        new SoftwareInventoryCollector(BloatwareCatalog.Empty).Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider(read)));

    /// <summary>
    /// A source the scan was refused. Four independent sources fill one list, so an ACL on the
    /// uninstall keys used to produce the same empty inventory as a machine with nothing
    /// installed — and the report said nothing at all (#184).
    ///
    /// <para>
    /// <see cref="AuditGap.Refused"/>: every registry source and the Chocolatey library are
    /// denied by an ACL, and an ACL is what elevating opens. Exit 3, which is the one thing the
    /// caller can act on.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_source_is_reported_rather_than_read_as_no_software()
    {
        var finding = Assert.Single(Collect(
            SoftwareInventoryRead.Refused([], [@"HKLM\SOFTWARE\…\Uninstall"])));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal(AuditGap.Refused, finding.Gap);
        Assert.Contains("Uninstall", string.Join(" ", finding.Reasons), StringComparison.Ordinal);

        // The mute half, the only way to reach the sentence the collector writes itself: a
        // read carrying a diagnostic has it printed verbatim.
        var mute = Assert.Single(Collect(new SoftwareInventoryRead(ReadStatus.AccessDenied, [], null)));

        Assert.Equal(AuditGap.Refused, mute.Gap);
        Assert.Contains("administrateur", string.Join(" ", mute.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The other cause, and the pair is what makes either half a claim: a source that failed
    /// without being denied — the Chocolatey library on a volume that went away. No privilege
    /// repairs it, so advising elevation here is the inversion CONTRIBUTING forbids.
    /// </summary>
    [Fact]
    public void A_source_that_failed_without_being_denied_is_reported_as_itself()
    {
        var finding = Assert.Single(Collect(
            SoftwareInventoryRead.SourcesFailed([], [@"C:\ProgramData\chocolatey\lib"])));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", finding.Reasons),
            StringComparison.OrdinalIgnoreCase);

        var mute = Assert.Single(Collect(new SoftwareInventoryRead(ReadStatus.Failed, [], null)));

        Assert.Equal(AuditGap.Unreadable, mute.Gap);
        Assert.NotEmpty(Assert.Single(mute.Reasons));
        Assert.DoesNotContain("administrateur", string.Join(" ", mute.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A partial read keeps what it read. Reporting the gap must not cost the entries the
    /// other three sources gave — including, on a bad day, the one the bloatware catalogue was
    /// about to escalate. Answering with the gap alone is the shape the ports collector and the
    /// two WMI-backed ones each had to be corrected out of.
    /// </summary>
    [Fact]
    public void A_partial_inventory_names_the_gap_without_dropping_what_it_saw()
    {
        var findings = Collect(SoftwareInventoryRead.Refused(
            [
                new InstalledSoftware("7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall,
                    Provisioned: false, SurvivesFeatureUpdate: true),
            ],
            [@"HKCU\SOFTWARE\…\Uninstall"]));

        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Gap == AuditGap.Refused);
        Assert.Contains(findings, f => f.Target == "7-Zip" && f.Gap is null);
    }

    /// <summary>
    /// The other half of the asymmetry: a read that answered with nothing says nothing. Zero
    /// installed program is not a plausible machine, but it accuses nobody and triggers no
    /// rule — so a finding here would cry wolf on every replay of a capture that never
    /// collected the surface, which is three of the four versioned ones.
    /// </summary>
    [Fact]
    public void An_empty_but_successful_inventory_stays_silent() =>
        Assert.Empty(Collect(SoftwareInventoryRead.Found([])));

    [Fact]
    public void An_unmatched_entry_stays_benign()
    {
        var finding = CollectWith(
            OneEntry(new BloatwareEntry("BLOAT-X", BloatwareMatch.Name, "zzz-absent",
                "game", BloatwareRisk.Unwanted, "impact")),
            new InstalledSoftware("7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall, false, true, "7-Zip"));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.False(finding.Details.ContainsKey("bloatware"));
    }
}

public class SoftwareSnapshotTests
{
    [Fact]
    public void Recording_then_replaying_round_trips_the_inventory()
    {
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-01-01T00:00:00.0000000Z" };
        var entry = new InstalledSoftware(
            "7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall, false, true, "7-Zip");

        new RecordingSoftwareInventoryProvider(new FakeSoftwareInventoryProvider(entry), snapshot).Read();

        var round = RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot));
        var replayed = new SnapshotSoftwareInventoryProvider(round).Read();

        Assert.Equal(entry, Assert.Single(replayed.Software));
    }

    /// <summary>
    /// A capture that never collected the inventory says so, since #192 — where it answered an
    /// empty, successful read.
    ///
    /// <para>
    /// « Zero installed program accuses nobody » was the argument, and it answers a question
    /// nobody asked: the objection to speaking here would be a false accusation, and a gap is
    /// not an accusation. What the old answer did assert is that this machine has nothing
    /// installed — a state no machine is in — over four sources the capture never opened.
    /// </para>
    ///
    /// <para>
    /// The status is asserted beside the emptiness, because the two are what #184 separated: a
    /// capture that recorded a <em>refusal</em> replays as one — the test next door — and this
    /// one must not be dragged along with it, which is why the denial is refused by name.
    /// </para>
    /// </summary>
    [Fact]
    public void A_snapshot_without_software_says_so_rather_than_reporting_nothing_installed()
    {
        var read = new SnapshotSoftwareInventoryProvider(new MachineSnapshot()).Read();

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Empty(read.Software);
        Assert.NotNull(read.Diagnostic);

        var finding = Assert.Single(
            new SoftwareInventoryCollector(BloatwareCatalog.Empty).Collect(new ProviderSet(
                new FakeRegistryProvider(), new FakeSystemInfoProvider(),
                softwareInventory: new FakeSoftwareInventoryProvider(read))));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", finding.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The four steps a field added to the snapshot has to survive, on the second of the two
    /// reads #184 gave a channel: recorded by the scan, serialised into the capture, replayed
    /// out of it, and — in <c>AnonymiserTests</c> — scrubbed.
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object, for the reason the
    /// firewall test in <c>SnapshotReplayTests</c> gives: the capture is a <em>file</em>, and a
    /// status the recorder sets but the source-generated serialiser drops would pass every
    /// in-memory assertion and still replay as a machine with nothing installed.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_inventory_is_recorded_serialised_and_replayed_as_a_refusal()
    {
        var kept = new InstalledSoftware(
            "7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall, false, true, "7-Zip");

        var snapshot = new MachineSnapshot();
        var source = new CountingSoftwareInventoryProvider(
            SoftwareInventoryRead.Refused([kept], [@"HKCU\SOFTWARE\…\Uninstall"]));
        var recording = new RecordingSoftwareInventoryProvider(source, snapshot);

        recording.Read();
        recording.Read();

        // A scan walks the collectors twice; asking the machine again on the second pass would
        // make the capture depend on which pass caught it in a better mood.
        Assert.Equal(1, source.Calls);

        var replayed = new SnapshotSoftwareInventoryProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).Read();

        Assert.Equal(ReadStatus.AccessDenied, replayed.Status);
        Assert.Contains("Uninstall", replayed.Diagnostic!, StringComparison.Ordinal);

        // The inventory the readable sources gave survives the refusal of the one that did
        // not: dropping it would trade one silence for another, on the surface the bloatware
        // catalogue is confronted with.
        Assert.Equal(kept, Assert.Single(replayed.Software));
    }

    /// <summary>
    /// The half no factory of this read can build, reached the way a capture reaches it — the
    /// same hole #177 found on the scheduler and #179 on the firewall.
    ///
    /// <para>
    /// A capture written before <c>softwareStatus</c> existed carries a list and nothing else,
    /// and the absence has to keep meaning what it meant: the inventory was read. Reading it as
    /// a refusal would put a NOTABLE on every capture older than this batch, the real-machine
    /// ones outside the repository included, and send their readers to elevate against a file
    /// already on disk.
    /// </para>
    ///
    /// <para>
    /// Asserted on the <em>value</em> the replay produces and never on the presence of the key:
    /// the serialiser writes every field it has, so a « the key is absent » premise goes green
    /// on any regeneration and proves nothing (#163).
    /// </para>
    /// </summary>
    [Fact]
    public void An_inventory_captured_before_the_status_replays_as_the_read_it_recorded()
    {
        const string BeforeTheField = """
            {"software":[{"name":"7-Zip","version":"23.01","publisher":"Igor Pavlov",
              "source":"Uninstall","provisioned":false,"survivesFeatureUpdate":true,
              "identifier":"7-Zip"}]}
            """;

        var read = new SnapshotSoftwareInventoryProvider(
            RempartJson.DeserialiseSnapshot(BeforeTheField)).Read();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Equal("7-Zip", Assert.Single(read.Software).Name);
    }

    private sealed class CountingSoftwareInventoryProvider(SoftwareInventoryRead answer)
        : ISoftwareInventoryProvider
    {
        public int Calls { get; private set; }

        public SoftwareInventoryRead Read()
        {
            Calls++;
            return answer;
        }
    }
}
