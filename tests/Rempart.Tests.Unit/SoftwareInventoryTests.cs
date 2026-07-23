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
}

internal sealed class FakeSoftwareInventoryProvider(params InstalledSoftware[] software)
    : ISoftwareInventoryProvider
{
    public IReadOnlyList<InstalledSoftware> Read() => software;
}

public class SoftwareInventoryCollectorTests
{
    private static Finding Collect(InstalledSoftware software) =>
        Assert.Single(new SoftwareInventoryCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider(software))));

    [Fact]
    public void No_software_yields_nothing() =>
        Assert.Empty(new SoftwareInventoryCollector().Collect(new ProviderSet(
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
        Assert.False(finding.Details.ContainsKey("éditeur"));   // pas d'éditeur Appx
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

        Assert.Equal(entry, Assert.Single(replayed));
    }

    [Fact]
    public void A_snapshot_without_software_replays_an_empty_inventory() =>
        Assert.Empty(new SnapshotSoftwareInventoryProvider(new MachineSnapshot()).Read());
}
