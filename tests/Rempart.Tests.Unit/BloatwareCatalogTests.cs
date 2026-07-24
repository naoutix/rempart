using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class BloatwareCatalogTests
{
    private static InstalledSoftware Appx(string pfn, string name = "X") =>
        new(name, null, null, SoftwareSource.Appx, false, false, pfn);

    private static InstalledSoftware Uninstall(string key, string name = "X", string? publisher = null) =>
        new(name, null, publisher, SoftwareSource.Uninstall, false, true, key);

    private static BloatwareCatalog Catalog(params BloatwareEntry[] entries) =>
        BloatwareCatalog.Parse(RempartJson.SerialiseCompact(
            new BloatwareCatalogFile("2026-07-23T00:00:00Z", "test", [.. entries])));

    private static BloatwareEntry Entry(
        string id, BloatwareMatch match, string value,
        BloatwareRisk risk = BloatwareRisk.Unwanted) =>
        new(id, match, value, "test-cat", risk, "Impact non vide.");

    [Fact]
    public void An_empty_catalog_matches_nothing() =>
        Assert.Null(BloatwareCatalog.Empty.Match(Appx("Anything_hash")));

    [Fact]
    public void A_pfn_entry_matches_an_appx_by_exact_identifier()
    {
        var hit = Catalog(Entry("B1", BloatwareMatch.Pfn, "king.CandyCrush_kgqvny"))
            .Match(Appx("king.CandyCrush_kgqvny"));

        Assert.Equal("B1", hit?.Id);
    }

    [Fact]
    public void A_pfn_entry_does_not_match_a_uninstall_entry_of_the_same_string()
    {
        // Source-gated: a PFN only matches an Appx.
        Assert.Null(Catalog(Entry("B1", BloatwareMatch.Pfn, "shared-id"))
            .Match(Uninstall("shared-id")));
    }

    [Fact]
    public void A_uninstall_entry_matches_by_exact_key()
    {
        Assert.Equal("B2", Catalog(Entry("B2", BloatwareMatch.Uninstall, "{GUID-123}"))
            .Match(Uninstall("{GUID-123}"))?.Id);
    }

    [Fact]
    public void A_name_entry_matches_a_case_insensitive_substring()
    {
        Assert.Equal("B3", Catalog(Entry("B3", BloatwareMatch.Name, "mcafee"))
            .Match(Uninstall("k", name: "McAfee LiveSafe"))?.Id);
    }

    [Fact]
    public void A_publisher_entry_matches_a_case_insensitive_substring()
    {
        Assert.Equal("B4", Catalog(Entry("B4", BloatwareMatch.Publisher, "acme oem"))
            .Match(Uninstall("k", name: "Whatever", publisher: "ACME OEM Inc."))?.Id);
    }

    [Fact]
    public void When_several_entries_match_the_highest_risk_wins()
    {
        var hit = Catalog(
            Entry("LOW", BloatwareMatch.Name, "vendor", BloatwareRisk.Unwanted),
            Entry("HIGH", BloatwareMatch.Publisher, "vendor", BloatwareRisk.SecurityRelevant))
            .Match(Uninstall("k", name: "Vendor Tool", publisher: "Vendor"));

        Assert.Equal("HIGH", hit?.Id);
        Assert.Equal(BloatwareRisk.SecurityRelevant, hit?.Risk);
    }

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_impact() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"B","match":"Name","value":"v","category":"c","risk":"Unwanted","impact":""}]}"""));

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_id() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"","match":"Name","value":"v","category":"c","risk":"Unwanted","impact":"i"}]}"""));

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_value() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"B","match":"Name","value":"","category":"c","risk":"Unwanted","impact":"i"}]}"""));

    [Fact]
    public void SerialiseCompact_writes_enums_as_strings_not_integers()
    {
        var json = RempartJson.SerialiseCompact(new BloatwareCatalogFile(
            "2026-07-23T00:00:00Z", "test",
            [new BloatwareEntry("B1", BloatwareMatch.Name, "v", "cat", BloatwareRisk.Unwanted, "impact")]));

        Assert.Contains("\"match\":\"Name\"", json);
        Assert.Contains("\"risk\":\"Unwanted\"", json);
    }

    [Fact]
    public void Parse_throws_when_the_entries_key_is_absent() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"drivers":[]}"""));

    [Fact]
    public void Parse_accepts_a_present_but_empty_entries_array()
    {
        var catalog = BloatwareCatalog.Parse("""{"asOfUtc":"x","source":null,"entries":[]}""");
        Assert.Equal(0, catalog.Count);
    }

    [Fact]
    public void An_unreadable_catalog_throws_rather_than_loading_partially() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse("pas du json"));

    [Fact]
    public void Merge_lets_an_incoming_entry_override_the_base_by_id()
    {
        var merged = BloatwareCatalog.Merge(
            Catalog(Entry("B1", BloatwareMatch.Name, "old")),
            Catalog(Entry("B1", BloatwareMatch.Name, "new"), Entry("B2", BloatwareMatch.Name, "extra")));

        Assert.Equal("B1", merged.Match(Uninstall("k", name: "new tool"))?.Id);   // overridden
        Assert.Null(merged.Match(Uninstall("k", name: "old tool")));               // old pattern gone
        Assert.Equal("B2", merged.Match(Uninstall("k", name: "extra tool"))?.Id);  // added
    }

    [Fact]
    public void The_embedded_baseline_parses_and_is_non_empty()
    {
        Assert.True(BloatwareCatalog.Embedded.Count > 0);
    }

    [Fact]
    public void The_embedded_baseline_matches_a_known_provisioned_appx()
    {
        // Xbox Game Bar: a provisioned Microsoft Appx, the textbook bloatware that returns.
        var hit = BloatwareCatalog.Embedded.Match(new InstalledSoftware(
            "Xbox Game Bar", null, null, SoftwareSource.Appx, true, true,
            "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe"));

        Assert.NotNull(hit);
        Assert.False(string.IsNullOrWhiteSpace(hit!.Impact));
    }
}
