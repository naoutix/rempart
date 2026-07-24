using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>Fake browser-extension provider, modelled on FakeWifiProfileProvider.</summary>
internal sealed class FakeBrowserExtensionProvider(params BrowserExtension[] extensions)
    : IBrowserExtensionProvider
{
    public IReadOnlyList<BrowserExtension> Read() => extensions;
}

public class BrowserExtensionCollectorTests
{
    private static BrowserExtension Extension(
        IReadOnlyList<string>? permissions = null,
        IReadOnlyList<string>? hosts = null,
        bool enabled = true,
        bool fromStore = true) =>
        new("Chrome", "Default", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Sample", "1.0",
            permissions ?? [], hosts ?? [], enabled, fromStore);

    private static Finding Collect(BrowserExtension extension) =>
        Assert.Single(new BrowserExtensionsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            browserExtensions: new FakeBrowserExtensionProvider(extension))));

    [Fact]
    public void No_extension_yields_nothing() =>
        Assert.Empty(new BrowserExtensionsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            browserExtensions: new FakeBrowserExtensionProvider())));

    [Fact]
    public void A_sideloaded_extension_is_suspicious_whatever_it_declares()
    {
        var finding = Collect(Extension(permissions: ["storage"], fromStore: false));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("magasin", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void A_disabled_sideloaded_extension_stays_suspicious_and_says_disabled()
    {
        var finding = Collect(Extension(fromStore: false, enabled: false));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Equal("désactivée", finding.Details["état"]);
    }

    [Fact]
    public void A_store_extension_with_broad_host_access_is_notable()
    {
        var finding = Collect(Extension(hosts: ["<all_urls>"]));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("toutes les pages", string.Join(" ", finding.Reasons));
    }

    [Theory]
    [InlineData("*://*/*")]
    [InlineData("https://*/*")]
    [InlineData("http://*/*")]
    public void Wildcard_host_patterns_count_as_broad_access(string pattern) =>
        Assert.Equal(FindingSeverity.Notable, Collect(Extension(hosts: [pattern])).Severity);

    [Fact]
    public void A_store_extension_with_a_strong_permission_is_notable()
    {
        var finding = Collect(Extension(
            permissions: ["nativeMessaging"], hosts: ["https://example.com/*"]));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("nativeMessaging", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void A_store_extension_with_narrow_permissions_is_benign_inventory()
    {
        var finding = Collect(Extension(
            permissions: ["storage"], hosts: ["https://example.com/*"]));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Empty(finding.Reasons);
    }

    [Fact]
    public void The_finding_carries_the_extension_identity_in_its_details()
    {
        var details = Collect(Extension(
            permissions: ["storage"], hosts: ["https://example.com/*"])).Details;

        Assert.Equal("Chrome", details["navigateur"]);
        Assert.Equal("Default", details["profil"]);
        Assert.Equal("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", details["id"]);
        Assert.Equal("1.0", details["version"]);
        Assert.Equal("storage", details["permissions"]);
        Assert.Equal("https://example.com/*", details["accès"]);
        Assert.Equal("activée", details["état"]);
        Assert.Equal("oui", details["magasin"]);
    }
}

public class BrowserExtensionSnapshotTests
{
    [Fact]
    public void Recording_then_replaying_round_trips_the_extensions()
    {
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-01-01T00:00:00.0000000Z" };
        var extension = new BrowserExtension(
            "Edge", "Profile 1", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Sample", "2.0",
            ["storage"], ["<all_urls>"], Enabled: true, FromStore: true);

        new RecordingBrowserExtensionProvider(
            new FakeBrowserExtensionProvider(extension), snapshot).Read();

        var round = RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot));
        var replayed = Assert.Single(new SnapshotBrowserExtensionProvider(round).Read());

        // Field-by-field: record equality compares the list properties by reference.
        Assert.Equal(extension.Browser, replayed.Browser);
        Assert.Equal(extension.Profile, replayed.Profile);
        Assert.Equal(extension.Id, replayed.Id);
        Assert.Equal(extension.Name, replayed.Name);
        Assert.Equal(extension.Version, replayed.Version);
        Assert.Equal(extension.Permissions, replayed.Permissions);
        Assert.Equal(extension.HostAccess, replayed.HostAccess);
        Assert.Equal(extension.Enabled, replayed.Enabled);
        Assert.Equal(extension.FromStore, replayed.FromStore);
    }

    [Fact]
    public void A_snapshot_without_extensions_replays_an_empty_list() =>
        Assert.Empty(new SnapshotBrowserExtensionProvider(new MachineSnapshot()).Read());
}

public class BrowserExtensionAnonymisationTests
{
    [Fact]
    public void The_profile_is_hashed_but_the_extension_stays_readable()
    {
        // The Firefox profile directory carries a random per-install salt: an
        // installation identifier, hence masked like the hostname. The extension
        // itself is what the audit is about — it stays.
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            BrowserExtensions = [new BrowserExtension(
                "Firefox", "a1b2c3d4.default-release", "uBlock0@raymondhill.net",
                "uBlock Origin", "1.60.0", [], ["<all_urls>"],
                Enabled: true, FromStore: true)],
        };

        var extension = Assert.Single(Anonymiser.Apply(snapshot).BrowserExtensions!);

        Assert.StartsWith("anon:", extension.Profile);
        Assert.DoesNotContain("a1b2c3d4", extension.Profile);
        Assert.Equal("uBlock Origin", extension.Name);
    }
}

public class BrowserExtensionEngineIntegrationTests
{
    [Fact]
    public void The_engine_surfaces_a_suspicious_sideloaded_extension()
    {
        var providers = new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            browserExtensions: new FakeBrowserExtensionProvider(
                new BrowserExtension(
                    "Chrome", "Default", "dddddddddddddddddddddddddddddddd", "Dropper",
                    "0.1", [], ["<all_urls>"], Enabled: true, FromStore: false)));

        var result = new ScanEngine(ScanEngine.DefaultCollectors, [])
            .Run(providers, "test", "2026-01-01T00:00:00.0000000Z", null,
                ScanEngine.DefaultFindingCollectors(DriverBlocklist.Empty, BloatwareCatalog.Empty));

        var finding = Assert.Single(result.Findings, f => f.Kind == "browser-extension");
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }
}
