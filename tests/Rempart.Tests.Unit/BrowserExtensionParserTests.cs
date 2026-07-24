using Rempart.Core.Browsers;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class ChromiumManifestTests
{
    [Fact]
    public void A_mv3_manifest_separates_api_and_host_permissions()
    {
        const string Json = """
            {
              "manifest_version": 3,
              "name": "Sample",
              "version": "1.2.3",
              "permissions": ["storage", "nativeMessaging"],
              "host_permissions": ["https://example.com/*"]
            }
            """;

        var manifest = ChromiumExtensions.ParseManifest(Json);

        Assert.NotNull(manifest);
        Assert.Equal("Sample", manifest!.Name);
        Assert.Equal("1.2.3", manifest.Version);
        Assert.Equal(["storage", "nativeMessaging"], manifest.Permissions);
        Assert.Equal(["https://example.com/*"], manifest.HostAccess);
    }

    [Fact]
    public void A_mv2_manifest_splits_hosts_out_of_the_mixed_permissions_list()
    {
        const string Json = """
            {
              "manifest_version": 2,
              "name": "Legacy",
              "version": "0.9",
              "permissions": ["tabs", "<all_urls>", "http://*/*"]
            }
            """;

        var manifest = ChromiumExtensions.ParseManifest(Json);

        Assert.Equal(["tabs"], manifest!.Permissions);
        Assert.Equal(["<all_urls>", "http://*/*"], manifest.HostAccess);
    }

    [Fact]
    public void A_theme_manifest_is_not_an_extension()
    {
        const string Json = """
            { "name": "Dark", "version": "1", "theme": { "colors": {} } }
            """;

        Assert.Null(ChromiumExtensions.ParseManifest(Json));
    }

    [Fact]
    public void A_malformed_manifest_is_skipped_not_crashing()
    {
        Assert.Null(ChromiumExtensions.ParseManifest("{ not json"));
    }

    [Fact]
    public void A_msg_placeholder_name_resolves_case_insensitively()
    {
        const string Messages = """
            { "appName": { "message": "Real Name" } }
            """;

        Assert.Equal("Real Name", ChromiumExtensions.ResolveName("__MSG_appname__", Messages));
        Assert.Equal("Plain", ChromiumExtensions.ResolveName("Plain", Messages));
        Assert.Equal("__MSG_missing__", ChromiumExtensions.ResolveName("__MSG_missing__", Messages));
        Assert.Equal("__MSG_appname__", ChromiumExtensions.ResolveName("__MSG_appname__", null));
    }
}

public class ChromiumSettingsTests
{
    // Shape observed in Secure Preferences on Chrome 150 / Edge (2026-07-24): no
    // "state" field any more, enabled/disabled carried by "disable_reasons".
    private const string RealisticSettings = """
        {
          "extensions": {
            "settings": {
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
                "disable_reasons": [],
                "from_webstore": true,
                "location": 1,
                "path": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\3.17.190_0",
                "granted_permissions": {
                  "api": ["storage", "unlimitedStorage"],
                  "explicit_host": ["https://example.com/*"],
                  "scriptable_host": ["https://example.com/account/*"]
                }
              },
              "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
                "disable_reasons": [2],
                "from_webstore": true,
                "location": 1,
                "path": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\1.0_0"
              },
              "cccccccccccccccccccccccccccccccc": {
                "disable_reasons": [],
                "from_webstore": false,
                "location": 5,
                "path": "C:\\Program Files\\Google\\Chrome\\Application\\150.0\\resources\\pdf"
              },
              "dddddddddddddddddddddddddddddddd": {
                "disable_reasons": [],
                "from_webstore": false,
                "location": 4,
                "path": "dddddddddddddddddddddddddddddddd\\9.9_0"
              },
              "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": {
                "account_extension_type": 0
              },
              "ffffffffffffffffffffffffffffffff": {
                "disable_reasons": [],
                "from_webstore": false,
                "location": 1,
                "path": "ffffffffffffffffffffffffffffffff\\2.0_0"
              }
            }
          }
        }
        """;

    [Fact]
    public void A_store_extension_is_parsed_with_its_granted_permissions()
    {
        var settings = ChromiumExtensions.ParseSettings(RealisticSettings);

        var entry = Assert.Single(settings, s => s.Id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        Assert.True(entry.Enabled);
        Assert.True(entry.FromStore);
        Assert.Equal(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\3.17.190_0", entry.RelativePath);
        Assert.Equal(["storage", "unlimitedStorage"], entry.GrantedApi);
        Assert.Equal(
            ["https://example.com/*", "https://example.com/account/*"], entry.GrantedHosts);
    }

    [Fact]
    public void A_non_empty_disable_reasons_list_means_disabled()
    {
        var settings = ChromiumExtensions.ParseSettings(RealisticSettings);

        Assert.False(Assert.Single(settings, s => s.Id.StartsWith('b')).Enabled);
    }

    [Fact]
    public void Component_extensions_with_an_absolute_path_are_excluded()
    {
        var settings = ChromiumExtensions.ParseSettings(RealisticSettings);

        Assert.DoesNotContain(settings, s => s.Id.StartsWith('c'));
    }

    [Fact]
    public void An_unpacked_extension_is_not_from_the_store()
    {
        var settings = ChromiumExtensions.ParseSettings(RealisticSettings);

        Assert.False(Assert.Single(settings, s => s.Id.StartsWith('d')).FromStore);
    }

    [Fact]
    public void Sync_stub_entries_without_a_path_are_excluded()
    {
        var settings = ChromiumExtensions.ParseSettings(RealisticSettings);

        Assert.DoesNotContain(settings, s => s.Id.StartsWith('e'));
    }

    [Fact]
    public void Edge_store_extensions_are_from_store_despite_from_webstore_false()
    {
        // Observed on Edge: Microsoft Add-ons installs carry from_webstore=false and
        // location=1. Only the location decides — flagging on from_webstore would mark
        // every Edge extension as sideloaded.
        var settings = ChromiumExtensions.ParseSettings(RealisticSettings);

        Assert.True(Assert.Single(settings, s => s.Id.StartsWith('f')).FromStore);
    }

    [Fact]
    public void Legacy_state_zero_means_disabled()
    {
        const string Legacy = """
            { "extensions": { "settings": { "gggggggggggggggggggggggggggggggg": {
              "state": 0, "from_webstore": true, "location": 1, "path": "g\\1_0" } } } }
            """;

        Assert.False(Assert.Single(ChromiumExtensions.ParseSettings(Legacy)).Enabled);
    }

    [Fact]
    public void A_preferences_file_without_settings_yields_nothing()
    {
        Assert.Empty(ChromiumExtensions.ParseSettings("{}"));
        Assert.Empty(ChromiumExtensions.ParseSettings("not json"));
    }
}

public class FirefoxExtensionsTests
{
    private const string ExtensionsJson = """
        {
          "addons": [
            {
              "id": "uBlock0@raymondhill.net",
              "version": "1.60.0",
              "type": "extension",
              "active": true,
              "location": "app-profile",
              "signedState": 2,
              "defaultLocale": { "name": "uBlock Origin" },
              "userPermissions": {
                "permissions": ["dns", "webRequest"],
                "origins": ["<all_urls>"]
              }
            },
            {
              "id": "shadow@example.org",
              "version": "0.1",
              "type": "extension",
              "active": false,
              "location": "app-profile",
              "signedState": 0,
              "defaultLocale": { "name": "Shadow" },
              "userPermissions": null
            },
            {
              "id": "default-theme@mozilla.org",
              "version": "1.0",
              "type": "theme",
              "active": true,
              "location": "app-profile",
              "defaultLocale": { "name": "System theme" }
            },
            {
              "id": "system@mozilla.org",
              "version": "1.0",
              "type": "extension",
              "active": true,
              "location": "app-system-defaults",
              "defaultLocale": { "name": "System addon" }
            }
          ]
        }
        """;

    [Fact]
    public void A_signed_user_extension_is_parsed_with_its_permissions()
    {
        var extensions = FirefoxExtensions.Parse(ExtensionsJson, "abcd1234.default-release");

        var ext = Assert.Single(extensions, e => e.Id == "uBlock0@raymondhill.net");
        Assert.Equal("Firefox", ext.Browser);
        Assert.Equal("abcd1234.default-release", ext.Profile);
        Assert.Equal("uBlock Origin", ext.Name);
        Assert.Equal("1.60.0", ext.Version);
        Assert.True(ext.Enabled);
        Assert.True(ext.FromStore);
        Assert.Equal(["dns", "webRequest"], ext.Permissions);
        Assert.Equal(["<all_urls>"], ext.HostAccess);
    }

    [Fact]
    public void An_unsigned_extension_is_not_from_the_store()
    {
        var extensions = FirefoxExtensions.Parse(ExtensionsJson, "p");

        var shadow = Assert.Single(extensions, e => e.Id == "shadow@example.org");
        Assert.False(shadow.FromStore);
        Assert.False(shadow.Enabled);
    }

    [Fact]
    public void Themes_and_system_addons_are_excluded()
    {
        var extensions = FirefoxExtensions.Parse(ExtensionsJson, "p");

        Assert.Equal(2, extensions.Count);
        Assert.DoesNotContain(extensions, e => e.Id.Contains("mozilla.org"));
    }

    [Fact]
    public void A_malformed_file_yields_nothing()
    {
        Assert.Empty(FirefoxExtensions.Parse("not json", "p"));
    }
}
