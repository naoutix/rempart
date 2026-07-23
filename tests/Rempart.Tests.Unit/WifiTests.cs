using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>Fournisseur de profils Wi-Fi factice, sur le modèle de FakeDnsProvider.</summary>
internal sealed class FakeWifiProfileProvider(params WifiProfile[] profiles) : IWifiProfileProvider
{
    public IReadOnlyList<WifiProfile> Read() => profiles;
}

public class WifiProfileCollectorTests
{
    private static Finding Collect(WifiProfile profile) =>
        Assert.Single(new WifiProfileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            wifi: new FakeWifiProfileProvider(profile))));

    [Fact]
    public void No_profile_yields_nothing() =>
        Assert.Empty(new WifiProfileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            wifi: new FakeWifiProfileProvider())));

    [Fact]
    public void An_open_network_on_auto_connect_is_suspicious()
    {
        var finding = Collect(new WifiProfile("café", "open", "none", AutoConnect: true));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("evil twin", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void An_open_network_on_manual_connect_is_notable() =>
        Assert.Equal(FindingSeverity.Notable,
            Collect(new WifiProfile("café", "open", "none", AutoConnect: false)).Severity);

    [Fact]
    public void A_wep_network_is_suspicious() =>
        Assert.Equal(FindingSeverity.Suspicious,
            Collect(new WifiProfile("vieux", "open", "WEP", AutoConnect: false)).Severity);

    [Fact]
    public void A_tkip_network_is_notable() =>
        Assert.Equal(FindingSeverity.Notable,
            Collect(new WifiProfile("maison", "WPAPSK", "TKIP", AutoConnect: true)).Severity);

    [Fact]
    public void A_wpa2_aes_network_is_benign() =>
        Assert.Equal(FindingSeverity.Benign,
            Collect(new WifiProfile("maison", "WPA2PSK", "AES", AutoConnect: true)).Severity);

    [Fact]
    public void A_wpa3_network_is_benign() =>
        Assert.Equal(FindingSeverity.Benign,
            Collect(new WifiProfile("maison", "WPA3SAE", "AES", AutoConnect: false)).Severity);

    [Fact]
    public void The_finding_carries_the_security_in_its_details()
    {
        var details = Collect(new WifiProfile("maison", "WPA3SAE", "AES", AutoConnect: false)).Details;

        Assert.Equal("WPA3SAE", details["authentification"]);
        Assert.Equal("AES", details["chiffrement"]);
        Assert.Equal("manuelle", details["connexion"]);
    }
}

public class WifiSnapshotTests
{
    [Fact]
    public void Recording_then_replaying_round_trips_the_profiles()
    {
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-01-01T00:00:00.0000000Z" };
        var profile = new WifiProfile("maison", "WPA2PSK", "AES", AutoConnect: true);

        new RecordingWifiProfileProvider(new FakeWifiProfileProvider(profile), snapshot).Read();

        var round = RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot));
        var replayed = new SnapshotWifiProfileProvider(round).Read();

        Assert.Equal(profile, Assert.Single(replayed));
    }

    [Fact]
    public void A_snapshot_without_wifi_replays_an_empty_list() =>
        Assert.Empty(new SnapshotWifiProfileProvider(new MachineSnapshot()).Read());
}

public class WifiAnonymisationTests
{
    [Fact]
    public void The_ssid_is_hashed_but_the_security_stays_readable()
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Wifi = [new WifiProfile("SSID-Maison-Perso", "WPA2PSK", "AES", AutoConnect: true)],
        };

        var profile = Assert.Single(Anonymiser.Apply(snapshot).Wifi!);

        Assert.StartsWith("anon:", profile.Name);
        Assert.DoesNotContain("Maison", profile.Name);
        Assert.Equal("WPA2PSK", profile.Authentication);   // la sécurité reste jugeable
    }
}

public class WifiEngineIntegrationTests
{
    [Fact]
    public void The_engine_surfaces_a_suspicious_open_auto_profile()
    {
        var providers = new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            wifi: new FakeWifiProfileProvider(
                new WifiProfile("café-gratuit", "open", "none", AutoConnect: true)));

        var result = new ScanEngine(ScanEngine.DefaultCollectors, [])
            .Run(providers, "test", "2026-01-01T00:00:00.0000000Z", null,
                ScanEngine.DefaultFindingCollectors(DriverBlocklist.Empty, BloatwareCatalog.Empty));

        var wifi = Assert.Single(result.Findings, f => f.Kind == "wifi-profile");
        Assert.Equal(FindingSeverity.Suspicious, wifi.Severity);
    }
}
