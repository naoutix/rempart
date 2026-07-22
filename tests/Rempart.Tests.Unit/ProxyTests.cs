using System.Buffers.Binary;
using System.Text;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>Un fournisseur proxy simulé, sur le modèle de FakeDnsProvider.</summary>
internal sealed class FakeProxyProvider(ProxyConfiguration config) : IProxyProvider
{
    public ProxyConfiguration Read() => config;
}

public class ProxyProviderSetTests
{
    /// <summary>Absent, aucun proxy n'est inventé : la config est vide, comme EmptyDns.</summary>
    [Fact]
    public void An_absent_proxy_provider_yields_an_empty_configuration()
    {
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        var config = providers.Proxy.Read();

        Assert.False(config.WinInet.Enabled);
        Assert.Null(config.WinInet.Server);
        Assert.False(config.WinHttp.Enabled);
        Assert.False(config.PolicyImposed);
    }
}

public class ProxyCollectorTests
{
    private static IReadOnlyList<Finding> Collect(ProxyConfiguration config) =>
        new ProxyCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            proxy: new FakeProxyProvider(config)));

    private static ProxyConfiguration WinInet(
        bool enabled = false, string? server = null, string? pac = null, bool policy = false) =>
        new(new ProxyScope(enabled, server, pac, []), ProxyScope.Disabled, policy);

    [Fact]
    public void Nothing_configured_yields_no_finding() =>
        Assert.Empty(Collect(ProxyConfiguration.Empty));

    [Fact]
    public void A_loopback_proxy_is_benign()
    {
        var finding = Assert.Single(Collect(WinInet(enabled: true, server: "127.0.0.1:8080")));
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
    }

    [Fact]
    public void An_external_proxy_imposed_by_policy_is_benign()
    {
        var finding = Assert.Single(
            Collect(WinInet(enabled: true, server: "proxy.corp:8080", policy: true)));
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
    }

    [Fact]
    public void An_external_proxy_not_imposed_is_notable()
    {
        var finding = Assert.Single(Collect(WinInet(enabled: true, server: "proxy.corp:8080")));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
    }

    [Fact]
    public void An_https_pac_is_notable()
    {
        var finding = Assert.Single(Collect(WinInet(pac: "https://wpad.example/proxy.pac")));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
    }

    [Fact]
    public void An_http_external_pac_not_imposed_is_suspicious()
    {
        var finding = Assert.Single(Collect(WinInet(pac: "http://198.51.100.7/p.pac")));
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("PAC", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void An_http_external_pac_imposed_by_policy_is_benign()
    {
        var finding = Assert.Single(
            Collect(WinInet(pac: "http://wpad.corp/p.pac", policy: true)));
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
    }

    [Fact]
    public void A_disabled_proxy_with_a_malicious_pac_is_still_judged_on_the_pac()
    {
        // AutoConfigURL s'applique même quand ProxyEnable vaut 0 : le PAC est jugé seul.
        var finding = Assert.Single(Collect(WinInet(enabled: false, pac: "http://198.51.100.7/p.pac")));
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    [Fact]
    public void Winhttp_and_wininet_are_two_findings()
    {
        var config = new ProxyConfiguration(
            new ProxyScope(true, "proxy.corp:8080", null, []),
            new ProxyScope(true, "10.0.0.9:3128", null, []),
            PolicyImposed: false);
        Assert.Equal(2, Collect(config).Count);
    }
}

public class WinHttpSettingsDecoderTests
{
    /// <summary>Construit un blob au format WinHttpSettings (en-tête + chaînes préfixées).</summary>
    private static byte[] BuildBlob(uint flags, string server, string bypass)
    {
        var serverBytes = Encoding.ASCII.GetBytes(server);
        var bypassBytes = Encoding.ASCII.GetBytes(bypass);
        var blob = new byte[12 + 4 + serverBytes.Length + 4 + bypassBytes.Length];
        var span = blob.AsSpan();

        BinaryPrimitives.WriteUInt32LittleEndian(span[0..], 0x18);   // version
        BinaryPrimitives.WriteUInt32LittleEndian(span[4..], 0x01);   // compteur
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], flags);
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], (uint)serverBytes.Length);
        serverBytes.CopyTo(span[16..]);
        var offset = 16 + serverBytes.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], (uint)bypassBytes.Length);
        bypassBytes.CopyTo(span[(offset + 4)..]);
        return blob;
    }

    [Fact]
    public void Decodes_a_configured_proxy_with_bypass()
    {
        var scope = WinHttpSettingsDecoder.Decode(
            BuildBlob(0x2, "proxy.corp:8080", "*.local;<local>"));

        Assert.True(scope.Enabled);
        Assert.Equal("proxy.corp:8080", scope.Server);
        Assert.Equal(["*.local", "<local>"], scope.Bypass);
    }

    [Fact]
    public void A_direct_access_blob_is_disabled()
    {
        var scope = WinHttpSettingsDecoder.Decode(BuildBlob(0x1, "", ""));

        Assert.False(scope.Enabled);
        Assert.Null(scope.Server);
    }

    [Fact]
    public void An_empty_blob_is_disabled_and_does_not_throw() =>
        Assert.False(WinHttpSettingsDecoder.Decode([]).Enabled);

    [Fact]
    public void A_truncated_blob_is_disabled_and_does_not_throw()
    {
        // En-tête annonçant un serveur de 400 octets sur un blob qui n'en a que 16.
        var blob = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan()[8..], 0x2);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan()[12..], 400);

        var scope = WinHttpSettingsDecoder.Decode(blob);

        Assert.Null(scope.Server);
    }
}

public class ProxySnapshotTests
{
    [Fact]
    public void Recording_then_replaying_round_trips_the_configuration()
    {
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-01-01T00:00:00.0000000Z" };
        var config = new ProxyConfiguration(
            new ProxyScope(true, "proxy.corp:8080", "http://wpad.corp/p.pac", ["*.local"]),
            ProxyScope.Disabled, PolicyImposed: false);

        new RecordingProxyProvider(new FakeProxyProvider(config), snapshot).Read();

        // Passe par la sérialisation réelle : garde-fou AOT sur les nouveaux records.
        var round = RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot));
        var replayed = new SnapshotProxyProvider(round).Read();

        // Comparaison structurelle : l'égalité de record compare Bypass (IReadOnlyList)
        // par référence, ce qu'une désérialisation ne peut pas satisfaire.
        Assert.Equal(config.PolicyImposed, replayed.PolicyImposed);
        Assert.Equal(config.WinInet.Enabled, replayed.WinInet.Enabled);
        Assert.Equal(config.WinInet.Server, replayed.WinInet.Server);
        Assert.Equal(config.WinInet.AutoConfigUrl, replayed.WinInet.AutoConfigUrl);
        Assert.Equal(config.WinInet.Bypass, replayed.WinInet.Bypass);
        Assert.Equal(config.WinHttp.Enabled, replayed.WinHttp.Enabled);
        Assert.Equal(config.WinHttp.Server, replayed.WinHttp.Server);
    }

    [Fact]
    public void A_snapshot_without_a_proxy_section_replays_an_empty_configuration()
    {
        // Rétrocompat : une fixture d'avant ce lot n'a pas de section proxy.
        var replayed = new SnapshotProxyProvider(new MachineSnapshot()).Read();

        Assert.Equal(ProxyConfiguration.Empty, replayed);
    }
}

public class ProxyAnonymisationTests
{
    private static ProxyConfiguration Anonymise(ProxyConfiguration config)
    {
        var snapshot = new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default, Proxy = config };
        return Anonymiser.Apply(snapshot).Proxy!;
    }

    [Fact]
    public void An_external_proxy_host_is_hashed()
    {
        var result = Anonymise(new ProxyConfiguration(
            new ProxyScope(true, "proxy.corp.example:8080", null, []),
            ProxyScope.Disabled, false));

        Assert.DoesNotContain("corp.example", result.WinInet.Server);
        Assert.Contains("anon:", result.WinInet.Server);
        Assert.EndsWith(":8080", result.WinInet.Server);   // le port reste lisible
    }

    [Fact]
    public void A_loopback_proxy_is_left_readable()
    {
        var result = Anonymise(new ProxyConfiguration(
            new ProxyScope(true, "127.0.0.1:8888", null, []),
            ProxyScope.Disabled, false));

        Assert.Equal("127.0.0.1:8888", result.WinInet.Server);
    }

    [Fact]
    public void A_pac_url_keeps_its_scheme_but_hides_its_host()
    {
        var result = Anonymise(new ProxyConfiguration(
            new ProxyScope(false, null, "http://wpad.corp.example/proxy.pac", []),
            ProxyScope.Disabled, false));

        Assert.StartsWith("http://anon:", result.WinInet.AutoConfigUrl);
        Assert.EndsWith("/proxy.pac", result.WinInet.AutoConfigUrl);
        Assert.DoesNotContain("corp.example", result.WinInet.AutoConfigUrl);
    }
}

public class ProxyEngineIntegrationTests
{
    [Fact]
    public void The_engine_surfaces_a_suspicious_pac_finding()
    {
        var providers = new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            proxy: new FakeProxyProvider(new ProxyConfiguration(
                new ProxyScope(false, null, "http://198.51.100.7/p.pac", []),
                ProxyScope.Disabled, PolicyImposed: false)));

        var result = new ScanEngine(ScanEngine.DefaultCollectors, [])
            .Run(providers, "test", "2026-01-01T00:00:00.0000000Z", null,
                ScanEngine.DefaultFindingCollectors(DriverBlocklist.Empty));

        var proxy = Assert.Single(result.Findings, f => f.Kind == "proxy");
        Assert.Equal(FindingSeverity.Suspicious, proxy.Severity);
    }
}
