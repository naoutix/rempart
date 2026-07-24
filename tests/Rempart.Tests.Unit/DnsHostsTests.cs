using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeDnsProvider(params DnsInterface[] interfaces) : IDnsProvider
{
    public IReadOnlyList<DnsInterface> Read() => interfaces;
}

internal sealed class FakeHostsFileProvider(params string[] lines) : IHostsFileProvider
{
    public IReadOnlyList<string> ReadLines() => lines;
}

public class DnsResolverTests
{
    private static IReadOnlyList<Finding> Collect(params DnsInterface[] interfaces) =>
        new DnsResolverCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            dns: new FakeDnsProvider(interfaces)));

    /// <summary>A resolver received from DHCP is the network's: inventoried, not judged.</summary>
    [Fact]
    public void A_dhcp_resolver_is_benign_inventory()
    {
        var finding = Assert.Single(Collect(new DnsInterface("if0", [], ["192.168.0.1"])));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("DHCP", finding.Details["origine"]);
    }

    /// <summary>A recognised static resolver — Cloudflare, Google — is a common deliberate choice.</summary>
    [Fact]
    public void A_well_known_static_resolver_is_benign()
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", ["1.1.1.1"], []))).Severity);
    }

    /// <summary>A local resolver — loopback, a filter installed on purpose — stays benign.</summary>
    [Fact]
    public void A_loopback_static_resolver_is_benign()
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", ["127.0.0.1"], []))).Severity);
    }

    /// <summary>
    /// An unrecognised static resolver is flagged: a server laid over the network's own
    /// is the very lever of a DNS hijack.
    /// </summary>
    [Fact]
    public void An_unrecognised_static_resolver_is_notable()
    {
        var finding = Assert.Single(Collect(new DnsInterface("if0", ["203.0.113.5"], [])));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("203.0.113.5", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// A mix of resolvers with one unknown among them is flagged: a single unrecognised
    /// address is enough to warrant a look, and it is the one the reason names.
    /// </summary>
    [Fact]
    public void A_mix_with_one_unrecognised_resolver_is_notable()
    {
        var finding = Assert.Single(Collect(new DnsInterface("if0", ["1.1.1.1", "203.0.113.5"], [])));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("203.0.113.5", string.Join(" ", finding.Reasons));
        Assert.DoesNotContain("1.1.1.1", finding.Reasons.Single());
    }

    /// <summary>An interface without resolvers produces nothing: nothing to inventory.</summary>
    [Fact]
    public void An_interface_without_resolvers_yields_nothing()
    {
        Assert.Empty(Collect(new DnsInterface("if0", [], [])));
    }
}

public class HostsFileTests
{
    private static IReadOnlyList<Finding> Collect(params string[] lines) =>
        new HostsFileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            hostsFile: new FakeHostsFileProvider(lines)));

    /// <summary>The default hosts file has nothing but comments: nothing to flag.</summary>
    [Fact]
    public void A_default_hosts_file_yields_nothing()
    {
        Assert.Empty(Collect("# Copyright", "#", "# 102.54.94.97   rhino.acme.com", "   "));
    }

    /// <summary>
    /// A redirect to a routable address short-circuits DNS toward a chosen machine:
    /// each one is flagged individually.
    /// </summary>
    [Fact]
    public void A_redirect_to_a_routable_address_is_notable()
    {
        var finding = Assert.Single(Collect("93.184.216.34  example.com"));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("redirection", finding.Details["type"]);
        Assert.Contains("→", finding.Target);
    }

    /// <summary>
    /// Redirecting a sensitive domain — an update, an authentication — is suspicious:
    /// it is the very shape of a hijack.
    /// </summary>
    [Fact]
    public void A_redirect_of_a_sensitive_domain_is_suspicious()
    {
        var finding = Assert.Single(Collect("93.184.216.34  windowsupdate.microsoft.com"));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    /// <summary>
    /// Blocking entries number in the thousands in an ad-blocking list: they are
    /// aggregated into a single finding, with their count.
    /// </summary>
    [Fact]
    public void Blocking_entries_are_aggregated_into_one_finding()
    {
        var findings = Collect(
            "0.0.0.0  ads.example.com",
            "0.0.0.0  tracker.example.net",
            "127.0.0.1  telemetry.example.org");

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("3", finding.Details["domaines"]);
    }

    /// <summary>
    /// Neutralising an update or a protection is no harmless tweak: preventing a fix is
    /// a manoeuvre, and the aggregate then escalates to suspicious.
    /// </summary>
    [Fact]
    public void Blocking_a_critical_domain_escalates_to_suspicious()
    {
        var findings = Collect(
            "0.0.0.0  ads.example.com",
            "0.0.0.0  update.microsoft.com");

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(findings).Severity);
    }

    /// <summary>One line can point several hosts at one address: each of them counts.</summary>
    [Fact]
    public void Multiple_hosts_on_one_line_each_count()
    {
        var findings = Collect("0.0.0.0  a.example.com b.example.com c.example.com");

        Assert.Equal("3", Assert.Single(findings).Details["domaines"]);
    }

    /// <summary>A trailing comment is stripped before analysis.</summary>
    [Fact]
    public void An_inline_comment_is_stripped()
    {
        var finding = Assert.Single(Collect("93.184.216.34  example.com  # test local"));

        Assert.Equal("example.com", finding.Details["domaine"]);
    }
}
