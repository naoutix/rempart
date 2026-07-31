using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// The DNS read, now that it is a judgement in Core rather than a Windows class nobody could
/// exercise off a Windows machine.
///
/// <para>
/// Its failures are quiet by construction, which is what makes it worth a test here. A wrong
/// key path yields no interface, and « aucun résolveur configuré » reads like a machine with
/// nothing unusual about it. A wrong separator yields one resolver whose address is two
/// addresses glued together, which matches nothing in the well-known list and produces a
/// <c>Notable</c> finding about a resolver that does not exist. Neither throws, neither is
/// visible in a report, and until this file existed the only thing watching them was a
/// Windows test that iterated over whatever interfaces the machine running it happened to
/// have — and asserted nothing at all when that was none.
/// </para>
/// </summary>
public sealed class RegistryDnsProviderTests
{
    private const string Interfaces = RegistryDnsProvider.InterfacesKey;

    [Theory]
    // A DHCP lease writes them space-separated.
    [InlineData("192.168.1.1 192.168.1.2", new[] { "192.168.1.1", "192.168.1.2" })]
    // A static list set through the interface writes them comma-separated.
    [InlineData("8.8.8.8,8.8.4.4", new[] { "8.8.8.8", "8.8.4.4" })]
    // Semicolons occur too, and mixed separators with stray spaces around them.
    [InlineData("1.1.1.1; 1.0.0.1 , 9.9.9.9", new[] { "1.1.1.1", "1.0.0.1", "9.9.9.9" })]
    // IPv6 resolvers carry colons of their own: the colon must never be a separator.
    [InlineData("fd00::1 2606:4700:4700::1111",
        new[] { "fd00::1", "2606:4700:4700::1111" })]
    // Nothing configured, in the three shapes the registry produces it.
    [InlineData("", new string[0])]
    [InlineData("   ", new string[0])]
    [InlineData(",,", new string[0])]
    public void Resolvers_are_split_on_every_separator_Windows_writes(string raw, string[] expected) =>
        Assert.Equal(expected, RegistryDnsProvider.Split(raw));

    /// <summary>
    /// The distinction the collector is built on: a resolver typed in by hand is not a
    /// resolver handed out by the network. Swapping the two value names would keep the count
    /// right and invert every judgement about deliberate configuration.
    /// </summary>
    [Fact]
    public void A_static_resolver_and_a_leased_one_are_kept_apart()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Interfaces, "{iface-1}")
            .WithText($@"{Interfaces}\{{iface-1}}", "NameServer", "9.9.9.9")
            .WithText($@"{Interfaces}\{{iface-1}}", "DhcpNameServer", "192.168.1.1");

        var iface = Assert.Single(new RegistryDnsProvider(registry).Read().Interfaces);

        Assert.Equal("{iface-1}", iface.Id);
        Assert.Equal(["9.9.9.9"], iface.StaticServers);
        Assert.Equal(["192.168.1.1"], iface.DhcpServers);
    }

    /// <summary>
    /// The dozen adapters a machine carries that resolve nothing — tunnels, loopback,
    /// disconnected cards — stay out. Listing them would bury the one or two that matter.
    /// </summary>
    [Fact]
    public void An_interface_without_a_single_resolver_is_left_out()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Interfaces, "{empty}", "{configured}")
            .WithText($@"{Interfaces}\{{empty}}", "NameServer", string.Empty)
            .WithText($@"{Interfaces}\{{configured}}", "DhcpNameServer", "1.1.1.1");

        Assert.Equal("{configured}",
            Assert.Single(new RegistryDnsProvider(registry).Read().Interfaces).Id);
    }

    /// <summary>
    /// The key path, held against a registry that answers only for the right one.
    ///
    /// <para>
    /// This is the failure that has no symptom: a typo in the path makes
    /// <c>ListSubKeys</c> answer with nothing, the collector reports no resolver, and the
    /// report of a machine with a hijacked DNS server looks exactly like the report of a
    /// machine without one. The fake registry answers for the real path and for nothing else,
    /// so a changed path fails here rather than in six months on someone's audit.
    /// </para>
    /// </summary>
    [Fact]
    public void The_interfaces_are_looked_for_where_Windows_keeps_them()
    {
        Assert.Equal(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            RegistryDnsProvider.InterfacesKey);

        var registry = new FakeRegistryProvider()
            .WithSubKeys(RegistryDnsProvider.InterfacesKey, "{iface}")
            .WithText($@"{RegistryDnsProvider.InterfacesKey}\{{iface}}", "DhcpNameServer", "1.1.1.1");

        Assert.NotEmpty(new RegistryDnsProvider(registry).Read().Interfaces);
    }

    /// <summary>
    /// A registry that answers with nothing: no interface, and no exception. The collector
    /// then says nothing about DNS rather than accusing a machine of a configuration it never
    /// read — and the fixtures that predate this collection stay replayable, which is what
    /// <c>ListSubKeys</c> answering empty rather than throwing buys.
    ///
    /// <para>
    /// « Ou une capture qui n'a jamais enregistré la clé » is what this summary also claimed
    /// until #184, and it was the sentence that hid the defect: the same empty answer stood
    /// for a key nobody enumerated, a key holding nothing, and a key the machine
    /// <em>refused</em>. The third one now has its own state, asserted below.
    /// </para>
    /// </summary>
    [Fact]
    public void A_registry_that_answers_nothing_yields_no_interface_rather_than_an_error() =>
        Assert.Empty(new RegistryDnsProvider(new FakeRegistryProvider()).Read().Interfaces);

    /// <summary>
    /// The defect of #184, on the surface it matters most: an ACL laid on
    /// <c>Tcpip\Parameters\Interfaces</c> made <c>ListSubKeys</c> answer « refusé » — which it
    /// has been able to say since REV-11 — and this read dropped that answer on the floor,
    /// returning the same empty list a machine with no configured interface returns.
    ///
    /// <para>
    /// The report then said nothing at all about DNS, on the one surface a hijack is laid on:
    /// zero resolver and zero finding, which reads exactly like a machine with nothing to
    /// report. Denying the enumeration is a cheaper way to hide a resolver than removing it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_interfaces_key_is_a_refusal_and_not_a_machine_without_resolvers()
    {
        var registry = new FakeRegistryProvider()
            .WithDeniedEnumeration(RegistryDnsProvider.InterfacesKey);

        // What the reader is told: a hole in the audit, repaired by elevating — not a silence.
        var finding = Assert.Single(new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry))));

        Assert.Equal(AuditGap.Refused, finding.Gap);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
    }

    /// <summary>
    /// The refusal one level down, and the one a guard written only for the key above would
    /// have missed entirely.
    ///
    /// <para>
    /// This read is three reads: the enumeration of the interfaces, then <c>NameServer</c> and
    /// <c>DhcpNameServer</c> on each of them. An ACL on a single adapter key leaves the
    /// enumeration answering perfectly and makes that adapter's two values read back as
    /// « rien » — so it drops out of the inventory with its static resolver, which is a
    /// cheaper place to hide a hijack than the key everybody watches. Watching only the
    /// enumeration would have left this exactly as it was, under a green suite.
    /// </para>
    ///
    /// <para>
    /// And the adapter that answered keeps its resolver: dropping what was read because the
    /// neighbour refused would trade one silence for another, which is the correction
    /// <c>ListeningPortRead.Partial</c> and <c>AutorunsCollector</c> each had to make.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_interface_key_costs_neither_its_neighbour_nor_the_reader()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Interfaces, "{muet}", "{lu}")
            .WithAccessDenied($@"{Interfaces}\{{muet}}", "NameServer")
            .WithAccessDenied($@"{Interfaces}\{{muet}}", "DhcpNameServer")
            .WithText($@"{Interfaces}\{{lu}}", "NameServer", "203.0.113.5");

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Contains("{muet}", read.Diagnostic!, StringComparison.Ordinal);

        // The neighbour survives, and so does the judgement made about it.
        Assert.Equal("{lu}", Assert.Single(read.Interfaces).Id);

        var findings = new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry)));

        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Gap == AuditGap.Refused);
        Assert.Contains(findings, f => f.Target == "203.0.113.5" && f.Gap is null);
    }

    /// <summary>
    /// The other half of the asymmetry, and the reason the fix is not « always warn »: a value
    /// that is simply <em>not there</em> is the ordinary case — most adapters carry neither
    /// resolver — and stays silent. Asserted beside the refusal above because it is the
    /// <em>difference</em> that is the invariant: a guard that reported both would put a
    /// NOTABLE on every scan and be switched off within a week.
    /// </summary>
    [Fact]
    public void An_absent_resolver_value_stays_silent_where_a_refused_one_speaks()
    {
        var registry = new FakeRegistryProvider().WithSubKeys(Interfaces, "{sans-resolveur}");

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Empty(read.Interfaces);
    }

    /// <summary>
    /// A registry with no interfaces key at all: an answer, and not a hole. Nothing resolves
    /// through an interface that was never configured, so the read says <c>NotFound</c> and the
    /// collector stays silent — spelling it <c>Found</c> instead would write a claim into the
    /// capture that the scan never made.
    /// </summary>
    [Fact]
    public void A_machine_without_the_interfaces_key_is_absent_and_not_a_refusal()
    {
        var read = new RegistryDnsProvider(new EmptyRegistry()).Read();

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Empty(read.Interfaces);

        Assert.Empty(new DnsResolverCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            dns: new RegistryDnsProvider(new EmptyRegistry()))));
    }

    /// <summary>
    /// Answers « cette clé n'existe pas » to every enumeration — which
    /// <see cref="FakeRegistryProvider"/> cannot, it having chosen <c>Found([])</c> for a key
    /// it was told nothing about.
    /// </summary>
    private sealed class EmptyRegistry : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) => RegistryRead.NotFound;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.NotFound;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.NotFound;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.NotFound;
    }
}
