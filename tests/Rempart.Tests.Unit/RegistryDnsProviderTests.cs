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

        var iface = Assert.Single(new RegistryDnsProvider(registry).Read());

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

        Assert.Equal("{configured}", Assert.Single(new RegistryDnsProvider(registry).Read()).Id);
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

        Assert.NotEmpty(new RegistryDnsProvider(registry).Read());
    }

    /// <summary>
    /// A registry that refuses, or a capture that never recorded the key: no interface, and
    /// no exception. The collector then says nothing about DNS rather than accusing a machine
    /// of a configuration it never read — and the fixtures that predate this collection stay
    /// replayable, which is what <c>ListSubKeys</c> answering empty rather than throwing buys.
    /// </summary>
    [Fact]
    public void A_registry_that_answers_nothing_yields_no_interface_rather_than_an_error() =>
        Assert.Empty(new RegistryDnsProvider(new FakeRegistryProvider()).Read());
}
