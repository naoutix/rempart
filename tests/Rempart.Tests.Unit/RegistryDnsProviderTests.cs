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

    /// <summary>
    /// Every stack the layer names, discovered from <see cref="DnsStack"/> and not written out.
    ///
    /// <para>
    /// This is what « par construction » comes to here, and it is worth stating what it does
    /// and does not buy. Every theory below is read once per member, so a stack declared
    /// tomorrow is exercised on collection, on the two value names, on a refused enumeration
    /// and on a refused adapter key without anyone remembering this file.
    /// </para>
    ///
    /// <para>
    /// One list of stacks is written by hand and stays written by hand:
    /// <see cref="The_interfaces_of_each_stack_are_looked_for_where_Windows_keeps_them"/> holds
    /// the whole table against the keys somebody verified on a machine. Deriving that one would
    /// assert nothing at all, and it is the line a stack cannot get past: declaring a member and
    /// a key for it leaves every other test here green — they all read the same declaration —
    /// and reddens this one, which is where the key gets written down after being read off a
    /// real registry rather than guessed.
    /// </para>
    ///
    /// <para>
    /// <b>What none of it can see.</b> It reads the stacks the program names, never the stacks
    /// Windows has: a resolver subtree this enum does not mention is invisible to every test in
    /// this file, because a fake registry answers what the test put in it. That question is a
    /// fact about Windows and is asked against the real <c>Services</c> hive by
    /// <c>LiveDnsProviderTests.No_service_outside_the_declared_stacks_keeps_a_resolver_per_interface</c>
    /// — which asks it of one shape only, a resolver kept <em>per adapter</em> under another
    /// service. A resolver kept somewhere else is out of reach of both, and the one such place
    /// this repository has measured is pinned below rather than left unsaid.
    /// </para>
    /// </summary>
    public static TheoryData<DnsStack> EveryStack() => [.. Enum.GetValues<DnsStack>()];

    /// <summary>
    /// A resolver of this stack's own, so that a read walking one key twice — two members
    /// pointing at the same subtree — cannot pass for a read that walked both.
    /// </summary>
    private static string ResolverOf(DnsStack stack) => $"203.0.113.{(int)stack + 1}";

    /// <summary>
    /// The identifier this file gives its adapter — <b>one identifier for every stack</b>,
    /// because that is the only shape Windows produces.
    ///
    /// <para>
    /// A card is bound to both stacks and keyed by its GUID under each of them, which is the
    /// whole reason <see cref="DnsInterface.Stack"/> exists. An identifier that differed per
    /// stack was a machine that does not exist, and it hid a defect under a green suite: folding
    /// the two subtrees on the identifier — <c>!interfaces.Any(seen =&gt; seen.Id == guid)</c> in
    /// the read — put #191 back, losing the v6 list of every real card, and passed every test in
    /// this file and in the live suite. Sharing the identifier is what lets a test meet that
    /// fold at all; the one that states it and reddens on it is
    /// <see cref="One_adapter_declared_under_every_stack_is_read_once_per_stack"/>, since the
    /// theories below stage a single stack each and cannot see a fold across two.
    /// </para>
    /// </summary>
    private const string Adapter = "{carte}";

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
    ///
    /// <para>
    /// Once per stack since #191, and the interface says which one it came from: the two
    /// values live under the same names in each subtree, so a read that dropped the stack
    /// would put a v6 address on the card's v4 configuration and send its reader to undo it
    /// with the command that cannot.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void A_static_resolver_and_a_leased_one_are_kept_apart(DnsStack stack)
    {
        var key = RegistryDnsProvider.InterfacesKeyOf(stack);

        var registry = new FakeRegistryProvider()
            .WithSubKeys(key, Adapter)
            .WithText($@"{key}\{Adapter}", "NameServer", "9.9.9.9")
            .WithText($@"{key}\{Adapter}", "DhcpNameServer", "192.168.1.1");

        var iface = Assert.Single(new RegistryDnsProvider(registry).Read().Interfaces);

        Assert.Equal(Adapter, iface.Id);
        Assert.Equal(stack, iface.Stack);
        Assert.Equal(["9.9.9.9"], iface.StaticServers);
        Assert.Equal(["192.168.1.1"], iface.DhcpServers);
    }

    /// <summary>
    /// The table the read walks, held against the type that names the stacks — both ways.
    ///
    /// <para>
    /// A member with no key is a stack nobody reads, which is #191 itself; a key with no member
    /// is a subtree nothing can tag. And two members sharing a key would read one subtree twice
    /// and call it two stacks, which every theory in this file would otherwise pass.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_stack_the_layer_names_is_declared_with_a_key_of_its_own()
    {
        Assert.Equal(
            Enum.GetValues<DnsStack>(),
            RegistryDnsProvider.Stacks.Select(declared => declared.Stack));

        Assert.Equal(
            RegistryDnsProvider.Stacks.Count,
            RegistryDnsProvider.Stacks
                .Select(declared => declared.InterfacesKey)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count());
    }

    /// <summary>
    /// The resolvers of a stack reach the report, whichever stack it is — the defect of #191
    /// read at every point of the space it lives in rather than at the one that used to work.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void A_static_resolver_on_any_declared_stack_reaches_the_report(DnsStack stack)
    {
        var key = RegistryDnsProvider.InterfacesKeyOf(stack);

        var registry = new FakeRegistryProvider()
            .WithSubKeys(key, Adapter)
            .WithText($@"{key}\{Adapter}", "NameServer", ResolverOf(stack));

        var read = new RegistryDnsProvider(registry).Read();
        var iface = Assert.Single(read.Interfaces);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal(stack, iface.Stack);
        Assert.Equal([ResolverOf(stack)], iface.StaticServers);

        var finding = Assert.Single(new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry))));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains(ResolverOf(stack), string.Join(" ", finding.Reasons),
            StringComparison.Ordinal);
        Assert.Equal(stack.ToString(), finding.Details["pile"]);
    }

    /// <summary>
    /// <b>One card, declared under every stack by the same identifier — the only arrangement a
    /// Windows machine actually produces</b>, and the one the fix has to survive.
    ///
    /// <para>
    /// A network card is bound to both stacks and keyed by its GUID under each
    /// <c>Parameters\Interfaces</c>, with a resolver list of its own on each side. So the read
    /// meets the same identifier twice per card, and the temptation is to take the second sight
    /// of it for a duplicate. Doing so — <c>!interfaces.Any(seen =&gt; seen.Id == guid)</c> before
    /// the add — is #191 put back where it stood: the v6 list of every real card dropped without
    /// a word, on the one machine shape that matters.
    /// </para>
    ///
    /// <para>
    /// Written because this file used to stage a different identifier per stack, which is a
    /// machine that does not exist: with that fold applied, the whole unit suite and the three
    /// live DNS tests stayed green. The identifier is shared everywhere now, and this states the
    /// property in one place — one record per declared stack, in the order they are declared,
    /// all under the one identifier — rather than leaving it to be inferred from theories that
    /// stage a single stack each.
    /// </para>
    /// </summary>
    [Fact]
    public void One_adapter_declared_under_every_stack_is_read_once_per_stack()
    {
        var registry = new FakeRegistryProvider();

        foreach (var (stack, key) in RegistryDnsProvider.Stacks)
        {
            registry
                .WithSubKeys(key, Adapter)
                .WithText($@"{key}\{Adapter}", "NameServer", ResolverOf(stack));
        }

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(
            RegistryDnsProvider.Stacks.Select(declared => declared.Stack),
            read.Interfaces.Select(iface => iface.Stack));

        Assert.All(read.Interfaces, iface => Assert.Equal(Adapter, iface.Id));

        // And each carries the list of its own subtree: one subtree read twice would give the
        // right count and the wrong addresses.
        Assert.Equal(
            RegistryDnsProvider.Stacks.Select(declared => ResolverOf(declared.Stack)),
            read.Interfaces.Select(iface => Assert.Single(iface.StaticServers)));

        // What the reader ends up with: one finding per stack about one card, told apart by
        // « pile » and by nothing else, the identifier being the same on both.
        var findings = new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry)));

        Assert.Equal(
            RegistryDnsProvider.Stacks.Select(declared => declared.Stack.ToString()),
            findings.Select(finding => finding.Details["pile"]));

        Assert.All(findings, finding => Assert.Equal(Adapter, finding.Source));
    }

    /// <summary>
    /// A refusal laid on one stack's enumeration, read at every stack: it speaks, it names the
    /// key it lost, and it costs the other stacks nothing.
    ///
    /// <para>
    /// This is #187's channel carried to the second subtree, and the cheapest hiding place
    /// there is: an ACL on <c>Tcpip6\Parameters\Interfaces</c> costs an attacker nothing and
    /// used to remove a whole stack from the audit without a word — one better than the ACL on
    /// a single adapter #184 was opened over, since before #191 nothing even looked there.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void A_refused_enumeration_costs_its_own_stack_and_no_other(DnsStack refused)
    {
        var registry = new FakeRegistryProvider();
        var readable = new List<DnsStack>();

        foreach (var (stack, key) in RegistryDnsProvider.Stacks)
        {
            if (stack == refused)
            {
                registry.WithDeniedEnumeration(key);
                continue;
            }

            readable.Add(stack);
            registry
                .WithSubKeys(key, Adapter)
                .WithText($@"{key}\{Adapter}", "NameServer", ResolverOf(stack));
        }

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Contains(RegistryDnsProvider.InterfacesKeyOf(refused), read.Diagnostic!,
            StringComparison.Ordinal);

        // What the other stacks gave survives, tagged with the stack it came from — the form
        // #184 settled on for the adapter next door, one level up.
        Assert.Equal(readable, read.Interfaces.Select(iface => iface.Stack));
        Assert.Equal(
            readable.Select(ResolverOf),
            read.Interfaces.Select(iface => Assert.Single(iface.StaticServers)));

        // And the reader is told about the hole rather than reading a machine that resolves
        // through one stack only.
        var findings = new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry)));

        Assert.Equal(AuditGap.Refused, Assert.Single(findings, f => f.Gap is not null).Gap);
        Assert.Equal(
            readable.Select(stack => stack.ToString()),
            findings.Where(f => f.Gap is null).Select(f => f.Details["pile"]));
    }

    /// <summary>
    /// Every stack refused at once, which is what a non-elevated scan of a machine with an ACL
    /// on the whole subtree looks like: each key is named, and none is dropped.
    ///
    /// <para>
    /// Written because the theory above is blind in one direction and the blindness is
    /// measurable. Replacing the accumulation with an immediate <c>return</c> — the shape the
    /// read had for one stack — leaves the row that refuses the <em>last</em> stack green: what
    /// the earlier stacks gave is already in hand by then, so the early exit costs nothing that
    /// row can see. It reddens on the row refusing the first stack, and it reddens here for
    /// every ordering, because a read that stops at the first refusal names one key out of two.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refusal_on_every_stack_names_every_key_it_lost()
    {
        var registry = new FakeRegistryProvider();

        foreach (var (_, key) in RegistryDnsProvider.Stacks)
        {
            registry.WithDeniedEnumeration(key);
        }

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Empty(read.Interfaces);
        Assert.All(RegistryDnsProvider.Stacks, declared => Assert.Contains(
            declared.InterfacesKey, read.Diagnostic!, StringComparison.Ordinal));

        // One gap and not one per key: the reader is told what the hole covers by the
        // diagnostic, and a finding per refused key would say the same thing twice.
        var finding = Assert.Single(new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry))));

        Assert.Equal(AuditGap.Refused, finding.Gap);
    }

    /// <summary>
    /// A machine that keeps interfaces on one stack and not the other — IPv6 unbound, or a
    /// registry that predates it — is a machine that was read, not one that was not.
    ///
    /// <para>
    /// <see cref="DnsRead.Absent"/> is for the case where no stack answers at all. Returning it
    /// as soon as one subtree is missing would throw away what the other gave; reporting the
    /// missing one as a gap would put a NOTABLE on every machine with a stack unbound, which is
    /// the « vide vivant » #187 settled and this change does not reopen.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void A_machine_keeping_interfaces_on_one_stack_only_is_read_and_stays_silent(
        DnsStack present)
    {
        var read = new RegistryDnsProvider(new OneStackOnly(present)).Read();
        var iface = Assert.Single(read.Interfaces);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Equal(present, iface.Stack);
        Assert.Equal([ResolverOf(present)], iface.StaticServers);
    }

    /// <summary>
    /// What a DHCPv6 lease looks like in the registry, and what this read says about it:
    /// nothing, on purpose and measured rather than assumed.
    ///
    /// <para>
    /// On a real Windows 11 machine the resolvers a DHCPv6 server hands out are not under
    /// <c>DhcpNameServer</c> — that value does not exist on the v6 subtree. They are in
    /// <c>Dhcpv6DNSServers</c>, a <c>REG_BINARY</c> holding the 16-byte addresses end to end;
    /// the blob below was read off such a machine, and the two addresses it encodes are the two
    /// <c>netsh interface ipv6 show dnsservers</c> printed for that adapter. <c>ReadValue</c>
    /// hands binary back as hexadecimal, so nothing throws — the read simply finds no resolver.
    /// </para>
    ///
    /// <para>
    /// That silence is a missing <em>inventory</em> line and never a verdict: what the collector
    /// judges is the statically configured resolver, which is under <c>NameServer</c> on both
    /// stacks and is collected. Pinned here rather than promised in a comment, so that decoding
    /// the blob one day is a deliberate act that reddens this test instead of a quiet win.
    /// </para>
    /// </summary>
    [Fact]
    public void A_DHCPv6_lease_is_not_where_this_read_looks_and_it_says_no_more_than_it_saw()
    {
        const string Leased =
            "2a01cb140b4344004ad24ffffe72cc20fe800000000000004ad24ffffe72cc20";

        var key = RegistryDnsProvider.InterfacesKeyIPv6;

        var registry = new FakeRegistryProvider()
            .WithSubKeys(key, "{bail-v6}")
            .WithText($@"{key}\{{bail-v6}}", "Dhcpv6DNSServers", Leased);

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Empty(read.Interfaces);

        // Silent, and not « aucun résolveur DHCP sur cette pile », which would be a claim the
        // scan never read.
        Assert.Empty(new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry))));
    }

    /// <summary>
    /// <b>The surface one level above the subtree this read walks</b>, and what the read says
    /// about it: nothing — stated here so that it is a known boundary and not an oversight.
    ///
    /// <para>
    /// Each stack's service keeps a <c>Parameters</c> key above its <c>Interfaces</c> subtree,
    /// and that key carries values under the very two names this read watches per adapter.
    /// Measured on the machine this was written on:
    /// <c>…\Services\Tcpip\Parameters\DhcpNameServer</c> holds <c>192.168.1.1</c>, written by
    /// Windows itself; <c>…\Tcpip\Parameters\NameServer</c> is present and empty; and the v6
    /// service keeps <c>Dhcpv6DNSServers</c> at the same level. <see cref="RegistryDnsProvider"/>
    /// descends into <c>{interfaces}\{guid}</c> and never reads <c>{service}\Parameters</c>, so
    /// none of them reaches a report.
    /// </para>
    ///
    /// <para>
    /// Whether Windows <em>resolves</em> through those values is a fact about the platform that
    /// this repository has not established, and the two answers call for different work — a
    /// second read, or a line saying why it is not one. What is not in doubt is that they exist
    /// and carry the names this read treats as the hijack lever, so the silence is pinned here:
    /// reading them one day reddens this test, which is a deliberate act, instead of quietly
    /// adding a finding to every machine.
    /// </para>
    ///
    /// <para>
    /// It is not an IPv6 gap — the v4 stack has the same one, and has had it since this read was
    /// written — which is why #191 closes the stack that was missing and names this rather than
    /// widening into it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_resolver_at_the_global_level_of_a_stack_is_not_where_this_read_looks()
    {
        var registry = new FakeRegistryProvider();

        foreach (var (_, interfacesKey) in RegistryDnsProvider.Stacks)
        {
            // The Parameters key above the Interfaces subtree, whatever the service is called.
            var parameters = interfacesKey[..interfacesKey.LastIndexOf('\\')];

            registry
                .WithText(parameters, "NameServer", "203.0.113.9")
                .WithText(parameters, "DhcpNameServer", "192.168.1.1");
        }

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Empty(read.Interfaces);

        // Silent, and not « aucun résolveur » spoken as a claim: the scan never read there.
        Assert.Empty(new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry))));
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
    /// The key path of each stack, held by value against a registry that answers only for the
    /// right one.
    ///
    /// <para>
    /// This is the failure that has no symptom: a typo in the path makes
    /// <c>ListSubKeys</c> answer with nothing, the collector reports no resolver, and the
    /// report of a machine with a hijacked DNS server looks exactly like the report of a
    /// machine without one. The fake registry answers for the real path and for nothing else,
    /// so a changed path fails here rather than in six months on someone's audit.
    /// </para>
    ///
    /// <para>
    /// The service names are written out and that is deliberate, in a file that otherwise
    /// derives everything from <see cref="DnsStack"/>: a service name is a fact about Windows,
    /// it can only be established on a real machine, and CONTRIBUTING has a rule about shipping
    /// one that was guessed — it answers « rien » for ever and nothing tells it apart from a
    /// machine with nothing to say.
    /// </para>
    ///
    /// <para>
    /// <b>The whole table and not the two rows it happens to have</b>, which is what makes the
    /// previous paragraph true rather than merely intended. Asserting
    /// <c>InterfacesKeyOf(IPv4)</c> and <c>InterfacesKeyOf(IPv6)</c> one at a time said nothing
    /// about a third row: a <c>DnsStack.IPvX</c> declared on
    /// <c>…\Services\Tcpip7\Parameters\Interfaces</c> — a service that exists on no machine —
    /// left the unit suite entirely green, this test included, and only the live suite caught it
    /// on a Windows runner. Held as one sequence, the table cannot grow without this list being
    /// written out too, and writing a line here is where somebody records the key they went and
    /// verified.
    /// </para>
    /// </summary>
    [Fact]
    public void The_interfaces_of_each_stack_are_looked_for_where_Windows_keeps_them()
    {
        (DnsStack Stack, string InterfacesKey)[] verified =
        [
            (DnsStack.IPv4, @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"),
            (DnsStack.IPv6, @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"),
        ];

        Assert.Equal(verified, RegistryDnsProvider.Stacks);

        // And the two constants callers name are the same two paths, so that neither can drift
        // from the table the read walks.
        Assert.Equal(
            RegistryDnsProvider.InterfacesKey,
            RegistryDnsProvider.InterfacesKeyOf(DnsStack.IPv4));

        Assert.Equal(
            RegistryDnsProvider.InterfacesKeyIPv6,
            RegistryDnsProvider.InterfacesKeyOf(DnsStack.IPv6));
    }

    /// <summary>
    /// And the shape every declared key has to have, which is the part a stack added tomorrow
    /// is held to without this file being touched: a service of the current control set,
    /// keeping its adapters under <c>Parameters\Interfaces</c>.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void Every_stack_reads_a_service_key_of_the_current_control_set(DnsStack stack)
    {
        var key = RegistryDnsProvider.InterfacesKeyOf(stack);

        Assert.StartsWith(@"HKLM\SYSTEM\CurrentControlSet\Services\", key, StringComparison.Ordinal);
        Assert.EndsWith(@"\Parameters\Interfaces", key, StringComparison.Ordinal);
    }

    /// <summary>
    /// The defect of #191 in the vocabulary the stack it was hiding on actually speaks, and the
    /// reason this survives beside the theory that generalises it: an IPv6 address is the one
    /// resolver whose text carries the character the splitter must never treat as a separator,
    /// so this reads the split, the key and the judgement together on a real address.
    /// </summary>
    [Fact]
    public void A_static_resolver_typed_on_to_the_IPv6_stack_reaches_the_report()
    {
        var key = RegistryDnsProvider.InterfacesKeyIPv6;

        var registry = new FakeRegistryProvider()
            .WithSubKeys(key, "{v6}")
            .WithText($@"{key}\{{v6}}", "NameServer", "2001:db8::53");

        var finding = Assert.Single(new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry))));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("IPv6", finding.Details["pile"]);
        Assert.Equal("2001:db8::53", finding.Details["résolveurs"]);
        Assert.Contains("2001:db8::53", string.Join(" ", finding.Reasons),
            StringComparison.Ordinal);
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
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void A_refused_interface_key_costs_neither_its_neighbour_nor_the_reader(DnsStack stack)
    {
        var key = RegistryDnsProvider.InterfacesKeyOf(stack);

        var registry = new FakeRegistryProvider()
            .WithSubKeys(key, "{muet}", "{lu}")
            .WithAccessDenied($@"{key}\{{muet}}", "NameServer")
            .WithAccessDenied($@"{key}\{{muet}}", "DhcpNameServer")
            .WithText($@"{key}\{{lu}}", "NameServer", ResolverOf(stack));

        var read = new RegistryDnsProvider(registry).Read();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Contains("{muet}", read.Diagnostic!, StringComparison.Ordinal);

        // The name of the stack it happened on, since the same adapter identifier exists under
        // both and « refusé sur {muet} » would not say which subtree to go and look at.
        Assert.Contains(key, read.Diagnostic!, StringComparison.Ordinal);

        // The neighbour survives, and so does the judgement made about it.
        Assert.Equal("{lu}", Assert.Single(read.Interfaces).Id);

        var findings = new DnsResolverCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), dns: new RegistryDnsProvider(registry)));

        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Gap == AuditGap.Refused);
        Assert.Contains(findings, f => f.Target == ResolverOf(stack) && f.Gap is null);
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
    /// A machine that keeps interfaces under one stack's key and answers « cette clé n'existe
    /// pas » for every other — a registry with IPv6 unbound, or one predating it.
    ///
    /// <para>
    /// Written rather than staged with <see cref="FakeRegistryProvider"/>, which answers
    /// <c>Found([])</c> for a key it was told nothing about: that is « enumerated, and empty »,
    /// a different state from « not there » and the one this theory is not about.
    /// </para>
    /// </summary>
    private sealed class OneStackOnly(DnsStack present) : IRegistryProvider
    {
        private readonly string key = RegistryDnsProvider.InterfacesKeyOf(present);

        public RegistrySubKeyList ListSubKeys(string keyPath) =>
            string.Equals(keyPath, key, StringComparison.OrdinalIgnoreCase)
                ? RegistrySubKeyList.Found([Adapter])
                : RegistrySubKeyList.NotFound;

        public RegistryRead ReadValue(string keyPath, string valueName) =>
            string.Equals(keyPath, $@"{key}\{Adapter}", StringComparison.OrdinalIgnoreCase)
                && valueName == "NameServer"
                    ? RegistryRead.Found(RegistryValue.OfText(ResolverOf(present)))
                    : RegistryRead.NotFound;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.NotFound;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.NotFound;
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
