namespace Rempart.Core.Providers;

/// <summary>
/// Each stack's DNS configuration — its adapters, and its own level above them — read through
/// <see cref="IRegistryProvider"/>.
///
/// <para>
/// It lives in Core and not in the Windows layer because there is nothing Windows about it:
/// no P/Invoke, no COM, no file — a handful of registry reads and a split. It sat in
/// <c>Rempart.Windows</c> for as long as it did only because that is where the class that
/// wires it up lives, and the price was that its logic could be exercised nowhere but on a
/// Windows machine, by a test that walked whatever interfaces that machine happened to have.
/// The same move CatalogSignature made, for the same reason: what is a judgement goes down
/// here and is tested on the Linux job; what is interop stays up there and is tested against
/// the real thing.
/// </para>
///
/// <para>
/// Each interface has its own key under <c>Parameters\Interfaces</c>, once per stack.
/// <c>NameServer</c> holds statically configured resolvers, <c>DhcpNameServer</c> those
/// handed out by the network — the distinction the collector evaluates, since a static
/// resolver on a machine that gets one by DHCP is a deliberate act.
/// </para>
///
/// <para>
/// <b>Both stacks, and driven by <see cref="Stacks"/> rather than by a key written into the
/// read.</b> Until #191 the key was a single constant naming <c>Tcpip</c>, which is the IPv4
/// stack alone: a resolver typed on to <c>Tcpip6</c> — where an ordinary machine already
/// resolves — was not collected, not judged, and not reported as uncollected. It is the loop
/// and not a second
/// constant that answers it: what the read walks is the declared table, so a stack that is
/// named is a stack that is read, and <c>RegistryDnsProviderTests</c> exercises every member of
/// <see cref="DnsStack"/> rather than the two that exist today.
/// </para>
///
/// <para>
/// Four reads deep <em>per stack</em>, and each one can be denied on its own: the stack's own
/// <c>NameServer</c>, the enumeration of the interfaces, and the two values of each interface.
/// All of them are watched, because the cheapest place to hide a resolver is the one nobody
/// looks at — an ACL on a single adapter key used to remove that adapter from the inventory
/// without a word (#184), an ACL on the <c>Tcpip6</c> enumeration would have hidden a whole
/// stack for free, and an ACL on the stack's own key hides one value while everything under it
/// answers perfectly.
/// </para>
///
/// <para>
/// <b>What it does not read, measured on a real machine rather than assumed.</b> On the IPv6
/// stack the resolvers a DHCPv6 server hands out are not under <c>DhcpNameServer</c>: Windows
/// writes them to <c>Dhcpv6DNSServers</c>, a <c>REG_BINARY</c> holding the 16-byte addresses
/// end to end, which this read does not decode. So a v6 interface that only <em>leases</em> its
/// resolvers contributes nothing here. That is an inventory line missing, never a verdict: the
/// collector judges statically configured resolvers, which is the hijack surface and which
/// <em>is</em> under <c>NameServer</c> on both stacks. Windows' own <c>fec0:0:0:ffff::1-3</c>
/// fallbacks are in neither place — they are built into the resolver — so they produce no
/// finding either. <c>RegistryDnsProviderTests</c> pins the first of those two rather than
/// leaving it to this paragraph.
/// </para>
///
/// <para>
/// <b>And one level <em>above</em> the adapters, on both stacks alike (#196).</b>
/// <c>{service}\Parameters</c> carries values named <c>NameServer</c> and <c>DhcpNameServer</c>
/// — the two names this read watches per adapter — and until #196 neither was read on either
/// stack. Only the first is read now, only when it holds something, and it is reported as an
/// observation rather than as a resolver. The rest of this summary is why.
/// </para>
///
/// <para>
/// <b>What was measured, on a real Windows 11 machine, on 2026-08-01.</b>
/// <c>Tcpip\Parameters\DhcpNameServer</c> held <c>192.168.1.1</c> — the <c>DhcpNameServer</c> of
/// the one connected adapter, not that of the disconnected card beside it, which held
/// <c>89.2.0.1 89.2.0.2</c>. <c>Tcpip6\Parameters\Dhcpv6DNSServers</c> held, byte for byte, the
/// blob its connected adapter's own key holds. The v4 key had last been written at a lease
/// renewal twelve hours after boot, so it is maintained rather than left over. And what the
/// machine resolves with is accounted for by the adapter keys alone: the operating system
/// reported <em>no</em> IPv4 server for four of its six interfaces while that copy sat there, so
/// it is not handed to an interface that has none of its own — and that same call does report
/// the <c>fec0:0:0:ffff::1-3</c> trio, which is in no registry key at all, so it is the
/// resolver's list it prints and not the registry's. Reading that half would repeat an inventory
/// line the adapter already carries. It is not read.
/// </para>
///
/// <para>
/// <b>What could not be established, and what follows from that.</b> Whether a resolver written
/// to <c>{service}\Parameters\NameServer</c> is consulted is still unknown here: that value is
/// present and <em>empty</em> on an ordinary install, writing one to find out needs an elevation
/// the measurement did not have, and the resolver's own binary settles nothing — <c>dnsrslvr</c>
/// does carry this key path, and that key also holds <c>SearchList</c>, <c>Domain</c> and
/// <c>DhcpDomain</c>, which are certainly read from it. What <em>is</em> established is that no
/// supported configuration path writes it: <c>Set-DnsClientServerAddress</c> and
/// <c>netsh interface ipv4 set dnsservers</c> both require an interface. So a value there is
/// something no ordinary machine has, of an effect this audit has not verified — which is a
/// signal and not an inventory line, and <see cref="Findings.DnsResolverCollector"/> words it
/// as one.
/// </para>
///
/// <para>
/// Neither of those is an IPv6 gap: the v4 stack has had the same one since this read was
/// written, which is why #191 closed the stack that was missing and named this instead of
/// widening into it.
/// </para>
///
/// <para>
/// <b>And one surface that belongs to no stack at all (#199): the name resolution policy
/// table.</b> Two stores of it are read — <see cref="PolicyNrptStore"/> and
/// <see cref="LocalNrptStore"/> — and every rule that names servers of its own is collected as
/// a record of <see cref="DnsScope.NrptRule"/>. See <c>ReadNrptRules</c> for what was measured
/// there and what was deliberately left unread.
/// </para>
///
/// <para>
/// <b>What is <em>not</em> read under the policy hive, and it is a conclusion rather than an
/// omission.</b> That hive also holds a <c>NameServer</c> value, and the help text Windows ships
/// says it « remplace la liste des serveurs DNS configurés localement […] appliquée à toutes les
/// connexions réseau ». The resolver does not read it there. The DNS configuration table of this
/// build — 142 entries of 16 bytes, identical in <c>dnsrslvr.dll</c> and <c>dnsapi.dll</c>
/// 10.0.26100.8875 — flags each entry with the keys it may be read from, and
/// <c>NameServer</c>'s policy flag is clear while <c>EnableMulticast</c>'s, which
/// <c>rules/security/legacy-protocols.yaml</c> already queries under that very key, is set. All
/// four generic readers gate the policy read on that flag, and the <c>supportedOn</c> of the
/// matching ADMX policy on this machine reads « Windows XP Professionnel uniquement ». So a
/// resolver written there is not one <em>either resolver binary reads from that key</em>, and
/// collecting it would be the line of noise this repository trades an audit's credibility for.
/// Recorded here because the help text is an active trap: it will send the next reader back down
/// this path.
/// </para>
///
/// <para>
/// The bound on that conclusion is stated rather than left to be assumed, since the paragraph
/// above is the one a reader six months out will weigh: what was read is <c>dnsrslvr.dll</c> and
/// <c>dnsapi.dll</c>. Nothing established that no component elsewhere copies that value into the
/// per-adapter configuration — the sweep behind this covered <c>System32</c> without recursing —
/// so the claim is about where the resolver reads and not about everything the machine might do
/// with the value. It is enough for the decision it carries, which is that reading the value here
/// would report a resolver on the strength of the help text alone.
/// </para>
/// </summary>
public sealed class RegistryDnsProvider(IRegistryProvider registry) : IDnsProvider
{
    public const string InterfacesKey =
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    public const string InterfacesKeyIPv6 =
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

    /// <summary>
    /// Where each stack keeps its interfaces — the whole of what this read walks.
    ///
    /// <para>
    /// A table and not two constants read one after the other, because the difference is what
    /// #191 is about: a constant is read wherever someone remembered to read it, and the second
    /// one was never written at all. Declaring a stack here is what makes it read, and
    /// <c>RegistryDnsProviderTests</c> holds the table against <see cref="DnsStack"/> both ways
    /// — a member with no key here, or a key here for no member, fails before it ships.
    /// </para>
    ///
    /// <para>
    /// What that cannot decide is whether Windows keeps resolvers on a stack this enum does not
    /// name; no fake registry can answer it, since the answer is a fact about Windows. The
    /// live suite is where it is asked, against the real <c>Services</c> hive.
    /// </para>
    /// </summary>
    public static readonly IReadOnlyList<(DnsStack Stack, string InterfacesKey)> Stacks =
    [
        (DnsStack.IPv4, InterfacesKey),
        (DnsStack.IPv6, InterfacesKeyIPv6),
    ];

    /// <summary>
    /// The name resolution policy table pushed by group policy. Rules are <em>subkeys</em> of
    /// this key, one per rule, each named by a GUID.
    /// </summary>
    public const string PolicyNrptStore =
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

    /// <summary>
    /// The same table laid down locally — what <c>Add-DnsClientNrptRule</c> writes without a
    /// <c>-GpoName</c>. Same shape, different store, and the two are not read alike by Windows.
    /// </summary>
    public const string LocalNrptStore =
        @"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

    /// <summary>
    /// The two stores, <b>policy first</b>, and that order is a measurement rather than a
    /// habit: in <c>dnsapi</c> the local store is opened only if opening the policy store
    /// fails, so of the two it is the policy one that applies when both exist. The store is
    /// therefore part of what a finding reports, and it is part of the key path each rule is
    /// identified by.
    ///
    /// <para>
    /// A table for the reason <see cref="Stacks"/> is one: a store named here is a store that
    /// is read, and <c>RegistryDnsProviderTests</c> holds every theory about rules against the
    /// whole table rather than against the one store somebody remembered.
    /// </para>
    /// </summary>
    public static readonly IReadOnlyList<string> NrptStores = [PolicyNrptStore, LocalNrptStore];

    /// <summary>
    /// The interfaces key of one stack. For callers naming a stack — the tests do; the read
    /// itself walks <see cref="Stacks"/>, so a stack left out of the table is unread rather
    /// than a scan that throws.
    /// </summary>
    public static string InterfacesKeyOf(DnsStack stack) =>
        Stacks.Single(declared => declared.Stack == stack).InterfacesKey;

    /// <summary>
    /// The service's own <c>Parameters</c> key — the level above the adapters, and the second
    /// place a stack keeps a resolver list.
    ///
    /// <para>
    /// Derived from the interfaces key rather than declared beside it, so that a stack added to
    /// <see cref="Stacks"/> is read at both levels without anyone remembering this method. What
    /// makes the derivation sound is the shape every declared key is held to —
    /// <c>…\Services\{service}\Parameters\Interfaces</c>, asserted per member by
    /// <c>RegistryDnsProviderTests</c> — and the two paths it produces are written out and
    /// verified against a real registry in the same file.
    /// </para>
    ///
    /// <para>
    /// Cut by hand rather than with <c>System.IO.Path</c>: this is a Windows registry path
    /// living in Core, which the Linux job compiles and runs, and <c>Path</c> would split it on
    /// the separator of whatever system is running.
    /// </para>
    /// </summary>
    public static string ParametersKeyOf(DnsStack stack)
    {
        var interfaces = InterfacesKeyOf(stack);
        return interfaces[..interfaces.LastIndexOf('\\')];
    }

    public DnsRead Read()
    {
        var interfaces = new List<DnsInterface>();

        // The denied paths, gathered rather than counted: what the report can act on is which
        // surface it lost, and a bare count of two would say nothing about where the hole is.
        var denied = new List<string>();

        // Whether any stack answered anything at all. Not a count of interfaces: a machine
        // whose adapters resolve nothing has been read and answers zero. The global level
        // counts too — a registry with no Interfaces subtree and a resolver on the stack's own
        // key has been read, and returning DnsRead.Absent there would drop what was found,
        // that constant carrying an empty list of its own.
        var answered = false;

        foreach (var (stack, interfacesKey) in Stacks)
        {
            // The level above the adapters, read first so that a refusal there is named even
            // when the enumeration below it is refused as well.
            answered |= ReadStackLevel(stack, interfaces, denied);

            var listing = registry.ListSubKeys(interfacesKey);

            // The key itself. Refused here means no interface of this stack was seen, which
            // used to be the same empty list a machine with no configured adapter returns —
            // the defect of #184, on the surface a hijack is laid on. Gathered and not
            // returned: the other stack is still read, so refusing one buys nothing.
            if (listing.Status is ReadStatus.AccessDenied)
            {
                denied.Add(interfacesKey);
                continue;
            }

            // The key is not on this machine. An answer, and one this read is allowed to give
            // silently: nothing resolves through an interface that was never configured.
            if (listing.Status is ReadStatus.NotFound)
            {
                continue;
            }

            answered = true;

            foreach (var guid in listing.Names)
            {
                var keyPath = $@"{interfacesKey}\{guid}";
                var staticRead = registry.ReadValue(keyPath, "NameServer");
                var dhcpRead = registry.ReadValue(keyPath, "DhcpNameServer");

                // The refusal one level down, and the one that hides a hijack most cheaply: an
                // ACL on a single interface key made both values read back as « rien », so the
                // adapter dropped out of the inventory with its static resolver. An absent
                // value is the ordinary case and stays silent; only a denial speaks.
                if (staticRead.Status is ReadStatus.AccessDenied
                    || dhcpRead.Status is ReadStatus.AccessDenied)
                {
                    denied.Add(keyPath);
                }

                var stat = Split(staticRead.Value?.Text);
                var dhcp = Split(dhcpRead.Value?.Text);

                // An interface with no resolver at all is not a finding and not an omission: a
                // machine carries a dozen of these — tunnels, loopback, disconnected adapters —
                // and listing them would bury the two that resolve anything. Twice over now,
                // since most adapters carry nothing on the v6 stack.
                if (stat.Count > 0 || dhcp.Count > 0)
                {
                    interfaces.Add(new DnsInterface(guid, stat, dhcp, stack));
                }
            }
        }

        // The name resolution policy table, which belongs to no stack and is therefore read
        // once rather than per stack. Last, so that the order of what a report already prints
        // is unchanged by this read existing.
        answered |= ReadNrptRules(interfaces, denied);

        // What the readable interfaces gave is kept beside the refusal: dropping them because
        // one adapter — or one whole stack — was denied would trade one silence for another.
        return denied.Count > 0 ? DnsRead.Refused(interfaces, denied)
            : answered ? DnsRead.Found(interfaces)
            : DnsRead.Absent;
    }

    /// <summary>
    /// The stack's own <c>Parameters</c> key: one value, <c>NameServer</c>, and only when it
    /// holds something.
    ///
    /// <para>
    /// <b>Keyed on the value and never on the key.</b> That value is <em>present</em> and empty
    /// on an ordinary Windows install — measured 2026-08-01 — so reporting its presence would
    /// put a line on every scan this tool runs, and a line of noise costs an audit tool more
    /// than it returns.
    /// </para>
    ///
    /// <para>
    /// <c>DhcpNameServer</c> beside it is not read, and that is a conclusion rather than an
    /// omission: on that same machine it held <c>192.168.1.1</c>, which is the
    /// <c>DhcpNameServer</c> of the one connected adapter and not of the disconnected card next
    /// to it, and the v6 service's <c>Dhcpv6DNSServers</c> held byte for byte what its connected
    /// adapter's own key holds. It is a copy Windows maintains — the key had last been written
    /// at a lease renewal — so reading it would add an inventory line the adapter beside it
    /// already carries.
    /// </para>
    /// </summary>
    /// <returns>Whether the key answered — an answer being a value, present or absent.</returns>
    private bool ReadStackLevel(DnsStack stack, List<DnsInterface> into, List<string> denied)
    {
        var parametersKey = ParametersKeyOf(stack);
        var read = registry.ReadValue(parametersKey, "NameServer");

        // The third place an ACL hides a resolver on this surface, after the enumeration
        // (#184) and the adapter key. It is the cheapest of them: everything below answers
        // perfectly, and the one value that would show a resolver posed above every adapter
        // reads back as « rien ».
        if (read.Status is ReadStatus.AccessDenied)
        {
            denied.Add(parametersKey);
            return false;
        }

        var servers = Split(read.Value?.Text);

        if (servers.Count > 0)
        {
            // Identified by the key it was read from: there is no adapter here, and the key is
            // what the reader goes and looks at. DHCP list empty because that half is unread,
            // never because the machine has none — the collector says so in words rather than
            // printing « DHCP : aucun » over a value nothing looked at.
            into.Add(new DnsInterface(parametersKey, servers, [], stack, DnsScope.Stack));
        }

        return read.Status is ReadStatus.Found;
    }

    /// <summary>
    /// The name resolution policy table, in both stores: every rule that names servers of its
    /// own, identified by its whole key path.
    ///
    /// <para>
    /// <b>Rules are subkeys and not values</b>, which is why this read enumerates rather than
    /// asking for a name — measured in <c>dnsapi</c>, which opens the store with
    /// <c>RegOpenKeyExW</c> and then calls <c>RegEnumKeyExW</c> on it. Each rule's own values are
    /// enumerated too, with <c>ListValues</c> and never <c>ReadValue</c>: the latter throws on a
    /// capture that never recorded the read, which would stop the replay of every fixture on
    /// disk, while <c>ListValues</c> answers <c>NotFound</c> and keeps the silence those captures
    /// already had.
    /// </para>
    ///
    /// <para>
    /// <b>What decides that a rule is collected is its server list, and nothing else.</b>
    /// <c>ConfigOptions</c> carries a bit declaring that a rule sets servers, and gating on it
    /// would sell an exit from the report for the price of deleting one DWORD while the servers
    /// stayed where they were. The rest of a rule — <c>DirectAccessDNSServers</c>,
    /// <c>ProxyName</c>, <c>IDNConfig</c> — is out of scope here and stays unread rather than
    /// half read.
    /// </para>
    ///
    /// <para>
    /// <b>Two states that must produce the same silence, and they coexist on an ordinary
    /// machine.</b> Read-only on 2026-08-01: the policy store is <em>absent</em> and the local
    /// store is <em>present with no subkey at all</em>. Neither is a signal — keying on the
    /// presence of the local store would put a line on every scan this tool runs, and treating
    /// the absence of the policy store as news would do the same off a domain. Only a refusal
    /// speaks, which is the « personne n'a regardé » against « j'ai regardé et il n'y a rien »
    /// of #192 on a surface holding both at once.
    /// </para>
    ///
    /// <para>
    /// What this read does <em>not</em> establish is left to the collector to say in words:
    /// whether resolution follows a rule for the names it claims, and how a rule ranks against
    /// the card's own list. Neither was measured, and #199 was arbitrated « signaler ».
    /// </para>
    /// </summary>
    /// <returns>Whether either store answered — an answer being an enumeration that ran.</returns>
    private bool ReadNrptRules(List<DnsInterface> into, List<string> denied)
    {
        var answered = false;

        foreach (var store in NrptStores)
        {
            var listing = registry.ListSubKeys(store);

            // A whole store refused, which is the cheapest hiding place here: one ACL removes
            // every rule of that store at once, and without this the report of a machine
            // carrying a redirection would be the report of a machine carrying none (#184).
            // Gathered and not returned: the other store is still read.
            if (listing.Status is ReadStatus.AccessDenied)
            {
                denied.Add(store);
                continue;
            }

            if (listing.Status is ReadStatus.NotFound)
            {
                continue;
            }

            answered = true;

            foreach (var rule in listing.Names)
            {
                var rulePath = $@"{store}\{rule}";
                var values = registry.ListValues(rulePath);

                // The refusal one level down, and the quieter of the two: the enumeration above
                // answers perfectly and one rule reads back as « rien ». A rule whose values are
                // refused must not vanish without a word — that is exactly the ACL of #184, one
                // key narrower.
                if (values.Status is ReadStatus.AccessDenied)
                {
                    denied.Add(rulePath);
                    continue;
                }

                var servers = Split(Text(values, "GenericDNSServers"));

                // A rule that names no server of its own is not this collector's business: the
                // table also carries rules that only demand DNSSEC or name a proxy, and a line
                // for those would report a redirection where nothing points anywhere.
                if (servers.Count > 0)
                {
                    into.Add(new DnsInterface(rulePath, servers, [], default, DnsScope.NrptRule)
                    {
                        Namespaces = SplitNames(Text(values, "Name")),
                    });
                }
            }
        }

        return answered;
    }

    /// <summary>
    /// One value of an enumerated key, by name. Absent is <c>null</c> and never an exception:
    /// a rule missing a value is an ordinary rule, and a capture that recorded the listing
    /// without that value is an ordinary capture.
    /// </summary>
    private static string? Text(RegistryValueList values, string name) =>
        values.Values.TryGetValue(name, out var value) ? value.Text : null;

    /// <summary>
    /// Splits the name spaces of a rule, which Windows keeps as a <c>REG_MULTI_SZ</c>.
    ///
    /// <para>
    /// Newlines and not the separators <see cref="Split"/> knows, and the two must not be
    /// confused: <c>IRegistryProvider</c> hands a multi-string over as its entries joined with
    /// <c>\n</c>, while a name space may legitimately contain none of the space, comma or
    /// semicolon a resolver list is cut on. Cutting one with the other would turn two name
    /// spaces into one nobody configured, or one into several.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> SplitNames(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(['\n', '\r'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Splits a resolver list.
    ///
    /// <para>
    /// Windows writes these three ways depending on how they were configured — spaces for a
    /// DHCP lease, commas for a static list set through the UI, and semicolons show up too.
    /// Getting the separators wrong does not fail: it produces one resolver whose address is
    /// two addresses glued together, which matches nothing in the well-known list and comes
    /// out as a <c>Notable</c> finding about a resolver that does not exist.
    /// </para>
    ///
    /// <para>
    /// <b>And the newline, which is a fourth separator and not a fourth spelling of the three
    /// above (#199).</b> The values this cuts under an adapter and under a stack are
    /// <c>REG_SZ</c> and hold none, but <c>GenericDNSServers</c> is read off a key nobody
    /// involved has ever seen written, so its on-disk type is not established — and if it is a
    /// <c>REG_MULTI_SZ</c> then <c>IRegistryProvider</c> hands it over as its entries joined
    /// with <c>\n</c>, which none of the three cuts. The cost is worse there than the glued
    /// address above: the raw newline reaches the finding's target and the sentence built from
    /// it, breaking the console alignment and the Markdown bullet of every finding beside it.
    /// Cutting on it as well cannot cost anything on a <c>REG_SZ</c>, no resolver list holding a
    /// line break, so the unestablished type stops deciding whether the read works.
    /// </para>
    ///
    /// <para>
    /// This stays distinct from <see cref="SplitNames"/> in the other direction, and that
    /// asymmetry is deliberate: a name space must <em>not</em> be cut on space, comma or
    /// semicolon, because nothing establishes those cannot appear in one.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split([' ', ',', ';', '\n', '\r'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
