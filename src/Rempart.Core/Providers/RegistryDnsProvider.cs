namespace Rempart.Core.Providers;

/// <summary>
/// Each interface's DNS configuration, read through <see cref="IRegistryProvider"/>.
///
/// <para>
/// It lives in Core and not in the Windows layer because there is nothing Windows about it:
/// no P/Invoke, no COM, no file — four registry reads and a split. It sat in
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
/// Three reads deep <em>per stack</em>, and each one can be denied on its own: the enumeration
/// of the interfaces, and the two values of each interface. All of them are watched, because
/// the cheapest place to hide a resolver is the one nobody looks at — an ACL on a single
/// adapter key used to remove that adapter from the inventory without a word (#184), and an
/// ACL on the <c>Tcpip6</c> enumeration would have hidden a whole stack for free.
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
/// And one surface a level <em>above</em> the subtree walked here, on both stacks alike:
/// <c>{service}\Parameters</c> carries values named <c>NameServer</c> and
/// <c>DhcpNameServer</c> — the two names this read watches per adapter. Measured on a real
/// Windows 11 machine: <c>Tcpip\Parameters\DhcpNameServer</c> held <c>192.168.1.1</c>, written
/// by Windows itself, <c>Tcpip\Parameters\NameServer</c> was present and empty, and
/// <c>Tcpip6\Parameters</c> kept <c>Dhcpv6DNSServers</c> at that level. This read descends into
/// <c>{interfaces}\{guid}</c> and never opens <c>{service}\Parameters</c>, so none of them
/// reaches a report. Whether the resolver consults them is a fact about Windows that has not
/// been established here, and it is what decides between reading them and writing down why not —
/// so the silence is pinned by a test rather than left to be discovered. It is not an IPv6 gap:
/// the v4 stack has had the same one since this read was written.
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
    /// The interfaces key of one stack. For callers naming a stack — the tests do; the read
    /// itself walks <see cref="Stacks"/>, so a stack left out of the table is unread rather
    /// than a scan that throws.
    /// </summary>
    public static string InterfacesKeyOf(DnsStack stack) =>
        Stacks.Single(declared => declared.Stack == stack).InterfacesKey;

    public DnsRead Read()
    {
        var interfaces = new List<DnsInterface>();

        // The denied paths, gathered rather than counted: what the report can act on is which
        // surface it lost, and a bare count of two would say nothing about where the hole is.
        var denied = new List<string>();

        // Whether any stack got as far as being enumerated. Not a count of interfaces: a
        // machine whose adapters resolve nothing has been read and answers zero.
        var enumerated = false;

        foreach (var (stack, interfacesKey) in Stacks)
        {
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

            enumerated = true;

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

        // What the readable interfaces gave is kept beside the refusal: dropping them because
        // one adapter — or one whole stack — was denied would trade one silence for another.
        return denied.Count > 0 ? DnsRead.Refused(interfaces, denied)
            : enumerated ? DnsRead.Found(interfaces)
            : DnsRead.Absent;
    }

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
    /// </summary>
    public static IReadOnlyList<string> Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split([' ', ',', ';'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
