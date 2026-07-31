using System.Net;
using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// A public resolver whose deliberate use is widespread, and <b>both address families on the
/// one row</b>.
///
/// <para>
/// A row per operator and not a flat list of addresses, and the difference is a false positive
/// #191 shipped and its review caught. The flat list carried Cloudflare's and Google's v6
/// addresses and neither Quad9's nor OpenDNS's; that was invisible for as long as no v6 resolver
/// was collected, and the first scan reading <c>Tcpip6</c> (#191) called a machine deliberately
/// pointed at Quad9 over IPv6 « résolveur statique non reconnu » — a NOTABLE on an ordinary
/// hardened machine, which is the shape this project refuses. Written as a row, a family left
/// empty is missing where it is read, and <c>DnsResolverTests</c> reddens on it rather than
/// waiting for the stack that would have exercised it to be collected.
/// </para>
/// </summary>
/// <param name="Operator">Who runs it. For the reader of the table; nothing matches on it.</param>
/// <param name="IPv4">Its addresses on the v4 stack.</param>
/// <param name="IPv6">Its addresses on the v6 stack. The same service, not a related one.</param>
internal sealed record WellKnownResolver(
    string Operator, IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6);

/// <summary>
/// Configured DNS resolvers, per interface.
///
/// <para>
/// A resolver received from DHCP is the network's: it is inventoried without judgement.
/// A statically set resolver is a choice — and DNS hijacking operates right there, by
/// writing a server the attacker controls over the network's one. We therefore flag
/// static resolvers we do not recognise; those of a well-known public resolver, or of a
/// local one (the loopback, a filter installed on purpose), stay benign — a common
/// deliberate configuration on a hardened machine.
/// </para>
///
/// <para>
/// <b>The same judgement on both stacks, and it means the same thing on both — but not
/// symmetrically (#191).</b> « Typed in by hand » is what is judged, and on the IPv6 stack that
/// is the same value under the same name, so an unrecognised v6 resolver is a hijack lever for
/// the reason a v4 one is. What did <em>not</em> transfer was the list a resolver is recognised
/// against: it carried Cloudflare's and Google's v6 addresses and not Quad9's or OpenDNS's, so
/// the first scan to read <c>Tcpip6</c> would have called the same deliberate choice benign on
/// one stack and unrecognised on the other. It is a table of operators now, both families on the
/// row, and a resolver is matched on the parsed address rather than on the spelling it was typed
/// in — see <see cref="WellKnownResolvers"/> and <see cref="Recognised"/>.
/// </para>
///
/// <para>
/// The other half does not transfer at all: a DHCPv6 lease is not written where
/// <see cref="RegistryDnsProvider"/> reads, so a v6 interface with none of its own shows up here
/// with nothing rather than as benign inventory. Missing an inventory line, never a verdict —
/// and the asymmetry is stated here rather than papered over by reporting v6 as « DHCP: aucun »,
/// which would be a claim the scan never read.
/// </para>
/// </summary>
public sealed class DnsResolverCollector : IFindingCollector
{
    public string Name => "dns-resolver";

    /// <summary>
    /// Public resolvers whose deliberate use is widespread. A static resolver not among
    /// them deserves a look; the list does not claim to be exhaustive, only to cover the
    /// most frequent legitimate choices.
    ///
    /// <para>
    /// The addresses of a row were read off the operator's own hostname —
    /// <c>one.one.one.one</c>, <c>dns.google</c>, <c>dns.quad9.net</c>, <c>dns.opendns.com</c>,
    /// each resolved for <c>A</c> and <c>AAAA</c> in the same breath — so the two families of a
    /// row are one service and not two addresses that looked alike.
    /// </para>
    /// </summary>
    internal static readonly IReadOnlyList<WellKnownResolver> WellKnownResolvers =
    [
        new("Cloudflare",
            ["1.1.1.1", "1.0.0.1"],
            ["2606:4700:4700::1111", "2606:4700:4700::1001"]),
        new("Google",
            ["8.8.8.8", "8.8.4.4"],
            ["2001:4860:4860::8888", "2001:4860:4860::8844"]),
        new("Quad9",
            ["9.9.9.9", "149.112.112.112"],
            ["2620:fe::fe", "2620:fe::9"]),
        new("OpenDNS",
            ["208.67.222.222", "208.67.220.220"],
            ["2620:119:35::35", "2620:119:53::53"]),
    ];

    /// <summary>
    /// The same addresses, parsed — because on the v6 stack « the same resolver » has more than
    /// one spelling.
    ///
    /// <para>
    /// An IPv6 address is written in upper or lower case and with any run of zero groups
    /// compressed or not, all of them naming one address (RFC 4291 §2.2), and what the registry
    /// holds is the spelling whoever configured it typed. Matching the text made the verdict
    /// depend on that spelling: <c>2620:FE::FE</c> and <c>2620:0:0:0:0:0:0:fe</c> are Quad9 and
    /// would have been reported as an unrecognised resolver. It cost nothing before #191, no v6
    /// address ever reaching this comparison; it is reachable now, so the comparison is on the
    /// address. A v4 address has one spelling and is unaffected, and anything that does not
    /// parse — two addresses glued together by a missed separator — matches nothing, which is
    /// the answer it had before.
    /// </para>
    /// </summary>
    private static readonly HashSet<IPAddress> Recognised =
    [
        .. WellKnownResolvers
            .SelectMany(resolver => resolver.IPv4.Concat(resolver.IPv6))
            .Select(IPAddress.Parse),
    ];

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var read = providers.Dns.Read();
        var findings = new List<Finding>();

        // A hole in what the scan saw, and not a machine that resolves nothing. Added rather
        // than returned: the read is partial by nature — the interface enumeration and the two
        // values of each interface are separate reads — so answering with this finding alone
        // would drop the adapters that did answer, including the one carrying the resolver.
        //
        // Refused for a denial, and the argument is the channel rather than the surface: the
        // only thing under the shipped read is IRegistryProvider, which catches the two denial
        // exceptions and lets every other failure through, so AccessDenied here is an ACL and
        // nothing else — and an ACL on Tcpip\Parameters\Interfaces is opened by elevating.
        // Exit 3, « droits insuffisants », which is exactly what the caller can act on.
        //
        // Failed cannot be built by any factory of this read and a capture can still hold it,
        // which is the shape #177 found on the firewall: read as Unreadable, exit 5, because
        // no console however elevated re-reads a snapshot. Anything else — Found on an empty
        // list, NotFound on a machine with no interface key — is an answer and stays silent.
        if (read.Status is ReadStatus.AccessDenied or ReadStatus.Failed)
        {
            var refused = read.Status is ReadStatus.AccessDenied;

            findings.Add(Finding.Unread(
                "dns-resolver", "résolveurs DNS",
                refused ? AuditGap.Refused : AuditGap.Unreadable,
                read.Diagnostic,
                refused
                    ? "Lecture des résolveurs DNS refusée. Relancer en administrateur : un "
                      + "serveur posé par-dessus celui du réseau resterait invisible."
                    : "Lecture des résolveurs DNS sans réponse : un serveur posé par-dessus "
                      + "celui du réseau resterait invisible."));
        }

        foreach (var iface in read.Interfaces)
        {
            if (iface.StaticServers.Count > 0)
            {
                findings.Add(JudgeStatic(iface));
            }
            else if (iface.DhcpServers.Count > 0)
            {
                findings.Add(new Finding("dns-resolver", iface.Id,
                    string.Join(", ", iface.DhcpServers), FindingSeverity.Benign, [],
                    Details(iface, "DHCP", iface.DhcpServers)));
            }
        }

        return findings;
    }

    private static Finding JudgeStatic(DnsInterface iface)
    {
        var unrecognised = iface.StaticServers
            .Where(server => !IsWellKnown(server) && !IsLocal(server))
            .ToList();

        var details = Details(iface, "statique", iface.StaticServers);

        if (unrecognised.Count == 0)
        {
            return new Finding("dns-resolver", iface.Id,
                string.Join(", ", iface.StaticServers), FindingSeverity.Benign, [], details);
        }

        return new Finding("dns-resolver", iface.Id,
            string.Join(", ", iface.StaticServers), FindingSeverity.Notable,
            [$"Résolveur DNS statique non reconnu ({string.Join(", ", unrecognised)}) — un "
             + "serveur posé par-dessus celui du réseau est le levier d'un détournement DNS."],
            details);
    }

    private static bool IsWellKnown(string server) =>
        IPAddress.TryParse(server, out var address) && Recognised.Contains(address);

    /// <summary>
    /// The loopback, and a filter listening on it — a deliberate configuration on a hardened
    /// machine. Read on the parsed address for the reason the well-known list is, with the
    /// textual test kept beside it so that nothing which was benign stops being so.
    /// </summary>
    private static bool IsLocal(string server) =>
        server.StartsWith("127.", StringComparison.Ordinal)
        || server is "::1"
        || (IPAddress.TryParse(server, out var address) && IPAddress.IsLoopback(address));

    /// <summary>
    /// What the reader needs beside the addresses, and the stack is one of the two.
    ///
    /// <para>
    /// Since #191 an adapter appears here once per stack, under the same identifier — that is
    /// how Windows keys the two subtrees — so without this line two findings about the same
    /// card would differ only by the shape of the addresses they carry. It also names the
    /// command that undoes the finding: a static resolver is removed with
    /// <c>netsh interface ipv4</c> or <c>netsh interface ipv6</c>, never with the other.
    /// </para>
    ///
    /// <para>
    /// Written from the member name, so a stack added to <see cref="DnsStack"/> is labelled
    /// rather than mapped to a default by a table nobody updated.
    /// </para>
    /// </summary>
    private static Dictionary<string, string> Details(
        DnsInterface iface, string origin, IReadOnlyList<string> servers) =>
        new(StringComparer.Ordinal)
        {
            ["origine"] = origin,
            ["pile"] = iface.Stack.ToString(),
            ["résolveurs"] = string.Join(", ", servers),
        };
}
