using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

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
/// the reason a v4 one is; the well-known list has carried Cloudflare's and Google's v6
/// addresses since it was written, and <see cref="IsLocal"/> already knew <c>::1</c>. The other
/// half does not transfer: a DHCPv6 lease is not written where <see cref="RegistryDnsProvider"/>
/// reads, so a v6 interface with none of its own shows up here with nothing rather than as
/// benign inventory. Missing an inventory line, never a verdict — and the asymmetry is stated
/// here rather than papered over by reporting v6 as « DHCP: aucun », which would be a claim the
/// scan never read.
/// </para>
/// </summary>
public sealed class DnsResolverCollector : IFindingCollector
{
    public string Name => "dns-resolver";

    /// <summary>
    /// Public resolvers whose deliberate use is widespread. A static resolver not among
    /// them deserves a look; the list does not claim to be exhaustive, only to cover the
    /// most frequent legitimate choices.
    /// </summary>
    private static readonly HashSet<string> WellKnownResolvers = new(StringComparer.Ordinal)
    {
        "1.1.1.1", "1.0.0.1",              // Cloudflare
        "8.8.8.8", "8.8.4.4",              // Google
        "9.9.9.9", "149.112.112.112",      // Quad9
        "208.67.222.222", "208.67.220.220", // OpenDNS
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
    };

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
            .Where(server => !WellKnownResolvers.Contains(server) && !IsLocal(server))
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

    private static bool IsLocal(string server) =>
        server.StartsWith("127.", StringComparison.Ordinal) || server is "::1";

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
