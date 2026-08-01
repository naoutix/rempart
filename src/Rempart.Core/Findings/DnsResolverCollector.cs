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
///
/// <para>
/// <b>And nothing above transfers to the level above the cards (#196).</b> A stack keeps a
/// resolver list on its own <c>Parameters</c> key as well, and neither « statique contre DHCP »
/// nor the well-known list means there what it means under a card — see
/// <see cref="SignalStackLevel"/>, which is the whole of what this collector says about it.
/// </para>
///
/// <para>
/// <b>Nor to a rule of the name resolution policy table (#199).</b> A rule points a set of names
/// at a set of servers, which is neither an adapter's configuration nor a stack's: see
/// <see cref="SignalNrptRule"/>. It is reported as an observation for the reason the level above
/// the cards is, and it is the surface where overclaiming would cost most — « le résolveur de la
/// machine est détourné » is a sentence about a reach nobody measured.
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
        // than returned: the read is partial by nature — the stack's own value, the interface
        // enumeration and the two values of each interface are separate reads — so answering
        // with this finding alone would drop what did answer, resolver included.
        //
        // Refused for a denial, and the argument is the channel rather than the surface: the
        // only thing under the shipped read is IRegistryProvider, which catches the two denial
        // exceptions and lets every other failure through, so AccessDenied here is an ACL and
        // nothing else — and an ACL on Tcpip\Parameters, or on the Interfaces subtree under it,
        // is opened by elevating. Exit 3, « droits insuffisants », which the caller can act on.
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
            // The two scopes that are not judged like an adapter — first, so that nothing
            // below can fall through to the adapter's verdict.
            if (iface.Scope is DnsScope.NrptRule)
            {
                findings.Add(SignalNrptRule(iface));
            }
            else if (iface.Scope is DnsScope.Stack)
            {
                findings.Add(SignalStackLevel(iface));
            }
            else if (iface.StaticServers.Count > 0)
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

    /// <summary>
    /// A resolver list sitting on the stack's own <c>Parameters</c> key: said, and said as an
    /// observation — never as the verdict the same address earns under a card.
    ///
    /// <para>
    /// <b>What #196 measured, and what it could not.</b> On a real Windows 11 machine the DHCP
    /// half of that level is written by Windows as a copy of the leasing adapter's list, and the
    /// resolver does not hand it to interfaces that have none of their own — four of that
    /// machine's six interfaces reported no IPv4 server while the copy sat there. So that half
    /// is not read: it would repeat an inventory line. The static half could not be settled:
    /// <c>NameServer</c> is present and <em>empty</em> there on an ordinary install, writing one
    /// to find out needs an elevation the measurement did not have, and no supported
    /// configuration path writes it — <c>Set-DnsClientServerAddress</c> and
    /// <c>netsh interface ipv4 set dnsservers</c> both require an interface.
    /// </para>
    ///
    /// <para>
    /// That is why this is a signal and not an inventory line. The reader is told a value is
    /// there, that nothing ordinary put it there, and that whether the machine resolves through
    /// it was <em>not</em> established — a finding claiming the third would be exactly the
    /// « collecter la clé en laissant croire que sa présence a été vérifiée » the issue forbids.
    /// </para>
    ///
    /// <para>
    /// Neither half of the adapter's judgement reaches here, deliberately. « Statique contre
    /// DHCP » compares two lists, and at this level there is one — the other is Windows' own
    /// copy. And the well-known list stays out: recognising Quad9 under a card means « a
    /// deliberate hardening choice, made where such choices are made », which is the very thing
    /// a key no command writes cannot be read as. What is reported is the place, so no address
    /// makes it go quiet.
    /// </para>
    ///
    /// <para>
    /// <see cref="Finding.Source"/> is the key, which designates exactly one finding per scan —
    /// one per stack, each on its own key — where an adapter GUID designates one per stack since
    /// #191. So <c>rempart diff</c> may merge a disappearance and an appearance on it into « the
    /// same place now holds something else », which is the reading a reader wants there.
    /// </para>
    /// </summary>
    private static Finding SignalStackLevel(DnsInterface level)
    {
        var servers = string.Join(", ", level.StaticServers);

        return new Finding("dns-resolver", level.Id, servers, FindingSeverity.Notable,
            [
                $"Liste de résolveurs DNS ({servers}) posée au niveau global de la pile "
                + $"{level.Stack}, au-dessus des cartes : aucune commande de configuration DNS "
                + "de Windows n'écrit à cet endroit.",

                "Cet audit n'a pas établi que la résolution consulte ce niveau : la valeur est "
                + "relevée telle quelle, elle n'est pas comptée comme un résolveur actif. À "
                + "vérifier à la main.",
            ],
            Details(level, "niveau global de la pile", level.StaticServers));
    }

    /// <summary>
    /// A rule of the name resolution policy table: said, and said as an observation — for the
    /// reason <see cref="SignalStackLevel"/> is, on a surface where the temptation to overclaim
    /// is stronger.
    ///
    /// <para>
    /// <b>What was established, and it is more than for the level above the cards.</b> The rules
    /// are subkeys of two stores that <c>dnsapi</c> opens and enumerates, and of the two it is
    /// the policy store that applies when both are there — the local one is opened only if
    /// opening the policy one fails, read in the binary rather than quoted from a specification.
    /// So the store is stated in words, and it is inside the key path each finding is sourced by.
    /// </para>
    ///
    /// <para>
    /// <b>What was not, and why this is a signal and not a verdict.</b> How a rule's server list
    /// ranks against the card's own was never measured — documented, never followed through the
    /// code to the point where a server is picked — and nobody involved has ever seen a rule
    /// written to disk. « Le résolveur de la machine est détourné » would claim a reach nobody
    /// verified, which is the reproach #199 forbids in advance. The sentence therefore names the
    /// name spaces the rule claims and stops there: an auditor reading it can tell whether those
    /// names are ones they care about, which is a judgement this audit is in no position to make
    /// for them.
    /// </para>
    ///
    /// <para>
    /// Nothing of the adapter's judgement reaches here either. « Statique contre DHCP » compares
    /// two lists and a rule has one; the well-known list stays out, because recognising Quad9
    /// under a card means « a deliberate hardening choice made where such choices are made » and
    /// a rule is not that place. And no stack is printed: see <see cref="NrptDetails"/>.
    /// </para>
    ///
    /// <para>
    /// <see cref="Finding.Source"/> is the rule's whole key path, store included, which
    /// designates exactly one finding per scan — a rule is a subkey, a subkey's GUID is unique
    /// in its store, and the store is in the path. So the same rule pushed by policy and laid
    /// down locally gives two Sources instead of colliding on one, which is a real case:
    /// <c>Add-DnsClientNrptRule</c> writes one store or the other depending on <c>-GpoName</c>.
    /// The consequence to have wanted rather than suffered is that a rule a GPO moves between
    /// the stores comes out as a disappearance and an appearance rather than as a « Change » —
    /// which is correct, the two places not being read alike by Windows.
    /// </para>
    /// </summary>
    private static Finding SignalNrptRule(DnsInterface rule)
    {
        var servers = string.Join(", ", rule.StaticServers);

        // Never « pour tous les noms »: whether a rule can claim every name at once is
        // documented one way by one Microsoft page and another by the protocol specification,
        // and this audit did not settle it. What is printed is the space the registry holds.
        var names = rule.Namespaces.Count > 0
            ? string.Join(", ", rule.Namespaces)
            : "des noms que cette lecture n'a pas relevés";

        return new Finding("dns-resolver", rule.Id, servers, FindingSeverity.Notable,
            [
                $"Une règle de résolution de noms envoie les requêtes pour {names} vers "
                + $"{servers} ; cette règle est portée par le {StoreOf(rule)}.",

                "Cet audit n'a pas établi que la résolution suit cette règle pour ces noms, ni "
                + "sa précédence face à la liste de serveurs de la carte : la règle est relevée "
                + "telle quelle. À vérifier à la main.",
            ],
            NrptDetails(rule));
    }

    /// <summary>
    /// Which of the two stores a rule was read from, in words — load-bearing and not
    /// decoration.
    ///
    /// <para>
    /// The local store is opened only when the policy store fails to open, so a report handing
    /// over two server lists without saying where each came from would leave its reader unable
    /// to tell which one applies. Read off the key path, which is where the store already is,
    /// rather than carried in a field of its own that a replay could lose.
    /// </para>
    ///
    /// <para>
    /// The third branch is not dead weight: a capture written by a later version may hold a
    /// store this one does not name, and calling that rule « local » would be a claim about
    /// precedence that nothing read. The <see cref="Finding.Source"/> carries the path either
    /// way.
    /// </para>
    /// </summary>
    private static string StoreOf(DnsInterface rule) =>
        rule.Id.StartsWith(RegistryDnsProvider.PolicyNrptStore, StringComparison.OrdinalIgnoreCase)
            ? "magasin de stratégie"
            : rule.Id.StartsWith(
                RegistryDnsProvider.LocalNrptStore, StringComparison.OrdinalIgnoreCase)
                ? "magasin local"
                : "magasin que cette version ne sait pas nommer";

    /// <summary>
    /// What the reader needs beside a rule's addresses — and <b>no stack row</b>, which is the
    /// whole point of writing this instead of reusing <see cref="Details"/>.
    ///
    /// <para>
    /// A rule belongs to neither stack: it carries one server list, and one list may hold both
    /// address families. <see cref="DnsInterface.Stack"/> therefore holds its zero member on
    /// such a record, and letting that reach a report would print « pile : IPv4 » over something
    /// nothing read a stack for — the silent label #196 refused when it kept « statique » away
    /// from the level above the cards. <c>DnsResolverTests</c> states it rather than this
    /// paragraph.
    /// </para>
    ///
    /// <para>
    /// <see cref="FindingDetails.Place"/> goes with it, and not by oversight: it names the row
    /// that tells two findings under one source apart, and a rule's source is its own key path —
    /// already one place. Naming a row this finding does not carry would point <c>rempart
    /// diff</c> at nothing.
    /// </para>
    ///
    /// <para>
    /// The name spaces are a row only when there are some. A rule with none is reported all the
    /// same — what earns the line is the server list — and the sentence says in words that they
    /// were not read, where an empty row would print a label with nothing after it.
    /// </para>
    /// </summary>
    private static Dictionary<string, string> NrptDetails(DnsInterface rule)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["origine"] = "règle de résolution de noms (NRPT)",
            ["résolveurs"] = string.Join(", ", rule.StaticServers),
        };

        if (rule.Namespaces.Count > 0)
        {
            details["espaces de noms"] = string.Join(", ", rule.Namespaces);
        }

        return details;
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
    ///
    /// <para>
    /// <b>And named as the coordinate, because a reader was not the only one needing it.</b>
    /// <c>rempart diff</c> folds a disappearance and an appearance at one place into « le même
    /// emplacement lance autre chose », keyed until #195 on the source — which is this
    /// adapter's identifier and designates two places here, one per stack. So a repointed
    /// resolver came out as two unrelated lines on a dual-stack card, and a resolver dropped on
    /// one stack while another was set on the other came out as a substitution that never
    /// happened. <see cref="FindingDetails.Place"/> names the row that tells the two apart
    /// rather than repeating its value, and <c>ScanDiffTests</c> exercises it on the findings
    /// this method builds.
    /// </para>
    ///
    /// <para>
    /// <c>origine</c> says where the addresses come from, and for the stack's own level that is
    /// neither « statique » nor « DHCP » but the level itself: those two words compare a card's
    /// two lists, and one level up there is one list — the other is Windows' own copy of an
    /// adapter's. Writing « statique » there would extend the adapter's judgement in silence,
    /// which is the one thing #196 asked not to do.
    /// </para>
    /// </summary>
    private static Dictionary<string, string> Details(
        DnsInterface iface, string origin, IReadOnlyList<string> servers) =>
        new(StringComparer.Ordinal)
        {
            ["origine"] = origin,
            [FindingDetails.Place] = Stack,
            [Stack] = iface.Stack.ToString(),
            ["résolveurs"] = string.Join(", ", servers),
        };

    /// <summary>
    /// The detail holding the stack, written once: the row and the name of the row have to
    /// stay the same word, and two literals is how they stop being.
    /// </summary>
    private const string Stack = "pile";
}
