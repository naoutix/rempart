namespace Rempart.Core.Providers;

/// <summary>
/// One of the TCP/IP stacks Windows keeps a resolver list of its own for.
///
/// <para>
/// Windows binds two stacks to the same adapter and gives each its own service key —
/// <c>Tcpip</c> and <c>Tcpip6</c> — with its own <c>Parameters\Interfaces</c> subtree under it,
/// keyed by the same adapter GUID. So the same network card carries two resolver lists, set by
/// two different commands (<c>netsh interface ipv4</c> and <c>netsh interface ipv6</c>), and
/// nothing in one of them says anything about the other.
/// </para>
///
/// <para>
/// <b>It exists so that the read cannot be written for one stack.</b> Until #191 the key was a
/// single constant and the second stack appeared nowhere in the repository at all: a resolver
/// laid on it was not collected, not judged, and not reported as uncollected. A constant per
/// stack would have been the same defect one line longer — what stops it is that this enum is
/// what <see cref="RegistryDnsProvider.Stacks"/> is indexed by and what the read loops over, so
/// a stack that exists is a stack that is walked.
/// </para>
///
/// <para>
/// <see cref="IPv4"/> is first, and that is load-bearing rather than alphabetical: a capture
/// taken before this field carries no <c>stack</c>, deserialises to the default member, and
/// every interface such a capture holds was read from <c>Tcpip</c> — so the default has to be
/// the stack those captures were read on. <c>DnsHostsTests</c> asserts it on the value.
/// </para>
/// </summary>
public enum DnsStack
{
    /// <summary>The IPv4 stack, under <c>Tcpip</c> — the only one read before #191.</summary>
    IPv4,

    /// <summary>
    /// The IPv6 stack, under <c>Tcpip6</c>. Not an exotic configuration: the machine this was
    /// written on keeps ten adapters there and resolves names through a DHCPv6-supplied server,
    /// nobody having configured anything for IPv6 on it.
    /// </summary>
    IPv6,
}

/// <summary>
/// Which level of a stack a resolver list was read from.
///
/// <para>
/// A stack keeps resolver lists at two levels, not one: under each adapter, and on the
/// service's own <c>Parameters</c> key above them — the same two value names in both places.
/// Until #196 only the lower one was read, on both stacks alike.
/// </para>
///
/// <para>
/// <b>The two levels are not judged alike, and this member is what keeps them apart at the
/// place the judgement is made.</b> Under an adapter, « statique » against « DHCP » is a real
/// distinction and a common configuration: a resolver typed on to a card is a deliberate act,
/// and one that is a recognised public resolver is an ordinary hardening choice. At the level
/// of the stack neither half of that holds — measurement in
/// <see cref="RegistryDnsProvider"/> — so the collector states what it saw and explicitly
/// does not call it an active resolver.
/// </para>
///
/// <para>
/// A capture taken before this field carries no <c>scope</c>, and it has to come back
/// <see cref="Adapter"/>: every record such a capture holds was read from an adapter key, that
/// read having opened nothing else. <c>DnsHostsTests</c> asserts that on the <em>value</em>,
/// never on the key being absent (#163).
/// </para>
///
/// <para>
/// <b>Two mechanisms could decide it, and they are made to agree — which is a correction and
/// not a belt.</b> <see cref="DnsStack.IPv4"/> is load-bearing by being the zero member, and
/// the same sentence written here was false: the serialiser honours the constructor default of
/// <see cref="DnsInterface.Scope"/> for a property a document does not carry, so reordering
/// this enum left the compatibility test green — measured, by doing it. Being the zero member
/// as well costs nothing and is what answers if that default is ever dropped or the serialiser
/// stops reading it, so the test pins both.
/// </para>
/// </summary>
public enum DnsScope
{
    /// <summary>
    /// One network card's own list, under <c>{stack}\Parameters\Interfaces\{guid}</c> — the
    /// only level read before #196, and what every capture written before it holds.
    /// </summary>
    Adapter,

    /// <summary>
    /// The stack's own <c>Parameters</c> key, above the adapters. Read for
    /// <c>NameServer</c> only, and reported as an observation rather than as a resolver: see
    /// <see cref="RegistryDnsProvider"/> for what was measured and what was not.
    /// </summary>
    Stack,

    /// <summary>
    /// One rule of the name resolution policy table — a subkey of one of the two
    /// <c>DnsPolicyConfig</c> stores, carrying its own server list and the name spaces it
    /// claims. Appended after <see cref="Stack"/> so that <see cref="Adapter"/> stays the zero
    /// member, which is what a capture written before either level replays as.
    ///
    /// <para>
    /// <b>The one scope for which <see cref="DnsInterface.Stack"/> says nothing</b>, and the
    /// reason that field is documented as unread here rather than quietly carried: a rule's
    /// server list is one list and may hold both address families at once, so a rule belongs to
    /// neither stack. <see cref="Findings.DnsResolverCollector"/> prints no stack row for a
    /// record of this scope, and <c>DnsResolverTests</c> holds it to that — the alternative,
    /// letting the zero member reach a report, would write « pile IPv4 » over a rule nothing
    /// read a stack for.
    /// </para>
    /// </summary>
    NrptRule,
}

/// <summary>
/// The DNS resolution configuration read at one place of one stack — a network card, or the
/// stack's own level above the cards.
///
/// <para>
/// The distinction that matters: a resolver received from DHCP comes from the network
/// and is not chosen; a <b>statically</b> set resolver is a deliberate choice — or an
/// implant. DNS hijacking operates exactly there, writing a server it controls over the
/// network's one to silently redirect name resolution.
/// </para>
///
/// <para>
/// One record per (interface, stack) pair and not per interface: an adapter carries the same
/// GUID under both stacks and a different resolver list on each, so folding the two would
/// either lose one list or attribute an address to the stack it is not on — and the stack is
/// what decides which command undoes it.
/// </para>
///
/// <para>
/// <b>The name says « interface » and one record per stack is not one</b>, which is a wart
/// kept on purpose: this list is what a capture stores under <c>dns</c>, and it is the only
/// place a new level could ride without turning that JSON array into an object — the change
/// this repository has refused five times because it makes every capture ever taken
/// unreadable, the real-machine ones outside the repository included.
/// <see cref="Scope"/> says which level the record came from, and
/// <see cref="Id"/> follows it: an adapter GUID for a card, the registry key path for the
/// stack's own level, and the rule's full key path — store included — for a name resolution
/// policy rule (#199).
/// </para>
///
/// <para>
/// <b><see cref="Stack"/> is read only where a scope names a stack.</b> A record of
/// <see cref="DnsScope.NrptRule"/> belongs to neither stack — one server list, both families
/// allowed in it — and carries the zero member because the field is not nullable and making it
/// so would take the default a capture written before #191 replays on
/// (<see cref="DnsStack.IPv4"/>, asserted on the value) with it. So the guard is at the reader:
/// <see cref="Findings.DnsResolverCollector"/> writes no stack row for such a record, and a test
/// states that rather than this paragraph. It is the same shape as <see cref="DhcpServers"/> one
/// level up, which is empty because that half is unread and never because the machine has none.
/// </para>
/// </summary>
public sealed record DnsInterface(
    string Id,
    IReadOnlyList<string> StaticServers,
    IReadOnlyList<string> DhcpServers,
    DnsStack Stack,
    DnsScope Scope = DnsScope.Adapter)
{
    /// <summary>
    /// The name spaces this record claims — the <c>Name</c> of an NRPT rule, and empty
    /// everywhere else.
    ///
    /// <para>
    /// A property rather than a sixth positional parameter, because <c>[]</c> is no constant and
    /// a positional default has to be one: the manoeuvre <see cref="Scope"/> used could not be
    /// repeated verbatim for a list.
    /// </para>
    ///
    /// <para>
    /// <b>And the accessor is where the empty list is decided, which is a correction and not a
    /// belt.</b> The initialiser alone reads as though it answered a document that carries no
    /// <c>namespaces</c> — it does not, and the difference was measured by shipping it: the
    /// source-generated serialiser can only reach an <c>init</c> property through an object
    /// initialiser, so it builds the record with <em>every</em> such property assigned, handing
    /// <c>default</c> for the ones the document did not carry. A positional parameter is not
    /// like that, which is why <see cref="Scope"/> could rely on its default and this cannot.
    /// The replay of two versioned fixtures came back holding <c>null</c> here, and every reader
    /// of the field threw. So the <c>init</c> accessor refuses the null, the initialiser answers
    /// anything that reaches the record without naming the field, and <c>DnsHostsTests</c>
    /// asserts the result on the <em>value</em> and never on the key being absent (#163).
    /// </para>
    ///
    /// <para>
    /// <b>The one field of this record that carries machine text</b>, and therefore the one that
    /// had to be anonymised in the same commit that added it: a rule's name space is typically
    /// the organisation's internal domain. Until #199 the DNS block held adapter GUIDs, registry
    /// key paths and IP addresses, which name nobody — which is why
    /// <see cref="Snapshots.Anonymiser"/> touched only its diagnostic, and why that reasoning
    /// stopped being true here.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> Namespaces
    {
        get => namespaces;
        init => namespaces = value ?? [];
    }

    private readonly IReadOnlyList<string> namespaces = [];
}

/// <summary>
/// The interfaces that resolve, plus whether they could be enumerated at all.
///
/// <para>
/// <b>An empty list here stays an answer</b>, and that judgement is unchanged: a machine with
/// no configured network interface exists, and every adapter that resolves nothing is left out
/// on purpose by <see cref="RegistryDnsProvider"/>. What was folded into that answer, and had
/// nothing to do with it, is the <em>refusal</em>: the interfaces live under a registry key
/// like any other, <c>ListSubKeys</c> has been able to say « refusé » since REV-11, and this
/// read had nowhere to put it — so an ACL on <c>Tcpip\Parameters\Interfaces</c> produced zero
/// resolver, zero finding, and a report that reads like a machine with nothing to say. Denying
/// the enumeration is a cheaper way to hide a hijacked resolver than removing it (#184).
/// </para>
///
/// <para>
/// One list for both stacks, each interface saying which one it came from
/// (<see cref="DnsInterface.Stack"/>), and one status over the two: what the refusal names is
/// the <em>keys</em> it was refused, so an ACL on <c>Tcpip6</c> alone is as legible as one on
/// <c>Tcpip</c> alone, and what the other stack gave travels beside it — the same shape as the
/// adapter next door, one level up (#191).
/// </para>
///
/// <para>
/// One list for both <em>levels</em> too, since #196, and for the rules of the name resolution
/// policy table since #199: a record says which of the three it is through
/// <see cref="DnsInterface.Scope"/> and rides here rather than in a field of its own. Not for
/// want of a better shape — a field beside the list is what this read would want — but because a
/// capture stores this list as a JSON array and rebuilds the read from three values
/// (<see cref="StatusChannel"/>), so a fourth would be written and silently dropped on the way
/// back in.
/// </para>
/// </summary>
public sealed record DnsRead(
    ReadStatus Status,
    IReadOnlyList<DnsInterface> Interfaces,
    string? Diagnostic = null)
    : IStatusCarryingRead<DnsRead, DnsInterface>
{
    /// <summary>
    /// Nothing this read walks answered anything — neither level of either stack, nor either
    /// name resolution policy store. An answer and not a hole: it is what a registry holding no
    /// TCP/IP stack says, and nothing resolves through an interface that was never configured.
    ///
    /// <para>
    /// Every surface, and that is load-bearing rather than tidy: this constant carries an
    /// <em>empty</em> list, so a read that found something on a surface its « something
    /// answered » flag ignored would put it in a list and drop it on the way out.
    /// <c>RegistryDnsProviderTests</c> stages each surface alone against a registry answering
    /// « cette clé n'existe pas » everywhere else.
    /// </para>
    ///
    /// <para>
    /// Every declared stack, and not one of them: a machine with <c>Tcpip6</c> unbound and
    /// <c>Tcpip</c> answering has been read, so it is <see cref="Found"/> with what the one
    /// stack gave. Absence <em>per stack</em> is silent for the reason emptiness is —
    /// reporting it would put a gap on the ordinary machine.
    /// </para>
    /// </summary>
    public static readonly DnsRead Absent = new(ReadStatus.NotFound, []);

    public static DnsRead Found(IReadOnlyList<DnsInterface> interfaces) =>
        new(ReadStatus.Found, interfaces);

    /// <summary>
    /// Nobody walked the stacks: no provider was wired, or the capture being replayed holds no
    /// DNS block at all. Not <see cref="Absent"/>, which is the machine's own answer — the
    /// difference is « personne n'a regardé » against « j'ai regardé et il n'y a rien », and
    /// only the second is a state a report may print (#192).
    ///
    /// <para>
    /// Elevation is not the answer and the status says so: no privilege wires a provider, and
    /// no console however elevated re-reads a snapshot.
    /// <see cref="Findings.DnsResolverCollector"/> reads it as <c>AuditGap.Unreadable</c> — exit 5,
    /// « non déterminé » — and the comment there had already written down that this state was
    /// reachable from a capture before any factory could build it.
    /// </para>
    /// </summary>
    /// <param name="reason">What was not read, in French — it reaches the report.</param>
    public static DnsRead Failed(string reason) => new(ReadStatus.Failed, [], reason);

    /// <summary>
    /// One or more of the keys this read walks was denied. Elevation is the answer.
    ///
    /// <para>
    /// Takes what the other keys gave, so the refusal costs nothing that was read: the stack's
    /// own value, the enumeration of the interfaces, the two values of each interface, the
    /// enumeration of each policy store and the values of each rule in it are separate reads, so
    /// a denial on one must not drop what the others gave. Partial by design, like
    /// <see cref="ScheduledTaskRead"/> and for its reason — and the total case is the same
    /// statement with an empty list, which is why there is one factory and not two.
    /// </para>
    /// </summary>
    /// <param name="denied">
    /// The registry paths that answered « refusé », named so the reader knows what the hole
    /// covers. Only a genuine denial comes through here: <see cref="IRegistryProvider"/>
    /// catches the two denial exceptions and lets every other failure through, so there is no
    /// failure on this channel that could be mistaken for one.
    /// </param>
    public static DnsRead Refused(
        IReadOnlyList<DnsInterface> interfaces, IReadOnlyList<string> denied) =>
        new(ReadStatus.AccessDenied, interfaces,
            $"Lecture DNS refusée sur {denied.Count} clé(s) : "
            + string.Join(", ", denied.Distinct(StringComparer.Ordinal))
            + ". Un résolveur posé à un de ces emplacements n'apparaît pas dans ce rapport.");

    // Explicit, so "Interfaces" stays the only name a caller sees and nothing new appears in
    // any serialised shape. See IStatusCarryingRead.
    IReadOnlyList<DnsInterface> IStatusCarryingRead<DnsRead, DnsInterface>.Items => Interfaces;

    static DnsRead IStatusCarryingRead<DnsRead, DnsInterface>.Compose(
        ReadStatus status, IReadOnlyList<DnsInterface> items, string? diagnostic) =>
        new(status, items, diagnostic);
}

/// <summary>
/// Enumerates the DNS configuration per interface.
///
/// Abstracted like the rest (ADR-001, D5): the judgment — an unknown static resolver,
/// a hijacking vector — is tested against a given list, without a network adapter.
/// </summary>
public interface IDnsProvider
{
    DnsRead Read();
}
