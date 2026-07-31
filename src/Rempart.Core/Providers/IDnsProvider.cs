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
/// The DNS resolution configuration of a network interface, on one stack.
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
/// </summary>
public sealed record DnsInterface(
    string Id,
    IReadOnlyList<string> StaticServers,
    IReadOnlyList<string> DhcpServers,
    DnsStack Stack);

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
/// </summary>
public sealed record DnsRead(
    ReadStatus Status,
    IReadOnlyList<DnsInterface> Interfaces,
    string? Diagnostic = null)
    : IStatusCarryingRead<DnsRead, DnsInterface>
{
    /// <summary>
    /// No stack keeps its interfaces where this read looks. An answer and not a hole: it
    /// is what a registry holding no TCP/IP stack says, and nothing resolves through an
    /// interface that was never configured.
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
    /// Takes what the other keys gave, so the refusal costs nothing that was read: the
    /// enumeration of the interfaces and the two values of each interface are separate reads,
    /// so a denial on one adapter must not drop the resolver of the one next to it. Partial by
    /// design, like <see cref="ScheduledTaskRead"/> and for its reason — and the total case is
    /// the same statement with an empty list, which is why there is one factory and not two.
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
            + ". Un résolveur posé sur une de ces interfaces n'apparaît pas dans ce rapport.");

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
