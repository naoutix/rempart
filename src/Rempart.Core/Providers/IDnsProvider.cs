namespace Rempart.Core.Providers;

/// <summary>
/// The DNS resolution configuration of a network interface.
///
/// <para>
/// The distinction that matters: a resolver received from DHCP comes from the network
/// and is not chosen; a <b>statically</b> set resolver is a deliberate choice — or an
/// implant. DNS hijacking operates exactly there, writing a server it controls over the
/// network's one to silently redirect name resolution.
/// </para>
/// </summary>
public sealed record DnsInterface(
    string Id,
    IReadOnlyList<string> StaticServers,
    IReadOnlyList<string> DhcpServers);

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
/// </summary>
public sealed record DnsRead(
    ReadStatus Status,
    IReadOnlyList<DnsInterface> Interfaces,
    string? Diagnostic = null)
    : IStatusCarryingRead<DnsRead, DnsInterface>
{
    /// <summary>
    /// The key Windows keeps its interfaces under is not there. An answer and not a hole: it
    /// is what a registry holding no TCP/IP stack says, and nothing resolves through an
    /// interface that was never configured.
    /// </summary>
    public static readonly DnsRead Absent = new(ReadStatus.NotFound, []);

    public static DnsRead Found(IReadOnlyList<DnsInterface> interfaces) =>
        new(ReadStatus.Found, interfaces);

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
