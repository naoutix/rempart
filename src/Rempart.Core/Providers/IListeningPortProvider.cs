namespace Rempart.Core.Providers;

/// <summary>
/// A network listening endpoint: a protocol, an address, and a port on which a process
/// waits for connections.
///
/// <para>
/// The bind address is the fact that matters. <c>127.0.0.1</c> (or <c>::1</c>) listens
/// only to the machine itself — a local service, out of the network's reach.
/// <c>0.0.0.0</c> (or <c>::</c>) listens on all interfaces: the service is reachable
/// from outside. Two processes on the same port can have different exposure surfaces
/// based on this address alone.
/// </para>
/// </summary>
public sealed record ListeningPort(string Protocol, string LocalAddress, int Port, int Pid)
{
    /// <summary>
    /// True if the endpoint listens only locally. <c>0.0.0.0</c> and <c>::</c> listen on
    /// all interfaces; a loopback address or a named interface does not expose to the
    /// network the same way — only <c>0.0.0.0</c>/<c>::</c> is general exposure.
    /// </summary>
    public bool IsLoopbackOnly =>
        LocalAddress.StartsWith("127.", StringComparison.Ordinal)
        || LocalAddress == "::1";

    public bool IsAllInterfaces =>
        LocalAddress is "0.0.0.0" or "::";
}

/// <summary>
/// The listening endpoints, plus whether they could be read at all.
///
/// <para>
/// The status is not decoration, and this is the fourth surface to need it (DET-WMI-MUET
/// for drivers and processes, DET-EXT-MUET for browser profiles, DET-PORTS-MUET here).
/// <b>No machine that is switched on listens on zero ports</b> — the RPC endpoint mapper,
/// SMB, the local resolver — so an empty list can only ever be a failed read. Before this
/// record existed the provider returned a bare list, and the report concluded « aucun port
/// en écoute », which reads like good news on the one surface that says what the network
/// can reach.
/// </para>
///
/// <para>
/// The asymmetry with browser extensions is deliberate, and it is the same one phase 2
/// settled: zero extensions is an ordinary state of a machine, so it stays silent; zero
/// ports cannot be true, so it speaks.
/// </para>
/// </summary>
public sealed record ListeningPortRead(
    ReadStatus Status,
    IReadOnlyList<ListeningPort> Ports,
    string? Diagnostic = null)
{
    public static ListeningPortRead Found(IReadOnlyList<ListeningPort> ports) =>
        new(ReadStatus.Found, ports);

    public static ListeningPortRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);

    /// <summary>
    /// What was read, and what could not be — four tables are queried (TCP and UDP, IPv4
    /// and IPv6) and they fail one at a time. The endpoints that were read stay in the
    /// report and the missing table is named beside them: dropping the IPv4 ports because
    /// the IPv6 table refused would trade one silence for another. Same shape as
    /// <see cref="BrowserExtensionRead.Partial"/>.
    /// </summary>
    public static ListeningPortRead Partial(
        IReadOnlyList<ListeningPort> ports, string reason) =>
        new(ReadStatus.AccessDenied, ports, reason);
}

/// <summary>
/// Enumerates TCP and UDP listening endpoints.
///
/// Abstracted like the rest (ADR-001, D5): the judgment — an unsigned binary exposing a
/// port on all interfaces — is tested against a given list, without opening a real
/// socket.
/// </summary>
public interface IListeningPortProvider
{
    ListeningPortRead Enumerate();
}
