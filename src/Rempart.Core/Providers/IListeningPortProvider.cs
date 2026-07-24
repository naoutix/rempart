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
/// Enumerates TCP and UDP listening endpoints.
///
/// Abstracted like the rest (ADR-001, D5): the judgment — an unsigned binary exposing a
/// port on all interfaces — is tested against a given list, without opening a real
/// socket.
/// </summary>
public interface IListeningPortProvider
{
    IReadOnlyList<ListeningPort> Enumerate();
}
