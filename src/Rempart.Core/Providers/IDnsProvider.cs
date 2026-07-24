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
/// Enumerates the DNS configuration per interface.
///
/// Abstracted like the rest (ADR-001, D5): the judgment — an unknown static resolver,
/// a hijacking vector — is tested against a given list, without a network adapter.
/// </summary>
public interface IDnsProvider
{
    IReadOnlyList<DnsInterface> Read();
}
