namespace Rempart.Core.Providers;

/// <summary>
/// La configuration de résolution DNS d'une interface réseau.
///
/// <para>
/// La distinction qui compte : un résolveur reçu du DHCP est celui du réseau, subi ;
/// un résolveur posé <b>statiquement</b> est un choix — ou une greffe. Le détournement
/// DNS opère précisément là, en écrivant un serveur qu'il contrôle par-dessus celui du
/// réseau, pour rediriger silencieusement la résolution de noms.
/// </para>
/// </summary>
public sealed record DnsInterface(
    string Id,
    IReadOnlyList<string> StaticServers,
    IReadOnlyList<string> DhcpServers);

/// <summary>
/// Énumère la configuration DNS par interface.
///
/// Abstrait comme le reste (ADR-001, D5) : le jugement — un résolveur statique inconnu,
/// vecteur de détournement — se teste sur une liste donnée, sans carte réseau.
/// </summary>
public interface IDnsProvider
{
    IReadOnlyList<DnsInterface> Read();
}
