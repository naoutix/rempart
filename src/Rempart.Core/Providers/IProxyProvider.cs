namespace Rempart.Core.Providers;

/// <summary>
/// Configuration proxy d'une portée (par utilisateur WinINET, ou machine WinHTTP).
///
/// <para>
/// Distincte du DNS mais de même esprit : un proxy imposé par stratégie de groupe est le
/// cas d'entreprise attendu, un proxy ou un PAC posé sans contrainte est un choix — ou une
/// greffe. Un AutoConfigURL (PAC) réécrit tout le routage de la machine, technique de
/// détournement connue.
/// </para>
/// </summary>
public sealed record ProxyScope(
    bool Enabled,
    string? Server,
    string? AutoConfigUrl,
    IReadOnlyList<string> Bypass)
{
    public static readonly ProxyScope Disabled = new(false, null, null, []);
}

/// <summary>Toutes les portées proxy de la machine, déjà décodées.</summary>
public sealed record ProxyConfiguration(
    ProxyScope WinInet,
    ProxyScope WinHttp,
    bool PolicyImposed)
{
    public static readonly ProxyConfiguration Empty =
        new(ProxyScope.Disabled, ProxyScope.Disabled, false);
}

/// <summary>
/// Rend la configuration proxy déjà décodée. Abstrait comme le reste (ADR-001, D5) : le
/// jugement se teste sur une config donnée, sans registre ni machine.
/// </summary>
public interface IProxyProvider
{
    ProxyConfiguration Read();
}
