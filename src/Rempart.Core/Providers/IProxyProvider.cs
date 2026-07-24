namespace Rempart.Core.Providers;

/// <summary>
/// Proxy configuration for one scope (per-user WinINET, or machine-wide WinHTTP).
///
/// <para>
/// Distinct from DNS but similar in kind: a proxy imposed by group policy is the
/// expected enterprise case; a proxy or PAC set without such a constraint is a
/// deliberate choice — or an implant. An AutoConfigURL (PAC) rewrites all of the
/// machine's routing, a known hijacking technique.
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

/// <summary>All proxy scopes of the machine, already decoded.</summary>
public sealed record ProxyConfiguration(
    ProxyScope WinInet,
    ProxyScope WinHttp,
    bool PolicyImposed)
{
    public static readonly ProxyConfiguration Empty =
        new(ProxyScope.Disabled, ProxyScope.Disabled, false);
}

/// <summary>
/// Returns the proxy configuration, already decoded. Abstracted like the rest
/// (ADR-001, D5): the judgment is tested against a given config, without registry or
/// machine.
/// </summary>
public interface IProxyProvider
{
    ProxyConfiguration Read();
}
