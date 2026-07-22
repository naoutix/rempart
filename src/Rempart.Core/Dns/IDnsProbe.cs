namespace Rempart.Core.Dns;

/// <summary>Les deux transports DNS chiffrés sondés.</summary>
public enum DnsProbeProtocol
{
    /// <summary>DNS over HTTPS (RFC 8484), <c>/dns-query</c> en <c>application/dns-message</c>.</summary>
    DoH,

    /// <summary>DNS over TLS (RFC 7858), port 853.</summary>
    DoT,
}

/// <summary>Résultat d'une sonde vers un résolveur, pour un protocole.</summary>
public sealed record DnsProbeResult(
    string Resolver,
    DnsProbeProtocol Protocol,
    bool Reachable,
    int? LatencyMs,
    string? Error);

/// <summary>Un résolveur chiffré connu — son nom et l'hôte servant DoH et DoT.</summary>
public sealed record EncryptedResolver(string Name, string Host);

/// <summary>
/// Sonde active des résolveurs DNS chiffrés. Abstrait comme le reste (ADR-001, D5) : le
/// classement et les constats se testent sur des résultats donnés, sans réseau.
/// </summary>
public interface IDnsProbe
{
    IReadOnlyList<DnsProbeResult> Probe();
}

/// <summary>
/// Résolveurs vie-privée répandus, chacun exposant DoH (<c>/dns-query</c>) et DoT (853).
/// La liste ne prétend pas à l'exhaustivité, seulement à couvrir les choix légitimes les
/// plus fréquents — comme la liste de résolveurs connus du collecteur DNS.
/// </summary>
public static class KnownResolvers
{
    public static readonly IReadOnlyList<EncryptedResolver> All =
    [
        new("Cloudflare", "cloudflare-dns.com"),
        new("Google", "dns.google"),
        new("Quad9", "dns.quad9.net"),
    ];
}
