namespace Rempart.Core.Dns;

/// <summary>The two encrypted DNS transports probed.</summary>
public enum DnsProbeProtocol
{
    /// <summary>DNS over HTTPS (RFC 8484), <c>/dns-query</c> as <c>application/dns-message</c>.</summary>
    DoH,

    /// <summary>DNS over TLS (RFC 7858), port 853.</summary>
    DoT,
}

/// <summary>The result of one probe against a resolver, for one protocol.</summary>
public sealed record DnsProbeResult(
    string Resolver,
    DnsProbeProtocol Protocol,
    bool Reachable,
    int? LatencyMs,
    string? Error);

/// <summary>A known encrypted resolver — its name and the host serving DoH and DoT.</summary>
public sealed record EncryptedResolver(string Name, string Host);

/// <summary>
/// Active probe of encrypted DNS resolvers. Abstracted like the rest (ADR-001, D5): the
/// ranking and the findings are tested against given results, without network access.
/// </summary>
public interface IDnsProbe
{
    IReadOnlyList<DnsProbeResult> Probe();
}

/// <summary>
/// Widespread privacy-oriented resolvers, each exposing DoH (<c>/dns-query</c>) and DoT (853).
/// The list does not claim to be exhaustive, only to cover the most common legitimate
/// choices — like the known-resolver list of the DNS collector.
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
