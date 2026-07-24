using Rempart.Core.Dns;
using Rempart.Core.Findings;

namespace Rempart.Tests.Unit;

public class DnsWireFormatTests
{
    [Fact]
    public void Build_query_has_a_valid_header_and_question()
    {
        var packet = DnsWireFormat.BuildQuery("example.com", 0xABCD);

        Assert.Equal(0xAB, packet[0]);           // identifier
        Assert.Equal(0xCD, packet[1]);
        Assert.Equal(0x01, packet[2]);           // flags: RD set
        Assert.Equal(1, packet[5]);              // QDCOUNT = 1
        Assert.Equal(7, packet[12]);             // length of the "example" label
        Assert.Equal((byte)'e', packet[13]);
        Assert.Equal(3, packet[20]);             // length of the "com" label
        Assert.Equal(0, packet[24]);             // root
        Assert.Equal(1, packet[26]);             // QTYPE = A
        Assert.Equal(1, packet[28]);             // QCLASS = IN
        Assert.Equal(29, packet.Length);
    }

    [Fact]
    public void A_response_with_matching_id_and_qr_bit_is_valid()
    {
        var query = DnsWireFormat.BuildQuery("example.com", 0x1234);
        var response = (byte[])query.Clone();
        response[2] = 0x81;   // QR bit set

        Assert.True(DnsWireFormat.IsValidResponse(query, response));
    }

    [Fact]
    public void A_response_with_a_different_id_is_invalid()
    {
        var query = DnsWireFormat.BuildQuery("example.com", 0x1234);
        var response = (byte[])query.Clone();
        response[0] ^= 0xFF;
        response[2] = 0x81;

        Assert.False(DnsWireFormat.IsValidResponse(query, response));
    }

    [Fact]
    public void A_query_echoed_without_the_qr_bit_is_not_a_response()
    {
        var query = DnsWireFormat.BuildQuery("example.com", 0x1234);

        Assert.False(DnsWireFormat.IsValidResponse(query, query));
    }

    [Fact]
    public void A_truncated_response_is_invalid_and_does_not_throw() =>
        Assert.False(DnsWireFormat.IsValidResponse(DnsWireFormat.BuildQuery("x", 1), [0, 1, 2]));
}

internal sealed class FakeDnsProbe(params DnsProbeResult[] results) : IDnsProbe
{
    public IReadOnlyList<DnsProbeResult> Probe() => results;
}

public class DnsProbeAnalysisTests
{
    private static DnsProbeResult Ok(string resolver, DnsProbeProtocol protocol, int ms) =>
        new(resolver, protocol, true, ms, null);

    private static DnsProbeResult Down(string resolver, DnsProbeProtocol protocol) =>
        new(resolver, protocol, false, null, "bloqué");

    [Fact]
    public void The_fastest_reachable_resolver_is_recommended()
    {
        var (report, findings) = DnsProbeAnalysis.Analyse(
        [
            Ok("Cloudflare", DnsProbeProtocol.DoH, 30),
            Ok("Google", DnsProbeProtocol.DoT, 12),
            Ok("Quad9", DnsProbeProtocol.DoH, 45),
        ]);

        Assert.Equal("Google", report.RecommendedResolver);
        Assert.Equal(DnsProbeProtocol.DoT, report.RecommendedProtocol);
        Assert.Equal(12, report.RecommendedLatencyMs);
        Assert.Empty(findings);
    }

    [Fact]
    public void All_encrypted_dns_blocked_is_a_suspicious_finding()
    {
        var (report, findings) = DnsProbeAnalysis.Analyse(
        [
            Down("Cloudflare", DnsProbeProtocol.DoH),
            Down("Cloudflare", DnsProbeProtocol.DoT),
        ]);

        Assert.Null(report.RecommendedResolver);
        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Equal("dns-encrypted", finding.Kind);
    }

    [Fact]
    public void A_fully_blocked_protocol_is_a_notable_finding()
    {
        var (report, findings) = DnsProbeAnalysis.Analyse(
        [
            Ok("Cloudflare", DnsProbeProtocol.DoH, 20),
            Down("Cloudflare", DnsProbeProtocol.DoT),
            Down("Google", DnsProbeProtocol.DoT),
        ]);

        Assert.Equal("Cloudflare", report.RecommendedResolver);   // DoH still gets through
        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("DoT", finding.Target);
    }
}
