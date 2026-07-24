using System.Buffers.Binary;

namespace Rempart.Core.Dns;

/// <summary>
/// Builds a DNS query in wire format (RFC 1035) and validates a response.
///
/// <para>
/// The same packet serves DoT (sent over a TLS socket, length-prefixed) and DoH
/// (posted as <c>application/dns-message</c>, RFC 8484). Pure, no reflection — AOT-safe.
/// </para>
/// </summary>
public static class DnsWireFormat
{
    /// <summary>An A query for <paramref name="name"/>, recursion desired.</summary>
    public static byte[] BuildQuery(string name, ushort id)
    {
        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var qnameLength = labels.Sum(label => label.Length + 1) + 1;   // each label prefixed + root
        var packet = new byte[12 + qnameLength + 4];
        var span = packet.AsSpan();

        BinaryPrimitives.WriteUInt16BigEndian(span, id);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], 0x0100);   // flags: standard query, RD
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1);        // QDCOUNT = 1
        // ANCOUNT / NSCOUNT / ARCOUNT stay at 0.

        var offset = 12;
        foreach (var label in labels)
        {
            packet[offset++] = (byte)Math.Min(label.Length, 63);
            foreach (var c in label)
            {
                packet[offset++] = (byte)c;
            }
        }

        packet[offset++] = 0;   // root

        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1);   // QTYPE = A
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1);   // QCLASS = IN

        return packet;
    }

    /// <summary>
    /// True if <paramref name="response"/> is a DNS response carrying the same identifier
    /// as <paramref name="query"/> — enough to attest that a resolver answered. Never
    /// throws: a truncated packet simply yields <c>false</c>.
    /// </summary>
    public static bool IsValidResponse(byte[] query, byte[] response)
    {
        if (query.Length < 12 || response.Length < 12)
        {
            return false;
        }

        // Same identifier (first 2 bytes) and QR (response) bit set.
        return response[0] == query[0]
            && response[1] == query[1]
            && (response[2] & 0x80) != 0;
    }
}
