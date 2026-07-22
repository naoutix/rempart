using System.Buffers.Binary;

namespace Rempart.Core.Dns;

/// <summary>
/// Construit une requête DNS au format wire (RFC 1035) et valide une réponse.
///
/// <para>
/// Le même paquet sert DoT (envoyé sur une socket TLS, préfixé de sa longueur) et DoH
/// (posté en <c>application/dns-message</c>, RFC 8484). Pur, sans réflexion — AOT-safe.
/// </para>
/// </summary>
public static class DnsWireFormat
{
    /// <summary>Requête A pour <paramref name="name"/>, récursion demandée.</summary>
    public static byte[] BuildQuery(string name, ushort id)
    {
        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var qnameLength = labels.Sum(label => label.Length + 1) + 1;   // chaque label préfixé + racine
        var packet = new byte[12 + qnameLength + 4];
        var span = packet.AsSpan();

        BinaryPrimitives.WriteUInt16BigEndian(span, id);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], 0x0100);   // drapeaux : requête standard, RD
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1);        // QDCOUNT = 1
        // ANCOUNT / NSCOUNT / ARCOUNT restent à 0.

        var offset = 12;
        foreach (var label in labels)
        {
            packet[offset++] = (byte)Math.Min(label.Length, 63);
            foreach (var c in label)
            {
                packet[offset++] = (byte)c;
            }
        }

        packet[offset++] = 0;   // racine

        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1);   // QTYPE = A
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1);   // QCLASS = IN

        return packet;
    }

    /// <summary>
    /// Vrai si <paramref name="response"/> est une réponse DNS au même identifiant que
    /// <paramref name="query"/> — assez pour attester qu'un résolveur a répondu. Ne lève
    /// jamais : un paquet tronqué rend simplement <c>false</c>.
    /// </summary>
    public static bool IsValidResponse(byte[] query, byte[] response)
    {
        if (query.Length < 12 || response.Length < 12)
        {
            return false;
        }

        // Même identifiant (2 premiers octets) et bit QR (réponse) posé.
        return response[0] == query[0]
            && response[1] == query[1]
            && (response[2] & 0x80) != 0;
    }
}
