using System.Buffers.Binary;
using System.Text;

namespace Rempart.Core.Providers;

/// <summary>
/// Décode le blob binaire <c>WinHttpSettings</c> — le proxy machine posé par
/// <c>netsh winhttp set proxy</c>. En-tête de 12 octets (version, compteur, drapeaux),
/// puis serveur et bypass en chaînes ASCII préfixées de leur longueur, little-endian.
///
/// <para>
/// Pur, testable sans Windows : la couche Windows lui passe les octets lus au registre.
/// Ne lève jamais — un blob tronqué ou corrompu rend un scope désactivé plutôt qu'une
/// exception qui emporterait le scan.
/// </para>
///
/// <para>
/// Format confirmé sur machine réelle (cas « accès direct », sans proxy) :
/// <c>18000000 00000000 01000000 00000000 00000000</c> — version 0x18, compteur, drapeaux
/// 0x01 (direct), longueur serveur 0, longueur bypass 0. Le bit 0x02 des drapeaux marque
/// un proxy configuré ; le serveur suit alors immédiatement l'en-tête, en chaîne préfixée.
/// Le cas « proxy posé » reste à confronter à un vrai <c>netsh winhttp set proxy</c> ; en
/// cas d'écart, la dégradation est sûre (scope désactivé = aucun constat, jamais de faux
/// positif), et le job CI Windows exerce la lecture réelle.
/// </para>
/// </summary>
public static class WinHttpSettingsDecoder
{
    private const uint ProxyConfiguredFlag = 0x2;
    private const int HeaderLength = 12;

    public static ProxyScope Decode(byte[] blob)
    {
        if (blob.Length < HeaderLength + 4)
        {
            return ProxyScope.Disabled;
        }

        var flags = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan()[8..]);
        var offset = HeaderLength;

        var server = ReadPrefixedAscii(blob, ref offset);
        var bypass = ReadPrefixedAscii(blob, ref offset);

        var configured = (flags & ProxyConfiguredFlag) != 0 && server.Length > 0;
        if (!configured)
        {
            return ProxyScope.Disabled;
        }

        return new ProxyScope(
            Enabled: true,
            Server: server,
            AutoConfigUrl: null,   // WinHTTP ne porte pas de PAC.
            Bypass: bypass.Length == 0
                ? []
                : bypass.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// Lit une chaîne préfixée de sa longueur. Rend la chaîne vide sans lever si le blob
    /// est trop court pour la longueur annoncée — un blob corrompu ne doit pas planter.
    /// </summary>
    private static string ReadPrefixedAscii(byte[] blob, ref int offset)
    {
        if (offset + 4 > blob.Length)
        {
            offset = blob.Length;
            return string.Empty;
        }

        var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan()[offset..]);
        offset += 4;

        if (length < 0 || offset + length > blob.Length)
        {
            offset = blob.Length;
            return string.Empty;
        }

        var text = Encoding.ASCII.GetString(blob, offset, length);
        offset += length;
        return text;
    }
}
