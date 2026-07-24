using System.Buffers.Binary;
using System.Text;

namespace Rempart.Core.Providers;

/// <summary>
/// Decodes the <c>WinHttpSettings</c> binary blob — the machine proxy set by
/// <c>netsh winhttp set proxy</c>. 12-byte header (version, counter, flags), then
/// server and bypass as length-prefixed ASCII strings, little-endian.
///
/// <para>
/// Pure, testable without Windows: the Windows layer passes it the bytes read from the
/// registry. Never throws — a truncated or corrupted blob yields a disabled scope
/// rather than an exception that would take down the scan.
/// </para>
///
/// <para>
/// Format confirmed on a real machine ("direct access" case, no proxy):
/// <c>18000000 00000000 01000000 00000000 00000000</c> — version 0x18, counter, flags
/// 0x01 (direct), server length 0, bypass length 0. Flag bit 0x02 marks a configured
/// proxy; the server then immediately follows the header, as a length-prefixed string.
/// The "proxy set" case still has to be checked against a real
/// <c>netsh winhttp set proxy</c>; if it differs, the degradation is safe (disabled
/// scope = no finding, never a false positive), and the Windows CI job exercises the
/// real read.
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
            AutoConfigUrl: null,   // WinHTTP does not carry a PAC.
            Bypass: bypass.Length == 0
                ? []
                : bypass.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// Reads a length-prefixed string. Returns the empty string without throwing if the
    /// blob is too short for the announced length — a corrupted blob must not crash.
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
