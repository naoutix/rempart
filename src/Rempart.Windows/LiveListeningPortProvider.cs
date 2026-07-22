using System.Globalization;
using System.Runtime.InteropServices;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Énumère les points d'écoute TCP et UDP via <c>iphlpapi</c>.
///
/// <para>
/// <c>GetExtendedTcpTable</c> rend une table à taille variable, comme les pilotes : on
/// demande d'abord la taille, on alloue, on relit. Le tampon est parcouru par décalages
/// plutôt que par une structure marshalée — le même choix que pour l'énumération des
/// pilotes, où un marshalling généré avait rendu un tampon vide en silence.
/// </para>
///
/// <para>
/// TCP en classe « listener » : Windows ne rend alors que les sockets en écoute, pas les
/// connexions établies. UDP n'a pas d'état — tout socket UDP ouvert « écoute ».
/// </para>
/// </summary>
public sealed partial class LiveListeningPortProvider : IListeningPortProvider
{
    private const uint AfInet = 2;
    private const int TcpTableOwnerPidListener = 3;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

    /// <summary>
    /// Une table MIB se lit en deux temps : un premier appel rend la taille nécessaire,
    /// le second remplit le tampon. La taille voyage par <c>ref</c> — un <c>Func</c> ne
    /// sait pas la porter, d'où ce délégué dédié.
    /// </summary>
    private delegate uint TableCall(IntPtr table, ref uint size);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(
        IntPtr table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order,
        uint af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(
        IntPtr table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order,
        uint af, int tableClass, uint reserved);

    public IReadOnlyList<ListeningPort> Enumerate()
    {
        var ports = new List<ListeningPort>();
        ReadTable(ports, "TCP", rowSize: 24, portOffset: 8, addrOffset: 4, pidOffset: 20,
            (IntPtr buffer, ref uint size) => GetExtendedTcpTable(buffer, ref size, false,
                AfInet, TcpTableOwnerPidListener, 0));
        ReadTable(ports, "UDP", rowSize: 12, portOffset: 4, addrOffset: 0, pidOffset: 8,
            (IntPtr buffer, ref uint size) => GetExtendedUdpTable(buffer, ref size, false,
                AfInet, UdpTableOwnerPid, 0));
        return ports;
    }

    /// <summary>
    /// Une table MIB partage la même forme : un compteur d'entrées sur quatre octets,
    /// puis les lignes. Seuls la taille d'une ligne et les décalages de ses champs
    /// changent entre TCP et UDP.
    /// </summary>
    private static void ReadTable(
        List<ListeningPort> ports, string protocol,
        int rowSize, int portOffset, int addrOffset, int pidOffset,
        TableCall call)
    {
        uint size = 0;

        // Premier appel : le tampon vide sert à obtenir la taille nécessaire.
        if (call(IntPtr.Zero, ref size) != ErrorInsufficientBuffer || size == 0)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (call(buffer, ref size) != 0)
            {
                return;
            }

            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
            {
                var row = 4 + (i * rowSize);
                if (row + rowSize > size)
                {
                    break;
                }

                var address = FormatAddress(Marshal.ReadInt32(buffer, row + addrOffset));
                var port = FormatPort(Marshal.ReadInt32(buffer, row + portOffset));
                var pid = Marshal.ReadInt32(buffer, row + pidOffset);

                ports.Add(new ListeningPort(protocol, address, port, pid));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Un DWORD IPv4 en octets réseau devient <c>a.b.c.d</c>.</summary>
    private static string FormatAddress(int raw) =>
        string.Create(CultureInfo.InvariantCulture, stackalloc char[15],
            $"{raw & 0xFF}.{(raw >> 8) & 0xFF}.{(raw >> 16) & 0xFF}.{(raw >> 24) & 0xFF}");

    /// <summary>
    /// Le port occupe le mot bas en octets réseau : l'octet de poids fort d'abord. On
    /// remet donc les deux octets dans l'ordre.
    /// </summary>
    private static int FormatPort(int raw) =>
        ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
}
