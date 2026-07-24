using System.Globalization;
using System.Runtime.InteropServices;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Enumerates TCP and UDP listening endpoints via <c>iphlpapi</c>.
///
/// <para>
/// <c>GetExtendedTcpTable</c> returns a variable-size table, like the driver APIs: ask
/// for the size first, allocate, then read again. The buffer is walked by offsets
/// rather than through a marshaled struct — the same choice as for driver enumeration,
/// where generated marshalling had silently returned an empty buffer.
/// </para>
///
/// <para>
/// TCP uses the "listener" table class: Windows then returns only listening sockets,
/// not established connections. UDP has no state — every open UDP socket "listens".
/// </para>
/// </summary>
public sealed partial class LiveListeningPortProvider : IListeningPortProvider
{
    private const uint AfInet = 2;
    private const int TcpTableOwnerPidListener = 3;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

    /// <summary>
    /// A MIB table is read in two steps: a first call returns the required size, the
    /// second fills the buffer. The size travels by <c>ref</c> — a <c>Func</c> cannot
    /// carry it, hence this dedicated delegate.
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
    /// Every MIB table has the same shape: a four-byte entry count, then the rows.
    /// Only the row size and the field offsets differ between TCP and UDP.
    /// </summary>
    private static void ReadTable(
        List<ListeningPort> ports, string protocol,
        int rowSize, int portOffset, int addrOffset, int pidOffset,
        TableCall call)
    {
        uint size = 0;

        // First call: the empty buffer is used to obtain the required size.
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

    /// <summary>Converts an IPv4 DWORD in network byte order to <c>a.b.c.d</c>.</summary>
    private static string FormatAddress(int raw) =>
        string.Create(CultureInfo.InvariantCulture, stackalloc char[15],
            $"{raw & 0xFF}.{(raw >> 8) & 0xFF}.{(raw >> 16) & 0xFF}.{(raw >> 24) & 0xFF}");

    /// <summary>
    /// The port occupies the low word in network byte order: most significant byte
    /// first. The two bytes are swapped back into host order.
    /// </summary>
    private static int FormatPort(int raw) =>
        ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
}
