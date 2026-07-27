using System.Globalization;
using System.Net;
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
///
/// <para>
/// Four tables are read and the result carries a status beside the list
/// (<see cref="ListeningPortRead"/>). Before DET-PORTS-MUET was closed, a table that
/// refused simply contributed nothing and the scan concluded « aucun port en écoute » —
/// indistinguishable from a machine exposing no service, which no running machine is.
/// </para>
/// </summary>
public sealed partial class LiveListeningPortProvider : IListeningPortProvider
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;
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

    public ListeningPortRead Enumerate()
    {
        var ports = new List<ListeningPort>();

        // Which of the four tables refused to answer. Named individually because they fail
        // individually: a machine whose IPv6 stack is unbound still has an IPv4 table worth
        // reading, and dropping it would replace one silence with another.
        var refused = new List<string>();

        // MIB_TCPROW_OWNER_PID: state(0) localAddr(4) localPort(8) remoteAddr(12)
        // remotePort(16) owningPid(20) — 24 bytes.
        ReadTable(ports, refused, "TCP", "TCP/IPv4",
            rowSize: 24, portOffset: 8, addrOffset: 4, addrSize: 4, pidOffset: 20,
            (IntPtr buffer, ref uint size) => GetExtendedTcpTable(buffer, ref size, false,
                AfInet, TcpTableOwnerPidListener, 0));

        // MIB_UDPROW_OWNER_PID: localAddr(0) localPort(4) owningPid(8) — 12 bytes.
        ReadTable(ports, refused, "UDP", "UDP/IPv4",
            rowSize: 12, portOffset: 4, addrOffset: 0, addrSize: 4, pidOffset: 8,
            (IntPtr buffer, ref uint size) => GetExtendedUdpTable(buffer, ref size, false,
                AfInet, UdpTableOwnerPid, 0));

        // The IPv6 rows are a different shape, not a different address width: the scope
        // id sits between the address and the port, which shifts every field after it.
        // MIB_TCP6ROW_OWNER_PID: localAddr(0,16) localScopeId(16) localPort(20)
        // remoteAddr(24,16) remoteScopeId(40) remotePort(44) state(48) owningPid(52) — 56.
        ReadTable(ports, refused, "TCP", "TCP/IPv6",
            rowSize: 56, portOffset: 20, addrOffset: 0, addrSize: 16, pidOffset: 52,
            (IntPtr buffer, ref uint size) => GetExtendedTcpTable(buffer, ref size, false,
                AfInet6, TcpTableOwnerPidListener, 0));

        // MIB_UDP6ROW_OWNER_PID: localAddr(0,16) localScopeId(16) localPort(20)
        // owningPid(24) — 28 bytes.
        ReadTable(ports, refused, "UDP", "UDP/IPv6",
            rowSize: 28, portOffset: 20, addrOffset: 0, addrSize: 16, pidOffset: 24,
            (IntPtr buffer, ref uint size) => GetExtendedUdpTable(buffer, ref size, false,
                AfInet6, UdpTableOwnerPid, 0));

        // Zero cannot be true. Every Windows machine answers on the RPC endpoint mapper
        // (135) at the very least, so an empty result is a broken read — a P/Invoke whose
        // size argument stopped travelling by ref once did exactly that — and never a
        // machine with nothing exposed.
        if (ports.Count == 0)
        {
            return ListeningPortRead.Failed(
                "Aucun point d'écoute lu"
                + (refused.Count > 0 ? $" ({string.Join(", ", refused)} sans réponse)" : string.Empty)
                + ". Une machine allumée écoute au moins sur le mappeur de points de "
                + "terminaison RPC : un service exposé au réseau resterait invisible.");
        }

        if (refused.Count > 0)
        {
            return ListeningPortRead.Partial(ports,
                $"Table(s) de points d'écoute sans réponse : {string.Join(", ", refused)}. "
                + "Un service exposé par ce protocole n'apparaît pas dans l'inventaire.");
        }

        return ListeningPortRead.Found(ports);
    }

    /// <summary>
    /// Every MIB table has the same shape: a four-byte entry count, then the rows.
    /// Only the row size and the field offsets differ between TCP and UDP.
    ///
    /// <para>
    /// A table that answers with no row is not a refusal and is not recorded as one: an
    /// empty table still needs its four-byte count, so Windows asks for 4 bytes and returns
    /// <c>ERROR_INSUFFICIENT_BUFFER</c> like any other. Only a call that never got that far
    /// lands in <paramref name="refused"/>.
    /// </para>
    /// </summary>
    private static void ReadTable(
        List<ListeningPort> ports, List<string> refused, string protocol, string table,
        int rowSize, int portOffset, int addrOffset, int addrSize, int pidOffset,
        TableCall call)
    {
        uint size = 0;

        // First call: the empty buffer is used to obtain the required size.
        if (call(IntPtr.Zero, ref size) != ErrorInsufficientBuffer || size == 0)
        {
            refused.Add(table);
            return;
        }

        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (call(buffer, ref size) != 0)
            {
                refused.Add(table);
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

                var address = addrSize == 16
                    ? FormatAddressV6(buffer, row + addrOffset)
                    : FormatAddress(Marshal.ReadInt32(buffer, row + addrOffset));
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
    /// Renders the 16 raw bytes of an IPv6 address in its canonical compressed form —
    /// <c>::</c>, <c>::1</c>, <c>fe80::1</c>.
    ///
    /// <para>
    /// <see cref="IPAddress"/> does the compression rather than a hand-rolled formatter:
    /// the rule for which run of zeros collapses is fiddly, and the Core judgement matches
    /// the exact strings <c>::</c> and <c>::1</c> to decide whether a port is exposed or
    /// merely local. A formatter that emitted <c>0:0:0:0:0:0:0:1</c> would be read as a
    /// named interface, quietly turning a local socket into an exposed one.
    /// </para>
    ///
    /// <para>
    /// The scope id, which sits next to the address in the row, is deliberately left out:
    /// <c>fe80::1%7</c> and <c>fe80::1%12</c> are the same exposure on two interfaces, and
    /// carrying the index would split one finding into several without adding a fact the
    /// audit acts on.
    /// </para>
    /// </summary>
    private static string FormatAddressV6(IntPtr buffer, int offset)
    {
        var raw = new byte[16];
        Marshal.Copy(buffer + offset, raw, 0, 16);
        return new IPAddress(raw).ToString();
    }

    /// <summary>
    /// The port occupies the low word in network byte order: most significant byte
    /// first. The two bytes are swapped back into host order. Identical for v4 and v6 —
    /// the field is a DWORD holding a network-order port in both row shapes.
    /// </summary>
    private static int FormatPort(int raw) =>
        ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
}
