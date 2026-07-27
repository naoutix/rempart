using System.Net;
using System.Net.Sockets;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The P/Invoke to <c>GetExtendedTcpTable</c> reads a variable-size table through
/// offsets. An error there is invisible at compile time and returns either an empty
/// buffer or plausible but wrong fields — a bug in passing the size by <c>ref</c> once
/// silently returned zero ports. These tests exercise the real call against the machine,
/// the only place where it can be verified.
/// </summary>
public sealed class LiveListeningPortProviderTests
{
    private readonly Core.Providers.ListeningPortRead read =
        new LiveListeningPortProvider().Enumerate();

    private IReadOnlyList<Core.Providers.ListeningPort> ports => read.Ports;

    [Fact]
    public void At_least_one_port_is_listening()
    {
        // Every Windows machine runs at least the RPC endpoint mapper (135). An empty
        // list means a broken P/Invoke, not a machine without services.
        Assert.NotEmpty(ports);
    }

    /// <summary>
    /// The four tables all answered, on a machine that is plainly working.
    ///
    /// <para>
    /// This is the check that gives the status channel its meaning, and it is why the
    /// channel does not simply say « Found » whenever the list is non-empty: the IPv4 and
    /// IPv6 tables are four separate calls and they fail one at a time. A run where the
    /// IPv6 tables stopped answering — an offset that stopped matching a row shape, a
    /// stack unbound on the machine — would still return dozens of IPv4 endpoints and look
    /// perfectly healthy without this.
    /// </para>
    ///
    /// <para>
    /// Not probed and not skippable, unlike the WMI and catalog suites: this call needs no
    /// privilege and no service, so a refusal here is a defect and never a quiet runner.
    /// </para>
    /// </summary>
    [Fact]
    public void The_read_reports_itself_as_complete()
    {
        Assert.Equal(Core.Providers.ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
    }

    [Fact]
    public void Every_port_is_structurally_plausible()
    {
        foreach (var port in ports)
        {
            Assert.Contains(port.Protocol, new[] { "TCP", "UDP" });
            Assert.InRange(port.Port, 1, 65535);
            Assert.True(port.Pid >= 0, $"PID négatif : {port.Pid}");

            // A wrong field offset in the table read shows up here: the bytes it lands on
            // do not parse as an address at all. Both families are checked, because the
            // IPv6 rows have their own shape — a scope id sits between the address and the
            // port, shifting every field after it.
            Assert.True(IPAddress.TryParse(port.LocalAddress, out var address),
                $"Adresse non analysable : « {port.LocalAddress} » — décalage de champ probable.");

            Assert.Contains(address!.AddressFamily,
                new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 });

            // The canonical compressed form is what the Core judgement matches on: "::"
            // and "::1" decide exposed versus local. A formatter emitting
            // "0:0:0:0:0:0:0:1" would make a loopback socket look like a named interface.
            Assert.Equal(port.LocalAddress, address.ToString());
        }
    }

    [Fact]
    public void Reading_twice_does_not_throw_or_leak()
    {
        // The exact list changes from one moment to the next; what is tested is that the
        // second call completes and frees its native buffer like the first.
        Assert.NotEmpty(new LiveListeningPortProvider().Enumerate().Ports);
    }
}
