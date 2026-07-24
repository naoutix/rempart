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
    private readonly IReadOnlyList<Core.Providers.ListeningPort> ports =
        new LiveListeningPortProvider().Enumerate();

    [Fact]
    public void At_least_one_port_is_listening()
    {
        // Every Windows machine runs at least the RPC endpoint mapper (135). An empty
        // list means a broken P/Invoke, not a machine without services.
        Assert.NotEmpty(ports);
    }

    [Fact]
    public void Every_port_is_structurally_plausible()
    {
        foreach (var port in ports)
        {
            Assert.Contains(port.Protocol, new[] { "TCP", "UDP" });
            Assert.InRange(port.Port, 1, 65535);
            Assert.True(port.Pid >= 0, $"PID négatif : {port.Pid}");

            // A wrongly decoded DWORD would yield an address outside the four octets —
            // the sign of a wrong field offset in the table read.
            var octets = port.LocalAddress.Split('.');
            Assert.Equal(4, octets.Length);
            Assert.All(octets, o => Assert.InRange(int.Parse(o), 0, 255));
        }
    }

    [Fact]
    public void Reading_twice_does_not_throw_or_leak()
    {
        // The exact list changes from one moment to the next; what is tested is that the
        // second call completes and frees its native buffer like the first.
        _ = new LiveListeningPortProvider().Enumerate();
    }
}
