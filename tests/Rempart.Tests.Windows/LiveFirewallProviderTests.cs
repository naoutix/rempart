using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The firewall read parses registry strings. A wrong key path or a misread format is not
/// caught at compile time: it returns an empty list and the cross-checking rule goes
/// silent without any signal. These tests exercise the real read against the machine.
/// </summary>
public sealed class LiveFirewallProviderTests
{
    private readonly FirewallState state = new LiveFirewallProvider().Read();

    [Fact]
    public void The_firewall_state_is_readable()
    {
        Assert.True(state.Readable);
    }

    [Fact]
    public void Rules_are_read_and_parsed()
    {
        // Every Windows installation carries hundreds of built-in rules. An empty list
        // means a wrong key path, not a firewall without rules.
        Assert.NotEmpty(state.Rules);
        Assert.All(state.Rules, rule => Assert.False(string.IsNullOrEmpty(rule.Direction)));
    }

    [Fact]
    public void Reachability_is_answered_without_throwing()
    {
        // The value depends on the machine; what is tested is that the cross-check
        // completes and never returns "unknown" for a state that was actually read.
        var reach = state.InboundReachability("TCP", 445, null);
        Assert.NotEqual(FirewallReachability.Unknown, reach);
    }
}
