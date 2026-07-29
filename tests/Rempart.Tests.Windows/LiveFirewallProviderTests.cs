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
        Assert.Null(state.Diagnostic);
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

/// <summary>
/// What the read answers when the registry does not. The three tests above run against the
/// machine and can only ever show the happy path — the audited machine, where the read is
/// refused at scan time, is the case they cannot reach and the one the report gets wrong.
///
/// <para>
/// The refusal cases are generated from <c>LiveFirewallProvider.Surfaces</c>, the list the
/// read itself walks, rather than from a copy of it here. A key added to the provider gains
/// its case without anyone remembering to write one: a hand-kept list of cases is right on
/// the day it is written, and the fifth key is the one nobody covers.
/// </para>
/// </summary>
public sealed class FirewallReadRefusalTests
{
    public static TheoryData<string> Surfaces()
    {
        var data = new TheoryData<string>();
        foreach (var surface in LiveFirewallProvider.Surfaces)
        {
            data.Add(surface.Path);
        }

        return data;
    }

    /// <summary>
    /// One surface refused, the rest answering normally — including hundreds of parsable
    /// rules. Every field the read would fall back on points at « the firewall is on and
    /// blocks », so a single refused key is enough to make the whole state a lie, and none
    /// of them may be shrugged off.
    /// </summary>
    [Theory]
    [MemberData(nameof(Surfaces))]
    public void Refusing_any_single_surface_makes_the_state_unreadable(string path)
    {
        var refused = new LiveFirewallProvider(new StubRegistryProvider(denied: path)).Read();

        Assert.False(refused.Readable);
        Assert.NotNull(refused.Diagnostic);
        Assert.Equal(FirewallReachability.Unknown, refused.InboundReachability("TCP", 4444, null));
    }

    /// <summary>The control: nothing refused, and the same stub answers a readable state.
    /// Without it the theory above would still pass on a provider that never reads.</summary>
    [Fact]
    public void With_every_surface_answering_the_state_is_readable()
    {
        var read = new LiveFirewallProvider(new StubRegistryProvider(denied: null)).Read();

        Assert.True(read.Readable);
        Assert.Null(read.Diagnostic);
        Assert.Equal(FirewallReachability.Reachable, read.InboundReachability("TCP", 4444, null));
    }

    /// <summary>
    /// The half no status can reach yet. <c>ListValues</c> returns the same empty dictionary
    /// for a key that holds nothing and for an enumeration that was refused (REV-11, #115),
    /// so a rules key that opens and yields nothing is the only visible trace of a denial —
    /// and no Windows installation ships zero firewall rules. The Windows suite already
    /// asserted this on the CI runner; here it protects the audited machine instead.
    /// </summary>
    [Fact]
    public void A_rules_key_that_answers_nothing_is_not_a_machine_without_rules()
    {
        var registry = new StubRegistryProvider(denied: null) { RulesAnswerNothing = true };

        var refused = new LiveFirewallProvider(registry).Read();

        Assert.False(refused.Readable);
        Assert.Equal(FirewallReachability.Unknown, refused.InboundReachability("TCP", 4444, null));
    }

    /// <summary>
    /// A machine no Group Policy applies to. The two policy keys are simply absent there —
    /// the ordinary case on any machine outside a domain — and treating that as a refusal
    /// would report every standalone machine as unreadable, which is the opposite mistake
    /// and just as useless.
    /// </summary>
    [Fact]
    public void Absent_group_policy_keys_are_a_fact_and_not_a_refusal()
    {
        var registry = new StubRegistryProvider(denied: null) { WithoutGroupPolicy = true };

        var read = new LiveFirewallProvider(registry).Read();

        Assert.True(read.Readable);
        Assert.Null(read.Diagnostic);
    }

    /// <summary>
    /// A registry that answers every firewall surface the way a healthy machine does, except
    /// the one under test. The rule opens 4444 inbound on Public, so a state that was really
    /// read answers <c>Reachable</c> and a state that was not cannot fake it.
    /// </summary>
    private sealed class StubRegistryProvider(string? denied) : IRegistryProvider
    {
        private const string Rule =
            "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|Profile=Public|";

        public bool RulesAnswerNothing { get; init; }

        public bool WithoutGroupPolicy { get; init; }

        public RegistryRead ReadValue(string keyPath, string valueName) =>
            Status(keyPath) switch
            {
                ReadStatus.AccessDenied => RegistryRead.AccessDenied,

                // Both flags absent, as on a default installation: the caller applies the
                // Windows defaults, which is legitimate on a key that answered.
                _ => RegistryRead.NotFound,
            };

        public ReadStatus KeyExists(string keyPath) => Status(keyPath);

        public IReadOnlyDictionary<string, RegistryValue> ListValues(string keyPath)
        {
            var values = new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);

            if (!RulesAnswerNothing
                && Status(keyPath) == ReadStatus.Found
                && keyPath.EndsWith("FirewallRules", StringComparison.OrdinalIgnoreCase))
            {
                values["RempartTest"] = RegistryValue.OfText(Rule);
            }

            return values;
        }

        public IReadOnlyList<string> ListSubKeys(string keyPath) => [];

        private ReadStatus Status(string keyPath)
        {
            if (string.Equals(keyPath, denied, StringComparison.OrdinalIgnoreCase))
            {
                return ReadStatus.AccessDenied;
            }

            var policy = keyPath.Contains(@"\Policies\", StringComparison.OrdinalIgnoreCase);

            return WithoutGroupPolicy && policy ? ReadStatus.NotFound : ReadStatus.Found;
        }
    }
}
