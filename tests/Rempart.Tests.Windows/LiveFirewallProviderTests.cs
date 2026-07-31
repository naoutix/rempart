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

        // And it is a refusal rather than merely « not settled »: the registry said no, which
        // is the one answer on this channel that re-running elevated repairs.
        Assert.Equal(ReadStatus.AccessDenied, refused.Status);
    }

    /// <summary>The universal keys, the two the read treats an absence of as a failure.</summary>
    public static TheoryData<string> UniversalSurfaces()
    {
        var data = new TheoryData<string>();
        foreach (var surface in LiveFirewallProvider.Surfaces.Where(s => s.Universal))
        {
            data.Add(surface.Path);
        }

        return data;
    }

    /// <summary>
    /// The other half of #179, on the side that produces it: a universal key the machine does
    /// not have. Every Windows installation carries these two, so their absence is a failed
    /// read — the provider has said so since it was written, in the <c>Universal</c> flag on
    /// its own surface list — and <em>nobody denied anything</em>.
    ///
    /// <para>
    /// It reached the same <c>FirewallState.Failed</c> as a genuine denial, and the collector
    /// read that state as a refusal, so this exited <c>3</c> with « relancer en administrateur »
    /// against a key no elevation creates. Generated from the provider's own list, like the
    /// refusal theory above, so a sixth universal surface gains its case unasked.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(UniversalSurfaces))]
    public void An_absent_universal_key_is_a_failure_and_not_a_refusal(string path)
    {
        var read = new LiveFirewallProvider(
            new StubRegistryProvider(denied: null) { Absent = path }).Read();

        Assert.False(read.Readable);
        Assert.NotNull(read.Diagnostic);
        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.False(read.Denied);
    }

    /// <summary>
    /// The mixed walk, and the shape a real non-elevated read of a policy-managed machine
    /// takes: something denied <em>and</em> something merely failed, in one sentence.
    ///
    /// <para>
    /// It answers a refusal, and that is not a shrug — elevating repairs the denied half, so
    /// the advice is earned. The rule is the one <c>ScheduledTaskRead.Partially</c> already
    /// applies to a folder walk. Without this row the provider could satisfy the two theories
    /// above by reading only the last surface it touched, which is the single-point reading
    /// #177's guard was rewritten over.
    /// </para>
    /// </summary>
    [Fact]
    public void A_read_that_met_a_denial_and_a_failure_answers_the_denial()
    {
        var registry = new StubRegistryProvider(
            denied: @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile")
        {
            RulesAnswerNothing = true,
        };

        var read = new LiveFirewallProvider(registry).Read();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);

        // The premise: both halves really are in the sentence, so the row is the mixed case
        // and not a denial on its own.
        Assert.Contains("profil Public de stratégie de groupe", read.Diagnostic!, StringComparison.Ordinal);
        Assert.Contains("règles illisibles", read.Diagnostic!, StringComparison.Ordinal);
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
    /// The safety net, now that the enumeration itself can speak. A rules key that opens and
    /// yields nothing usable is still a failure — no Windows installation ships zero firewall
    /// rules — but it is no longer the <em>only</em> trace of a denial: it used to be, because
    /// <c>ListValues</c> returned the same empty dictionary for « clé vide » and for « accès
    /// refusé » (REV-11). It now catches what a status cannot, an enumeration that answered
    /// with values none of which parse.
    /// </summary>
    [Fact]
    public void A_rules_key_that_answers_nothing_is_not_a_machine_without_rules()
    {
        var registry = new StubRegistryProvider(denied: null) { RulesAnswerNothing = true };

        var refused = new LiveFirewallProvider(registry).Read();

        Assert.False(refused.Readable);
        Assert.Equal(FirewallReachability.Unknown, refused.InboundReachability("TCP", 4444, null));

        // A failure, and the second of the two entries #179 found travelling as a refusal:
        // the key opened, the values came back, none of them parsed. No privilege is missing.
        Assert.Equal(ReadStatus.Failed, refused.Status);
    }

    /// <summary>
    /// The rule containers, the only two surfaces the read enumerates. The profile keys are
    /// read value by value and their refusal is already caught by <c>ReadValue</c>; filtered
    /// from the provider's own list rather than named here, so a container added there gains
    /// its case on its own.
    /// </summary>
    public static TheoryData<string> RuleSurfaces()
    {
        var data = new TheoryData<string>();
        foreach (var surface in LiveFirewallProvider.Surfaces.Where(s => s.CarriesRules))
        {
            data.Add(surface.Path);
        }

        return data;
    }

    /// <summary>
    /// A key whose <em>values</em> are refused while the key itself opens — what a per-value
    /// ACL produces, and what <c>KeyExists</c> answers <c>Found</c> for throughout. The read
    /// then walked an empty enumeration and concluded « ce conteneur ne porte aucune règle »,
    /// which on the local container is a claim no Windows installation supports. The count
    /// above caught it only because zero is impossible there; a container that answered one
    /// parsable rule out of six hundred passed.
    /// </summary>
    [Theory]
    [MemberData(nameof(RuleSurfaces))]
    public void Refusing_the_enumeration_of_a_rules_key_makes_the_state_unreadable(string path)
    {
        var registry = new StubRegistryProvider(denied: null) { DeniedEnumeration = path };

        var refused = new LiveFirewallProvider(registry).Read();

        Assert.False(refused.Readable);
        Assert.NotNull(refused.Diagnostic);
        Assert.Equal(FirewallReachability.Unknown, refused.InboundReachability("TCP", 4444, null));
        Assert.Equal(ReadStatus.AccessDenied, refused.Status);
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

        /// <summary>
        /// A key that opens and whose values are refused — the per-value ACL
        /// <see cref="KeyExists"/> cannot see, and the one case the rule count could not
        /// cover on a container that still answered something.
        /// </summary>
        public string? DeniedEnumeration { get; init; }

        /// <summary>
        /// A key the machine simply does not have. On a universal surface that is a failed
        /// read and not a fact about the machine — and not a refusal either, which is the
        /// distinction #179 closed.
        /// </summary>
        public string? Absent { get; init; }

        public RegistryRead ReadValue(string keyPath, string valueName) =>
            Status(keyPath) switch
            {
                ReadStatus.AccessDenied => RegistryRead.AccessDenied,

                // Both flags absent, as on a default installation: the caller applies the
                // Windows defaults, which is legitimate on a key that answered.
                _ => RegistryRead.NotFound,
            };

        public ReadStatus KeyExists(string keyPath) => Status(keyPath);

        public RegistryValueList ListValues(string keyPath)
        {
            if (string.Equals(keyPath, DeniedEnumeration, StringComparison.OrdinalIgnoreCase))
            {
                return RegistryValueList.AccessDenied;
            }

            var values = new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);

            if (!RulesAnswerNothing
                && Status(keyPath) == ReadStatus.Found
                && keyPath.EndsWith("FirewallRules", StringComparison.OrdinalIgnoreCase))
            {
                values["RempartTest"] = RegistryValue.OfText(Rule);
            }

            return RegistryValueList.Found(values);
        }

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.Found([]);

        private ReadStatus Status(string keyPath)
        {
            if (string.Equals(keyPath, denied, StringComparison.OrdinalIgnoreCase))
            {
                return ReadStatus.AccessDenied;
            }

            if (string.Equals(keyPath, Absent, StringComparison.OrdinalIgnoreCase))
            {
                return ReadStatus.NotFound;
            }

            var policy = keyPath.Contains(@"\Policies\", StringComparison.OrdinalIgnoreCase);

            return WithoutGroupPolicy && policy ? ReadStatus.NotFound : ReadStatus.Found;
        }
    }
}
