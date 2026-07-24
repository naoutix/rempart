using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class FirewallRuleParseTests
{
    [Fact]
    public void Extracts_the_fields_that_decide_reachability()
    {
        var rule = FirewallRule.Parse(
            "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|Profile=Public|"
            + @"App=%SystemRoot%\system32\svchost.exe|Name=@FirewallAPI.dll,-1|");

        Assert.NotNull(rule);
        Assert.True(rule.Active);
        Assert.Equal("In", rule.Direction);
        Assert.Equal("Allow", rule.Action);
        Assert.Equal(6, rule.Protocol);
        Assert.Equal("445", rule.LocalPorts);
        Assert.Equal(["Public"], rule.Profiles);
        Assert.Equal(@"%SystemRoot%\system32\svchost.exe", rule.App);
    }

    [Fact]
    public void A_missing_profile_means_all_profiles()
    {
        // Without a Profile field, the rule applies to all profiles — a fact not to be
        // confused with "none". Represented as an empty list, treated as "Public
        // included" at evaluation.
        var rule = FirewallRule.Parse("v2.31|Action=Allow|Active=TRUE|Dir=In|LPort=80|");

        Assert.NotNull(rule);
        Assert.Empty(rule.Profiles);
    }

    [Fact]
    public void A_version_header_alone_is_not_a_usable_rule()
    {
        // Without a Dir field, the string describes no traffic direction: nothing to evaluate.
        Assert.Null(FirewallRule.Parse("v2.31|"));
        Assert.Null(FirewallRule.Parse(""));
    }

    [Fact]
    public void An_inactive_rule_is_parsed_as_inactive()
    {
        var rule = FirewallRule.Parse("v2.31|Action=Allow|Active=FALSE|Dir=In|LPort=445|");

        Assert.NotNull(rule);
        Assert.False(rule.Active);
    }
}

public class FirewallReachabilityTests
{
    private static FirewallState With(params string[] rawRules) =>
        new([.. rawRules.Select(FirewallRule.Parse).Where(r => r is not null)!],
            PublicFirewallEnabled: true, PublicDefaultInboundAllow: false);

    private static string Allow(int port, string extra = "") =>
        $"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort={port}|Profile=Public|{extra}";

    /// <summary>An unread firewall settles nothing: the cross-checking rule steps aside.</summary>
    [Fact]
    public void An_unread_state_answers_unknown()
    {
        Assert.Equal(FirewallReachability.Unknown,
            FirewallState.Unread.InboundReachability("TCP", 445, null));
    }

    /// <summary>Firewall off: everything that listens is reachable.</summary>
    [Fact]
    public void A_disabled_firewall_makes_everything_reachable()
    {
        var state = new FirewallState([], PublicFirewallEnabled: false, PublicDefaultInboundAllow: false);

        Assert.Equal(FirewallReachability.Reachable, state.InboundReachability("TCP", 445, null));
    }

    /// <summary>Blocking inbound default and no rule: not reachable.</summary>
    [Fact]
    public void With_no_matching_rule_the_default_inbound_block_wins()
    {
        Assert.Equal(FirewallReachability.Blocked, With().InboundReachability("TCP", 445, null));
    }

    [Fact]
    public void An_active_allow_on_the_port_makes_it_reachable()
    {
        Assert.Equal(FirewallReachability.Reachable, With(Allow(445)).InboundReachability("TCP", 445, null));
    }

    /// <summary>A block wins over an allow, as it does in Windows.</summary>
    [Fact]
    public void A_block_rule_overrides_an_allow_rule()
    {
        var state = With(
            Allow(445),
            "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=445|Profile=Public|");

        Assert.Equal(FirewallReachability.Blocked, state.InboundReachability("TCP", 445, null));
    }

    /// <summary>
    /// The Profile field repeats rather than combining; the Public profile is recognised
    /// even buried among others. A naive dictionary would keep only one of them, at the
    /// mercy of ordering.
    /// </summary>
    [Fact]
    public void A_repeated_profile_field_is_read_in_full()
    {
        var state = With(
            "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|"
            + "Profile=Domain|Profile=Private|Profile=Public|");

        Assert.Equal(FirewallReachability.Reachable, state.InboundReachability("TCP", 445, null));
    }

    /// <summary>
    /// A rule with neither port nor application — in practice a packaged-app rule, carried
    /// by a package identifier we cannot map back to a path — does not open every port.
    /// Counting it would wrongly classify each system port as reachable.
    /// </summary>
    [Fact]
    public void An_app_agnostic_any_port_rule_does_not_open_arbitrary_ports()
    {
        var state = With("v2.31|Action=Allow|Active=TRUE|Dir=In|Profile=Public|PFN=Some.Package_abc|");

        Assert.Equal(FirewallReachability.Blocked, state.InboundReachability("TCP", 445, null));
        Assert.Equal(FirewallReachability.Blocked,
            state.InboundReachability("UDP", 5353, @"C:\Windows\System32\svchost.exe"));
    }

    /// <summary>A rule scoped to the Domain profile does not apply on Public.</summary>
    [Fact]
    public void A_rule_scoped_to_another_profile_does_not_apply()
    {
        var state = With("v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|Profile=Domain|");

        Assert.Equal(FirewallReachability.Blocked, state.InboundReachability("TCP", 445, null));
    }

    /// <summary>An inactive rule does not count.</summary>
    [Fact]
    public void An_inactive_allow_does_not_open_the_port()
    {
        var state = With("v2.31|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|Profile=Public|");

        Assert.Equal(FirewallReachability.Blocked, state.InboundReachability("TCP", 445, null));
    }

    [Fact]
    public void A_port_range_and_a_list_both_match()
    {
        Assert.Equal(FirewallReachability.Reachable,
            With(Allow(0, "").Replace("LPort=0", "LPort=1000-2000")).InboundReachability("TCP", 1500, null));
        Assert.Equal(FirewallReachability.Reachable,
            With(Allow(0, "").Replace("LPort=0", "LPort=80,443,8080")).InboundReachability("TCP", 443, null));
    }

    /// <summary>
    /// A dynamic-port keyword ("RPC") does not resolve to a number: we do not claim it
    /// allows a specific port, so as not to invent an exposure.
    /// </summary>
    [Fact]
    public void A_keyword_port_does_not_match_a_specific_number()
    {
        var state = With("v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|Profile=Public|");

        Assert.Equal(FirewallReachability.Blocked, state.InboundReachability("TCP", 49664, null));
    }

    /// <summary>
    /// A rule bound to an application counts only for that application — and its path is
    /// compared after environment variables are expanded.
    /// </summary>
    [Fact]
    public void An_app_scoped_rule_matches_only_its_own_binary()
    {
        var state = With(Allow(445, @"App=%SystemRoot%\system32\svchost.exe|"));

        Assert.Equal(FirewallReachability.Reachable,
            state.InboundReachability("TCP", 445, @"C:\Windows\system32\svchost.exe"));
        Assert.Equal(FirewallReachability.Blocked,
            state.InboundReachability("TCP", 445, @"C:\tmp\autre.exe"));
    }

    /// <summary>
    /// Unknown owner against an app-bound rule: we cannot confirm it applies, so we do
    /// not assume it does.
    /// </summary>
    [Fact]
    public void An_app_scoped_rule_does_not_apply_when_the_owner_is_unknown()
    {
        var state = With(Allow(445, @"App=%SystemRoot%\system32\svchost.exe|"));

        Assert.Equal(FirewallReachability.Blocked, state.InboundReachability("TCP", 445, null));
    }
}
