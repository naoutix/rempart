using Rempart.Core.Collectors;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// Recording what SCHANNEL says, and judging none of it.
///
/// <para>
/// The whole point of this collector is that it comes <em>before</em> the rules it will one
/// day feed. TLS hardening rules are deferred because the effective defaults vary by Windows
/// build, and a guessed <c>windowsDefault</c> would fail machines that are correctly
/// configured — the lesson of the three false CRITICALs of M1. What was missing was not the
/// judgement but the evidence: a capture records only what was read, and nothing read
/// SCHANNEL, so no capture ever taken carries a single one of these values.
/// </para>
///
/// <para>
/// The distinction this file exists to pin: <b>an absent value is an observation, not a
/// hole.</b> On SCHANNEL absence is the ordinary state and it means « the default of this
/// build applies » — which is precisely the unknown being measured. Recording it as nothing
/// would throw away the only datum that matters.
/// </para>
/// </summary>
public sealed class TlsCollectorTests
{
    [Fact]
    public void A_configured_protocol_is_recorded_as_the_machine_has_it()
    {
        var result = Collect(new FakeRegistryProvider()
            .WithNumber(Key("TLS 1.0", "Client"), "Enabled", 0)
            .WithNumber(Key("TLS 1.0", "Client"), "DisabledByDefault", 1));

        Assert.Equal("0", result.Fields["tls.1_0.client.enabled"]);
        Assert.Equal("1", result.Fields["tls.1_0.client.disabledByDefault"]);
        Assert.Equal(CollectorStatus.Ok, result.Status);
    }

    /// <summary>
    /// The case this collector was written for. « absent » is not « 0 » and not « rien » : it
    /// says the build's default applies, and which default that is, is the question the whole
    /// deferred milestone turns on.
    /// </summary>
    [Fact]
    public void An_absent_value_is_recorded_as_absent_and_not_as_disabled()
    {
        var result = Collect(new FakeRegistryProvider());

        Assert.Equal("absent", result.Fields["tls.1_2.client.enabled"]);
        Assert.Equal("absent", result.Fields["tls.1_2.server.disabledByDefault"]);
        Assert.Equal(CollectorStatus.Ok, result.Status);
    }

    /// <summary>
    /// Every protocol and both roles, every time. A field written only when it has a value
    /// would make « this machine has no entry for TLS 1.3 » indistinguishable from « this
    /// capture predates the collector », which is the comparison the aggregation across builds
    /// is going to rest on.
    /// </summary>
    [Fact]
    public void Every_protocol_and_both_roles_are_recorded_whatever_the_machine_says()
    {
        var fields = Collect(new FakeRegistryProvider()).Fields;

        foreach (var protocol in new[] { "1_0", "1_1", "1_2", "1_3" })
        {
            foreach (var role in new[] { "client", "server" })
            {
                Assert.True(fields.ContainsKey($"tls.{protocol}.{role}.enabled"));
                Assert.True(fields.ContainsKey($"tls.{protocol}.{role}.disabledByDefault"));
            }
        }

        Assert.Equal(16, fields.Count);
    }

    /// <summary>
    /// A refused read is not an absent value, and saying so is the whole of what this
    /// repository closed five times elsewhere. The status carries it, the field says
    /// « illisible », and the two together stop a denied enumeration from being counted as
    /// evidence about a build's defaults.
    /// </summary>
    [Fact]
    public void A_refused_read_is_not_an_absent_value()
    {
        var result = Collect(new FakeRegistryProvider().WithDeniedEnumeration(Key("TLS 1.2", "Client")));

        Assert.Equal("illisible", result.Fields["tls.1_2.client.enabled"]);
        Assert.Equal(CollectorStatus.InsufficientPrivileges, result.Status);
        Assert.NotEmpty(result.Diagnostics);

        // The other locations still answered, and their answers are kept.
        Assert.Equal("absent", result.Fields["tls.1_2.server.enabled"]);
    }

    /// <summary>
    /// It reads and it concludes nothing: no verdict, no finding, no severity. The rules come
    /// later, once enough builds have been seen — that order is the point of the collector.
    /// </summary>
    [Fact]
    public void The_collector_judges_nothing()
    {
        var result = Collect(new FakeRegistryProvider()
            .WithNumber(Key("TLS 1.0", "Server"), "Enabled", 1));

        Assert.All(result.Fields.Values, value =>
            Assert.DoesNotContain("échec", value ?? "", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(result.Diagnostics);
    }

    private static CollectorResult Collect(FakeRegistryProvider registry) =>
        new TlsCollector().Collect(new ProviderSet(registry, new FakeSystemInfoProvider()));

    private static string Key(string protocol, string role) =>
        $@"{TlsCollector.ProtocolsKey}\{protocol}\{role}";
}
