using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

internal sealed class FakeServiceProvider : IServiceStateProvider
{
    private readonly Dictionary<string, ServiceRead> services = [];

    public FakeServiceProvider With(string name, ServiceState state, ServiceStartMode startMode)
    {
        services[name] = ServiceRead.Found(new ServiceInfo(name, state, startMode));
        return this;
    }

    public FakeServiceProvider WithoutService(string name)
    {
        services[name] = ServiceRead.NotInstalled;
        return this;
    }

    public FakeServiceProvider WithAccessDenied(string name)
    {
        services[name] = ServiceRead.AccessDenied;
        return this;
    }

    /// <summary>A read that failed for a reason that is not a refusal, and says so.</summary>
    public FakeServiceProvider WithFailure(string name, string reason)
    {
        services[name] = ServiceRead.Failed(reason);
        return this;
    }

    public ServiceRead Read(string serviceName) =>
        services.TryGetValue(serviceName, out var read) ? read : ServiceRead.NotInstalled;
}

/// <summary>
/// Service checks report what the registry cannot: a service declared automatic
/// can still be stopped. For Windows Update or the firewall, the difference
/// between "supposed to run" and "running" is exactly what an audit must
/// establish.
/// </summary>
public sealed class ServiceCheckTests
{
    [Fact]
    public void A_running_service_satisfies_a_state_check()
    {
        var services = new FakeServiceProvider().With("mpssvc", ServiceState.Running, ServiceStartMode.Automatic);

        Assert.Equal(VerdictStatus.Pass, Evaluate(StateRule("running"), services).Status);
    }

    [Fact]
    public void A_service_configured_to_start_but_stopped_fails()
    {
        // The case the registry cannot see, and the reason this check kind exists:
        // the configuration is correct, but the protection is not running.
        var services = new FakeServiceProvider().With("mpssvc", ServiceState.Stopped, ServiceStartMode.Automatic);

        var verdict = Evaluate(StateRule("running"), services);

        Assert.Equal(VerdictStatus.Fail, verdict.Status);
        Assert.Equal("stopped", verdict.Observed);
    }

    [Fact]
    public void A_missing_service_reads_as_absent_not_as_a_failure_to_read()
    {
        var services = new FakeServiceProvider().WithoutService("TlntSvr");

        var verdict = Evaluate(StartModeRule("absent", CheckOperator.Equals, "TlntSvr"), services);

        Assert.Equal(VerdictStatus.Pass, verdict.Status);
        Assert.Equal("absent", verdict.Observed);
    }

    /// <summary>
    /// The premise the Win32 mapping rests on, pinned here because it is invisible from
    /// there. <c>NotInstalled</c> is the one read of this provider that does <em>not</em>
    /// come back <c>Unknown</c>: it is observed as « absent » and compared, so against
    /// WIN-SVC-002's <c>state equals running</c> it is a <c>Fail</c> at critical severity.
    ///
    /// <para>
    /// That is correct for a service that is genuinely absent, and it is why
    /// <c>LiveServiceStateProvider</c> may read <c>ERROR_SERVICE_DOES_NOT_EXIST</c> as
    /// absence from <c>OpenService</c> alone. Should this ever be routed to <c>Unknown</c>
    /// instead, that guard would be protecting nothing and this test says so first.
    /// </para>
    /// </summary>
    [Fact]
    public void An_absent_service_is_a_verdict_and_not_an_unverifiable_check()
    {
        var services = new FakeServiceProvider().WithoutService("mpssvc");

        var verdict = Evaluate(StateRule("running"), services);

        Assert.Equal(VerdictStatus.Fail, verdict.Status);
        Assert.Equal("absent", verdict.Observed);
    }

    [Fact]
    public void Access_denied_yields_unknown_rather_than_a_verdict()
    {
        // Without elevation, the service control manager denies some queries.
        // The state is unknown, so no pass/fail verdict must be produced.
        var services = new FakeServiceProvider().WithAccessDenied("mpssvc");

        var verdict = Evaluate(StateRule("running"), services);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
    }

    /// <summary>
    /// The other half of that distinction, and the one nothing carried: a read that
    /// <em>failed</em>.
    ///
    /// <para>
    /// The verdict is deliberately the same — <c>Unknown</c>, out of the score, never
    /// <c>Fail</c>: what the scan could not establish says nothing about the machine. What
    /// changes is that the reason travels with it, exactly as <c>ReadWmi</c> carries the
    /// one WMI writes. Without it an unreachable service control manager is
    /// indistinguishable from missing privileges, and the report advises an elevation that
    /// fixes nothing on every <c>type: service</c> rule at once.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failed_read_stays_unverifiable_and_says_what_failed()
    {
        var services = new FakeServiceProvider().WithFailure("mpssvc",
            "OpenSCManager : erreur Win32 1722 (Le serveur RPC n'est pas disponible.)");

        var verdict = Evaluate(StateRule("running"), services);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Contains("1722", verdict.Observed ?? "", StringComparison.Ordinal);

        // Never Fail, written out beside the equality rather than left implicit in it: this is
        // where #177 could have broken the invariant CONTRIBUTING opens with. The read answers
        // ReadStatus.Failed now, and CheckReader.ReadService tested for AccessDenied alone —
        // left that way, an RPC endpoint that would not answer fell through to « absent », got
        // compared against « running », and made a critical accusation about a machine nobody
        // had managed to read.
        Assert.NotEqual(VerdictStatus.Fail, verdict.Status);
    }

    [Theory]
    [InlineData(ServiceStartMode.Disabled, "disabled", VerdictStatus.Fail)]
    [InlineData(ServiceStartMode.Automatic, "disabled", VerdictStatus.Pass)]
    [InlineData(ServiceStartMode.Manual, "disabled", VerdictStatus.Pass)]
    public void Start_mode_is_compared_by_name(
        ServiceStartMode actual, string refused, VerdictStatus expected)
    {
        var services = new FakeServiceProvider().With("wuauserv", ServiceState.Running, actual);

        Assert.Equal(expected,
            Evaluate(StartModeRule(refused, CheckOperator.NotEquals, "wuauserv"), services).Status);
    }

    [Fact]
    public void Without_a_service_provider_the_check_is_unverifiable_not_failing()
    {
        // A missing provider is a coverage gap, not a machine non-compliance.
        // Conflating them would penalize a scan for its own tooling.
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        Assert.Equal(VerdictStatus.Unknown,
            RuleEvaluator.Evaluate(StateRule("running"), providers).Status);
    }

    [Fact]
    public void A_service_check_needs_no_windows_default()
    {
        // A service state is directly observable: there is no "value Windows
        // applies when the key is absent".
        var yaml = """
            - id: TEST-SVC
              title: Un service
              severity: high
              domain: test
              rationale: Une justification suffisamment longue pour passer la validation.
              check:
                type: service
                path: mpssvc
                value: state
                operator: equals
                expect: running
            """;

        Assert.Equal(CheckKind.Service, RuleLoader.Load(yaml)[0].Check.Kind);
    }

    [Fact]
    public void An_unknown_service_field_is_rejected()
    {
        var yaml = """
            - id: TEST-SVC
              title: Un service
              severity: high
              domain: test
              rationale: Une justification suffisamment longue pour passer la validation.
              check:
                type: service
                path: mpssvc
                value: couleur
                operator: equals
                expect: bleu
            """;

        Assert.Contains("startMode", Assert.Throws<RuleFormatException>(
            () => RuleLoader.Load(yaml)).Message, StringComparison.Ordinal);
    }

    private static Verdict Evaluate(Rule rule, IServiceStateProvider services) =>
        RuleEvaluator.Evaluate(rule, new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(), services));

    private static Rule StateRule(string expect) =>
        Rule(new CheckSpec(CheckKind.Service, "mpssvc", "state", CheckOperator.Equals, expect, null));

    private static Rule StartModeRule(string expect, CheckOperator op, string service) =>
        Rule(new CheckSpec(CheckKind.Service, service, "startMode", op, expect, null));

    private static Rule Rule(CheckSpec check) =>
        new("TEST-SVC", "Un service", Severity.High, "test", "Parce que.", [], check, null);
}
