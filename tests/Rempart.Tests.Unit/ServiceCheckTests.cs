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

    public ServiceRead Read(string serviceName) =>
        services.TryGetValue(serviceName, out var read) ? read : ServiceRead.NotInstalled;
}

/// <summary>
/// Les contrôles de service disent ce que le registre ne peut pas : un service déclaré
/// automatique peut se trouver arrêté. Pour Windows Update ou le pare-feu, la
/// différence entre « censé tourner » et « tourne » est exactement ce qu'un audit
/// doit établir.
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
        // Le cas que le registre ne peut pas voir, et la raison d'être de ce type de
        // contrôle : la configuration est correcte, la protection ne tourne pas.
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

    [Fact]
    public void Access_denied_yields_unknown_rather_than_a_verdict()
    {
        // Sans élévation, le gestionnaire de services refuse certaines requêtes.
        // Conclure serait mentir : on ne sait pas.
        var services = new FakeServiceProvider().WithAccessDenied("mpssvc");

        var verdict = Evaluate(StateRule("running"), services);

        Assert.Equal(VerdictStatus.Unknown, verdict.Status);
        Assert.Null(verdict.Observed);
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
        // Un provider manquant est une lacune de couverture, pas une non-conformité
        // de la machine. Le confondre pénaliserait un scan pour son propre outillage.
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        Assert.Equal(VerdictStatus.Unknown,
            RuleEvaluator.Evaluate(StateRule("running"), providers).Status);
    }

    [Fact]
    public void A_service_check_needs_no_windows_default()
    {
        // L'état d'un service est directement observable : il n'existe pas de « valeur
        // qu'applique Windows quand la clé est absente ».
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
