using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeListeningPortProvider(params ListeningPort[] ports) : IListeningPortProvider
{
    public IReadOnlyList<ListeningPort> Enumerate() => ports;
}

public class PortTests
{
    private static IReadOnlyList<Finding> Collect(
        ISignatureProvider signatures,
        RunningProcess[] processes,
        params ListeningPort[] ports) =>
        new ListeningPortsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: signatures,
            processes: new FakeProcessProvider(processes),
            listeningPorts: new FakeListeningPortProvider(ports)));

    /// <summary>
    /// Un binaire non signé qui écoute sur <c>0.0.0.0</c> est suspect : un port ouvert au
    /// réseau par un programme dont rien n'atteste l'origine est la forme d'une porte
    /// dérobée. C'est le constat qui fait la valeur du collecteur.
    /// </summary>
    [Fact]
    public void An_unsigned_binary_exposed_on_all_interfaces_is_suspicious()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            [new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")],
            new ListeningPort("TCP", "0.0.0.0", 4444, 500));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("exposé", string.Join(" ", finding.Reasons));
        Assert.Equal("toutes les interfaces", finding.Details["exposition"]);
    }

    /// <summary>
    /// Le même binaire signé sur <c>0.0.0.0</c> reste bénin : un service système signé qui
    /// écoute le réseau est la norme, pas un signal.
    /// </summary>
    [Fact]
    public void A_signed_binary_exposed_on_all_interfaces_is_benign()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\Windows\System32\svc.exe", SignatureStatus.Valid),
            [new RunningProcess(600, 4, "svc.exe", @"C:\Windows\System32\svc.exe", "")],
            new ListeningPort("TCP", "0.0.0.0", 135, 600));

        Assert.Equal(FindingSeverity.Benign, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// Un binaire non signé qui n'écoute que la boucle locale n'est pas hissé : il n'expose
    /// rien au réseau. Le binaire lui-même est l'affaire du collecteur de processus ; le
    /// redoubler ici brouillerait la question de l'exposition.
    /// </summary>
    [Fact]
    public void An_unsigned_binary_on_loopback_is_not_escalated()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            [new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")],
            new ListeningPort("TCP", "127.0.0.1", 4444, 500));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("locale", finding.Details["exposition"]);
    }

    /// <summary>
    /// Un port exposé dont le propriétaire ne se résout pas — le processus System, ou un
    /// service hors de portée sans élévation — est inventorié, gravité bénigne. On ne peut
    /// pas juger sa signature, et l'absence de preuve n'est pas une preuve : sur un scan non
    /// élevé, presque tous les services système sont dans ce cas, et les hisser tous
    /// noierait le seul signal qui compte. L'exposition reste consignée dans les détails.
    /// </summary>
    [Fact]
    public void An_exposed_port_with_no_resolvable_owner_is_benign_inventory()
    {
        var findings = Collect(
            new FakeSignatureProvider(),
            [],
            new ListeningPort("TCP", "0.0.0.0", 445, 4));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("PID 4", finding.Target);
        Assert.Equal("toutes les interfaces", finding.Details["exposition"]);
    }
}
