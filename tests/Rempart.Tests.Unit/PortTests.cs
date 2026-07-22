using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeListeningPortProvider(params ListeningPort[] ports) : IListeningPortProvider
{
    public IReadOnlyList<ListeningPort> Enumerate() => ports;
}

internal sealed class FakeFirewallProvider(FirewallState state) : IFirewallProvider
{
    public FirewallState Read() => state;
}

public class PortTests
{
    private static IReadOnlyList<Finding> Collect(
        ISignatureProvider signatures,
        RunningProcess[] processes,
        params ListeningPort[] ports) =>
        Collect(signatures, processes, FirewallState.Unread, ports);

    private static IReadOnlyList<Finding> Collect(
        ISignatureProvider signatures,
        RunningProcess[] processes,
        FirewallState firewall,
        params ListeningPort[] ports) =>
        new ListeningPortsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: signatures,
            processes: new FakeProcessProvider(processes),
            listeningPorts: new FakeListeningPortProvider(ports),
            firewall: new FakeFirewallProvider(firewall)));

    /// <summary>Un pare-feu actif qui autorise en entrée le port donné sur Public.</summary>
    private static FirewallState Allows(string protocol, int port) =>
        new([new FirewallRule(true, "In", "Allow",
                protocol == "TCP" ? 6 : 17, port.ToString(), ["Public"], null)],
            PublicFirewallEnabled: true, PublicDefaultInboundAllow: false);

    /// <summary>Un pare-feu actif sans règle : le défaut entrant bloque tout.</summary>
    private static FirewallState BlocksAll =>
        new([], PublicFirewallEnabled: true, PublicDefaultInboundAllow: false);

    /// <summary>
    /// Un binaire non signé qui écoute sur <c>0.0.0.0</c> est suspect : un port ouvert au
    /// réseau par un programme dont rien n'atteste l'origine est la forme d'une porte
    /// dérobée. C'est le constat qui fait la valeur du collecteur.
    /// </summary>
    [Fact]
    public void An_unsigned_binary_reachable_from_public_is_suspicious()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            [new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")],
            Allows("TCP", 4444),
            new ListeningPort("TCP", "0.0.0.0", 4444, 500));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("réseau public", string.Join(" ", finding.Reasons));
        Assert.Equal("autorisé en entrée (Public)", finding.Details["pare-feu"]);
    }

    /// <summary>
    /// Le cœur du critère de sortie : le même binaire non signé sur <c>0.0.0.0</c>, mais que
    /// le pare-feu ne laisse pas entrer, n'est pas classé comme un port réellement exposé. Il
    /// est inventorié en bénin — le port est ouvert localement, pas joignable de l'extérieur.
    /// Le binaire non signé, lui, reste relevé par le collecteur de processus.
    /// </summary>
    [Fact]
    public void An_unsigned_binary_blocked_by_the_firewall_is_not_exposed()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            [new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")],
            BlocksAll,
            new ListeningPort("TCP", "0.0.0.0", 4444, 500));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("bloqué en entrée (Public)", finding.Details["pare-feu"]);
    }

    /// <summary>
    /// Un service signé joignable depuis Public est notable, pas suspect : sa signature
    /// atteste de son origine, mais un port réellement exposé mérite tout de même un regard —
    /// c'est là que se décide une surface d'attaque.
    /// </summary>
    [Fact]
    public void A_signed_service_reachable_from_public_is_notable()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\Windows\System32\svc.exe", SignatureStatus.Valid),
            [new RunningProcess(600, 4, "svc.exe", @"C:\Windows\System32\svc.exe", "")],
            Allows("TCP", 3389),
            new ListeningPort("TCP", "0.0.0.0", 3389, 600));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("réseau public", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// Le même service signé, mais bloqué par le pare-feu, redevient bénin : le port existe,
    /// il n'est pas atteignable.
    /// </summary>
    [Fact]
    public void A_signed_service_blocked_by_the_firewall_is_benign()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\Windows\System32\svc.exe", SignatureStatus.Valid),
            [new RunningProcess(600, 4, "svc.exe", @"C:\Windows\System32\svc.exe", "")],
            BlocksAll,
            new ListeningPort("TCP", "0.0.0.0", 135, 600));

        Assert.Equal(FindingSeverity.Benign, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// Sans état de pare-feu — une capture antérieure à sa collecte — la règle croisée se
    /// retire et le collecteur retombe sur la signature seule : un binaire non signé exposé
    /// reste suspect. On ne prétend pas trancher l'atteignabilité qu'on n'a pas mesurée.
    /// </summary>
    [Fact]
    public void Without_firewall_data_an_unsigned_exposed_binary_stays_suspicious()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            [new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")],
            FirewallState.Unread,
            new ListeningPort("TCP", "0.0.0.0", 4444, 500));

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(findings).Severity);
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
    /// Le même point d'écoute tenu par plusieurs instances d'un binaire — quatre Chrome sur
    /// mDNS — ne fait qu'un constat, avec le nombre d'instances. Deux adresses de bind
    /// distinctes, en revanche, restent deux constats : c'est l'adresse qui porte l'exposition.
    /// </summary>
    [Fact]
    public void Identical_listeners_collapse_to_one_finding()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\chrome.exe", SignatureStatus.Valid),
            [
                new RunningProcess(10, 4, "chrome.exe", @"C:\chrome.exe", ""),
                new RunningProcess(20, 4, "chrome.exe", @"C:\chrome.exe", ""),
                new RunningProcess(30, 4, "chrome.exe", @"C:\chrome.exe", ""),
            ],
            BlocksAll,
            new ListeningPort("UDP", "0.0.0.0", 5353, 10),
            new ListeningPort("UDP", "0.0.0.0", 5353, 20),
            new ListeningPort("UDP", "0.0.0.0", 5353, 30));

        var finding = Assert.Single(findings);
        Assert.Equal("3", finding.Details["instances"]);
        Assert.False(finding.Details.ContainsKey("pid"));
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
