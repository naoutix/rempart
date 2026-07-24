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

    /// <summary>An active firewall that allows the given port inbound on Public.</summary>
    private static FirewallState Allows(string protocol, int port) =>
        new([new FirewallRule(true, "In", "Allow",
                protocol == "TCP" ? 6 : 17, port.ToString(), ["Public"], null)],
            PublicFirewallEnabled: true, PublicDefaultInboundAllow: false);

    /// <summary>An active firewall with no rule: the inbound default blocks everything.</summary>
    private static FirewallState BlocksAll =>
        new([], PublicFirewallEnabled: true, PublicDefaultInboundAllow: false);

    /// <summary>
    /// An unsigned binary listening on <c>0.0.0.0</c> is suspicious: a port opened to the
    /// network by a program whose origin nothing attests has the shape of a backdoor.
    /// This is the finding that gives the collector its value.
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
    /// The heart of the exit criterion: the same unsigned binary on <c>0.0.0.0</c>, but one
    /// the firewall does not let in, is not classified as a genuinely exposed port. It is
    /// inventoried as benign — the port is open locally, not reachable from outside. The
    /// unsigned binary itself is still picked up by the process collector.
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
    /// A signed service reachable from Public is notable, not suspicious: its signature
    /// attests its origin, but a genuinely exposed port still deserves a look — this is
    /// where an attack surface is decided.
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
    /// The same signed service, but blocked by the firewall, drops back to benign: the port
    /// exists, it is not reachable.
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
    /// Without firewall state — a capture predating its collection — the cross-check steps
    /// aside and the collector falls back on the signature alone: an unsigned exposed binary
    /// stays suspicious. We do not pretend to settle a reachability we never measured.
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
    /// An unsigned binary listening only on loopback is not escalated: it exposes nothing
    /// to the network. The binary itself is the process collector's business; repeating it
    /// here would muddy the question of exposure.
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
    /// The same listening endpoint held by several instances of a binary — four Chromes on
    /// mDNS — makes a single finding, with the instance count. Two distinct bind addresses,
    /// however, remain two findings: the address is what carries the exposure.
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
    /// An exposed port whose owner cannot be resolved — the System process, or a service
    /// out of reach without elevation — is inventoried at benign severity. We cannot judge
    /// its signature, and absence of evidence is not evidence: on a non-elevated scan,
    /// nearly every system service is in this case, and escalating them all would drown
    /// the only signal that matters. The exposure stays recorded in the details.
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
