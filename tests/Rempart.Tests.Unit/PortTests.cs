using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeListeningPortProvider(params ListeningPort[] ports) : IListeningPortProvider
{
    public ListeningPortRead Enumerate() => ListeningPortRead.Found(ports);
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

        // And the port says the firewall was not consulted, rather than leaving the reader
        // to notice a missing line: the two neighbouring branches both print one.
        Assert.Equal("non lu", Assert.Single(findings).Details["pare-feu"]);
    }

    /// <summary>
    /// REV-07, the false negative this closes. A firewall the scan could not read used to
    /// answer « bloqué » for every port, because its failed read is field-for-field a
    /// firewall that blocks: no rules, <c>EnableFirewall</c> absent (default on),
    /// <c>DefaultInboundAction</c> absent (default block). The unsigned binary on
    /// <c>0.0.0.0:4444</c> then came out Benign, with an empty reason list and the printed
    /// claim « bloqué en entrée (Public) » — strictly worse than having no firewall provider
    /// at all, since the Unread branch beside it keeps the same binary Suspicious.
    ///
    /// <para>
    /// Two assertions, and the second is the one worth having: the severity could be reached
    /// again by accident, whereas asserting on what the details <em>claim</em> pins the
    /// sentence the report prints about a machine nobody read.
    /// </para>
    /// </summary>
    [Fact]
    public void A_firewall_that_could_not_be_read_never_declares_a_port_blocked()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            [new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")],
            FirewallState.Failed("Pare-feu non lu : règles locales."),
            new ListeningPort("TCP", "0.0.0.0", 4444, 500));

        var port = Assert.Single(findings, f => f.Source == "TCP 0.0.0.0:4444");

        Assert.Equal(FindingSeverity.Suspicious, port.Severity);
        Assert.Equal("non lu", port.Details["pare-feu"]);
        Assert.DoesNotContain("bloqué", string.Join(" ", port.Details.Values),
            StringComparison.Ordinal);
        Assert.NotEmpty(port.Reasons);
    }

    /// <summary>
    /// The refusal itself, said out loud. A firewall read that was attempted and refused
    /// removes the reachability cross-check from every port in the report; leaving that
    /// invisible is the same silence one layer up, and the listening table beside it has
    /// spoken since DET-PORTS-MUET.
    ///
    /// <para>
    /// Only a read that was attempted speaks. <see cref="FirewallState.Unread"/> — every
    /// capture predating the firewall collection — is <see cref="ReadStatus.NotFound"/> and
    /// stays quiet, which is why the test above asserts a single finding while this one
    /// asserts two.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_firewall_read_is_reported_and_an_uncollected_one_is_not()
    {
        var refused = Collect(
            new FakeSignatureProvider(),
            [],
            FirewallState.Refused("Pare-feu non lu : règles locales."),
            new ListeningPort("TCP", "0.0.0.0", 445, 4));

        var said = Assert.Single(refused, f => f.Source == "pare-feu");
        Assert.Equal(FindingSeverity.Notable, said.Severity);
        Assert.Contains("Pare-feu non lu", Assert.Single(said.Reasons), StringComparison.Ordinal);

        var uncollected = Collect(
            new FakeSignatureProvider(),
            [],
            FirewallState.Unread,
            new ListeningPort("TCP", "0.0.0.0", 445, 4));

        Assert.DoesNotContain(uncollected, f => f.Source == "pare-feu");
    }

    /// <summary>
    /// The defect #179 was opened over, and it is a false verdict rather than only a
    /// contradiction in prose.
    ///
    /// <para>
    /// The collector classified on « is there a diagnostic », because that was the only
    /// question <see cref="FirewallState"/> could answer, and it read the answer as a refusal
    /// because <see cref="FirewallState.Diagnostic"/> was documented « the read was attempted
    /// and refused ». Two of the five entries <c>LiveFirewallProvider</c> can put in that
    /// sentence are not refusals at all — a universal key the machine does not have, and a
    /// rule container that answered with values none of which parse — so a firewall that
    /// failed came back <see cref="AuditGap.Refused"/>, and the run exited <c>3</c> telling
    /// its reader to re-run as administrator. That is the inversion CONTRIBUTING forbids in
    /// so many words, on the collector the audit's own listening-port chapter rests on.
    /// </para>
    ///
    /// <para>
    /// All four states the branch can see, rather than the one that fails: a fix that flipped
    /// every firewall gap to <see cref="AuditGap.Unreadable"/> would close the defect and open
    /// its mirror, and the two rows below are what stop it. The two silent states are here for
    /// the same reason — a collector that started speaking about a firewall nobody looked at
    /// would be the crying wolf this repository keeps refusing, and it is one line away.
    /// </para>
    /// </summary>
    [Fact]
    public void A_firewall_that_failed_without_being_denied_never_advises_elevation()
    {
        const string Reason = "Pare-feu non lu : règles locales.";

        Assert.Equal(AuditGap.Refused, FirewallGap(FirewallState.Refused(Reason)));
        Assert.Equal(AuditGap.Unreadable, FirewallGap(FirewallState.Failed(Reason)));

        // And the two that settle nothing to say: silence, not a gap of either kind.
        Assert.Null(FirewallGap(FirewallState.Unread));
        Assert.Null(FirewallGap(BlocksAll));
    }

    /// <summary>
    /// What the collector says about the firewall itself, or null when it says nothing —
    /// the port findings beside it are another question.
    /// </summary>
    private static AuditGap? FirewallGap(FirewallState firewall) =>
        Collect(
            new FakeSignatureProvider(), [], firewall,
            new ListeningPort("TCP", "0.0.0.0", 445, 4))
        .SingleOrDefault(finding => finding.Source == "pare-feu")?.Gap;

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
