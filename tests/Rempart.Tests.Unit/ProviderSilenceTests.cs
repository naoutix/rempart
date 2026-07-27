using Rempart.Core.Browsers;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// What a collector must do when the provider under it could not look.
///
/// <para>
/// The distinction these tests defend is the one the whole project rests on: <b>an empty
/// list and a failed read are not the same answer</b>. Drivers and running processes carry
/// the LOLDrivers comparison and unsigned-binary detection; a machine scanned while WMI is
/// mute used to report zero of each, which reads exactly like a clean machine. Silence
/// where the tool could not look is the one failure an audit must never produce.
/// </para>
/// </summary>
public class ProviderSilenceTests
{
    private sealed class DeniedDrivers : IDriverProvider
    {
        public DriverRead Enumerate() => DriverRead.Failed("WMI n'a rendu aucune ligne.");
    }

    private sealed class DeniedProcesses : IProcessProvider
    {
        public ProcessRead Enumerate() => ProcessRead.Failed("WMI n'a rendu aucune ligne.");
    }

    private sealed class EmptyButSuccessfulDrivers : IDriverProvider
    {
        public DriverRead Enumerate() => DriverRead.Found([]);
    }

    private sealed class DeniedPorts : IListeningPortProvider
    {
        public ListeningPortRead Enumerate() =>
            ListeningPortRead.Failed("Les tables d'écoute n'ont rendu aucune ligne.");
    }

    /// <summary>
    /// The IPv6 tables refused, the IPv4 ones answered. Four calls fail one at a time, so
    /// « lecture ratée » and « rien à lire » are not the only two states.
    /// </summary>
    private sealed class PartiallyReadPorts(params ListeningPort[] ports) : IListeningPortProvider
    {
        public ListeningPortRead Enumerate() =>
            ListeningPortRead.Partial(ports, "Table(s) sans réponse : TCP/IPv6, UDP/IPv6.");
    }

    private static ProviderSet Providers(
        IDriverProvider? drivers = null,
        IProcessProvider? processes = null,
        IListeningPortProvider? listeningPorts = null) =>
        new(new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            drivers: drivers, processes: processes, listeningPorts: listeningPorts);

    [Fact]
    public void A_failed_driver_enumeration_is_reported_rather_than_read_as_no_drivers()
    {
        var findings = new LoadedDriversCollector(DriverBlocklist.Empty)
            .Collect(Providers(drivers: new DeniedDrivers()));

        Assert.NotEmpty(findings);
        Assert.All(findings, finding =>
            Assert.NotEqual(FindingSeverity.Benign, finding.Severity));
    }

    [Fact]
    public void A_failed_process_enumeration_is_reported_rather_than_read_as_no_processes()
    {
        var findings = new RunningProcessesCollector()
            .Collect(Providers(processes: new DeniedProcesses()));

        Assert.NotEmpty(findings);
    }

    [Fact]
    public void A_machine_that_genuinely_has_nothing_to_report_stays_silent()
    {
        // The other half of the contract, and the reason the fix is not "always warn":
        // a successful enumeration returning nothing is a real answer, and turning it
        // into a finding would cry wolf on every machine.
        var findings = new LoadedDriversCollector(DriverBlocklist.Empty)
            .Collect(Providers(drivers: new EmptyButSuccessfulDrivers()));

        Assert.Empty(findings);
    }

    /// <summary>
    /// DET-PORTS-MUET, the fourth occurrence of this shape and the one the guard in
    /// <c>ProviderStatusChannelTests</c> found before it did any harm.
    ///
    /// <para>
    /// The asymmetry that settles it: <b>no machine that is switched on listens on zero
    /// ports</b> — the RPC endpoint mapper, SMB, the local resolver — so an empty list here
    /// cannot be an answer. It used to produce « aucun port en écoute », on the one surface
    /// that says what the network can reach, which reads as good news.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failed_port_enumeration_is_reported_rather_than_read_as_no_exposure()
    {
        var findings = new ListeningPortsCollector()
            .Collect(Providers(listeningPorts: new DeniedPorts()));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("aucune ligne", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// A partial read keeps what it read. Reporting the gap must not cost the endpoints
    /// that were collected: answering with the finding alone would hide an exposed IPv4
    /// service because the IPv6 table refused, which is the same silence one table over.
    /// </summary>
    [Fact]
    public void A_partial_port_read_names_the_gap_without_dropping_what_it_saw()
    {
        var findings = new ListeningPortsCollector().Collect(Providers(
            listeningPorts: new PartiallyReadPorts(
                new ListeningPort("TCP", "0.0.0.0", 445, 4))));

        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Source == "ports en écoute");
        Assert.Contains(findings, f => f.Source == "TCP 0.0.0.0:445");
    }

    [Fact]
    public void An_absent_port_provider_is_a_coverage_gap_not_a_machine_without_services()
    {
        // No provider supplied at all — the default inside ProviderSet, which used to be an
        // empty list. Same trap as the drivers below, on the network exposure surface.
        var findings = new ListeningPortsCollector().Collect(Providers());

        Assert.NotEmpty(findings);
        Assert.All(findings, finding =>
            Assert.NotEqual(FindingSeverity.Benign, finding.Severity));
    }

    [Theory]
    // The judgement already accepted IPv6 before anything collected it; now that the
    // provider reads the v6 tables, these strings actually reach it. The canonical
    // compressed form is load-bearing: "::" is general exposure, "0:0:0:0:0:0:0:0" would
    // fall through to "named interface" and be treated as narrower than it is.
    [InlineData("::", false, true)]
    [InlineData("::1", true, false)]
    [InlineData("fe80::e0f7:5ffe:36ce:d9e4", false, false)]
    [InlineData("0.0.0.0", false, true)]
    [InlineData("127.0.0.1", true, false)]
    [InlineData("192.168.1.20", false, false)]
    public void Exposure_is_judged_the_same_way_for_both_address_families(
        string address, bool loopbackOnly, bool allInterfaces)
    {
        var port = new ListeningPort("TCP", address, 445, 4);

        Assert.Equal(loopbackOnly, port.IsLoopbackOnly);
        Assert.Equal(allInterfaces, port.IsAllInterfaces);
    }

    [Fact]
    public void An_unreadable_browser_profile_is_named_rather_than_dropped()
    {
        // A malformed Secure Preferences used to be swallowed by catch (JsonException) {},
        // so a whole profile vanished from the inventory and read as "no extensions".
        var read = ChromiumExtensions.ParseSettings("{ ceci n'est pas du JSON");

        Assert.Null(read);
    }

    [Fact]
    public void A_readable_profile_without_extensions_is_not_an_error()
    {
        // The other half: an empty profile is a real answer. Unlike drivers, a machine
        // with no browser extension is perfectly ordinary, so absence must stay silent.
        var read = ChromiumExtensions.ParseSettings("{\"extensions\":{\"settings\":{}}}");

        Assert.NotNull(read);
        Assert.Empty(read);
    }

    [Fact]
    public void An_absent_provider_is_a_coverage_gap_not_an_empty_machine()
    {
        // No provider supplied at all — the default inside ProviderSet. It must not
        // pretend the machine has no drivers either.
        var findings = new LoadedDriversCollector(DriverBlocklist.Empty).Collect(Providers());

        Assert.NotEmpty(findings);
    }
}
