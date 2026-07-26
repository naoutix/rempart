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

    private static ProviderSet Providers(
        IDriverProvider? drivers = null, IProcessProvider? processes = null) =>
        new(new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            drivers: drivers, processes: processes);

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
