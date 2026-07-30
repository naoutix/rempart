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

    private const string Truncated =
        "L'énumération WMI de Win32_SystemDriver s'est interrompue sur 0x80041004.";

    /// <summary>
    /// The same state one surface over: the WMI walk behind these two answers one object per
    /// call and can break on the tenth. Built through the constructor rather than a
    /// <c>Partial</c> factory, because <c>LiveDriverProvider</c> forwards whichever status
    /// the WMI read carried instead of choosing one.
    /// </summary>
    private sealed class PartiallyReadDrivers(params LoadedDriver[] drivers) : IDriverProvider
    {
        public DriverRead Enumerate() =>
            new(ReadStatus.AccessDenied, drivers, Truncated);
    }

    private sealed class PartiallyReadProcesses(params RunningProcess[] processes)
        : IProcessProvider
    {
        public ProcessRead Enumerate() =>
            new(ReadStatus.AccessDenied, processes, Truncated);
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

    /// <summary>
    /// A driver enumeration that broke halfway, which is what a WMI walk interrupted by
    /// <c>IEnumWbemClassObject::Next</c> now answers.
    ///
    /// <para>
    /// These two collectors opened on « <c>Status != Found</c> → return the finding », the
    /// shape the ports collector was corrected out of one issue ago. It is right for a total
    /// failure and wrong for a partial one: a walk that stops after the vulnerable driver
    /// would report a hole in the audit and drop the driver, on the surface a BYOVD attack
    /// lands on. Both surfaces here, because the shape is what is being fixed.
    /// </para>
    /// </summary>
    [Fact]
    public void A_partial_enumeration_names_the_gap_without_dropping_what_it_saw()
    {
        var drivers = new LoadedDriversCollector(DriverBlocklist.Empty).Collect(Providers(
            drivers: new PartiallyReadDrivers(
                new LoadedDriver("pilote", @"C:\Windows\System32\drivers\x.sys"))));

        Assert.Equal(2, drivers.Count);
        Assert.Contains(drivers, f => f.Source == "pilotes chargés");
        Assert.Contains(drivers, f => f.Source == "pilote");

        var processes = new RunningProcessesCollector().Collect(Providers(
            processes: new PartiallyReadProcesses(
                new RunningProcess(1234, 4, "p.exe", @"C:\Temp\p.exe", ""))));

        Assert.Equal(2, processes.Count);
        Assert.Contains(processes, f => f.Source == "processus courants");
        Assert.Contains(processes, f => f.Source == "p.exe");
    }

    /// <summary>
    /// The one aggregate any of these collectors computes, held against the read that makes
    /// it wrong.
    ///
    /// <para>
    /// <c>RunningProcessesCollector</c> groups by binary and prints « instances » in the
    /// finding's details, so a walk truncated at seven <c>svchost.exe</c> puts « 7 » in the
    /// report where twelve are running — a plausible, false count, which is the exact
    /// objection #143 raised against keeping a truncated netapi32 walk. Keeping the WMI prefix
    /// is nonetheless the right trade, and this test is what the argument rests on rather than
    /// a sentence in a commit: the figure is per binary, not a total anything reasons over,
    /// and it never travels alone. The same status that produced it forces the gap finding
    /// beside it, so a reader who sees the count also sees that the walk did not finish.
    /// </para>
    /// </summary>
    [Fact]
    public void A_truncated_walk_never_prints_its_instance_count_without_the_gap_beside_it()
    {
        var findings = new RunningProcessesCollector().Collect(Providers(
            processes: new PartiallyReadProcesses(
                new RunningProcess(10, 4, "svchost.exe", @"C:\W\svchost.exe", ""),
                new RunningProcess(20, 4, "svchost.exe", @"C:\W\svchost.exe", ""),
                new RunningProcess(30, 4, "svchost.exe", @"C:\W\svchost.exe", ""))));

        var counted = findings.Single(f => f.Source == "svchost.exe");
        Assert.Equal("3", counted.Details["instances"]);

        // The half that makes the count tolerable, asserted rather than argued: the same read
        // that shortened it also says so, at the same altitude, in the same report.
        var gap = findings.Single(f => f.Source == "processus courants");
        Assert.Equal(AuditGap.Unreadable, gap.Gap);
        Assert.Contains(Truncated, gap.Reasons);
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

    private const string MachineShellFolders =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";

    private const string UserShellFolders =
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";

    private const string CommonStartup =
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";

    private const string UserStartup =
        @"C:\Users\anon\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

    private static IReadOnlyList<Finding> Autoruns(
        FakeRegistryProvider registry, IFileSystemProvider files) =>
        new AutorunsCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(),
            signatures: new FakeSignatureProvider(), files: files));

    /// <summary>
    /// DET-FICHIERS-MUET, the fifth occurrence of this shape and the one the four before it
    /// left standing.
    ///
    /// <para>
    /// A startup folder the scan is refused used to return the same bare list as an empty
    /// one, so the report said « aucun autorun » about the first place a persistence is
    /// dropped. The refusal is now a finding of its own, naming the folder.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_startup_folder_is_reported_rather_than_read_as_no_autorun()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup);

        var finding = Assert.Single(
            Autoruns(registry, new FakeFileSystemProvider().WithDenied(CommonStartup)));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal(CommonStartup, finding.Source);
        Assert.Contains("accès refusé", string.Join(" ", finding.Reasons), StringComparison.Ordinal);

        // The kind decides how the finding is grouped and labelled — "[constats] 8 autorun"
        // in the console, ReportLabels.Family in the HTML and the Markdown. Left
        // unasserted, renaming it to anything at all kept the whole suite green while the
        // report grew a family nobody named.
        Assert.Equal("autorun", finding.Kind);

        // The sentence the collector falls back to when the read carries no diagnostic of
        // its own. A capture holding a status with no matching diagnostic — hand-edited, or
        // written by some later provider — would otherwise print a NOTABLE whose reason
        // line is blank, which is a finding that says nothing.
        // The reason TEXT, not the reason list: a list holding one empty string is
        // non-empty, and the console prints it as a blank arrow under the finding.
        Assert.NotEmpty(Assert.Single(Assert.Single(
            Autoruns(registry,
                new FakeFileSystemProvider().WithDenied(CommonStartup, reason: null))).Reasons));
    }

    /// <summary>
    /// The other half of the asymmetry, and the reason the fix is not « always warn ».
    ///
    /// <para>
    /// <b>An empty startup folder is the ordinary state of most machines</b> — unlike zero
    /// drivers or zero listening ports, which cannot be true of a running machine. Turning
    /// this into a finding would put a Notable on nearly every scan, and a report nobody
    /// finishes reading protects nothing. Two folders in one test because it is the
    /// <em>difference</em> that is the invariant: asserting them apart would let someone
    /// align them without failing anything.
    /// </para>
    /// </summary>
    [Fact]
    public void An_empty_or_absent_startup_folder_says_nothing_where_a_refused_one_speaks()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup)
            .WithText(UserShellFolders, "Startup", UserStartup);

        // Listed and empty on one side, not on disk at all on the other — the fake answers
        // NotFound for a folder it was never told about. Neither is a hole in what the scan
        // saw, so neither speaks.
        var silent = Autoruns(registry, new FakeFileSystemProvider().With(CommonStartup));

        Assert.Empty(silent);
    }

    /// <summary>
    /// The partial case, and the answer to « faut-il un <c>Partial</c> comme les ports ? ».
    ///
    /// <para>
    /// <c>ListFiles</c> takes the directory as an argument, so one call is one folder and a
    /// read cannot come back half-done the way the four listening tables behind a single
    /// <c>Enumerate</c> can. The partiality is real all the same, one level up: the machine
    /// folder can be refused while the user folder answers. Dropping the executable found in
    /// the readable one because the other refused would trade one silence for another —
    /// exactly what <c>ListeningPortRead.Partial</c> exists to prevent, obtained here by the
    /// collector adding the finding instead of returning it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_folder_does_not_cost_the_files_of_the_one_that_answered()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup)
            .WithText(UserShellFolders, "Startup", UserStartup);

        var files = new FakeFileSystemProvider()
            .WithDenied(CommonStartup)
            .With(UserStartup, $@"{UserStartup}\evil.exe");

        var findings = Autoruns(registry, files);

        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Source == CommonStartup && f.Target == "—");
        Assert.Contains(findings, f => f.Target == $@"{UserStartup}\evil.exe");
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

    /// <summary>
    /// The fileless persistence surface, on the same truncated walk.
    ///
    /// <para>
    /// <c>root\subscription</c> is where a permanent WMI subscription hides, and it is read
    /// through three enumerations that can each break in mid-walk. The two consumer queries
    /// returned as soon as the read was refused, and the filter query returned in silence on
    /// anything other than <c>Found</c>; either way a consumer already handed over was
    /// dropped along with the walk that carried it — the one finding this collector exists to
    /// produce, lost to the failure that came after it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_truncated_subscription_walk_keeps_the_consumer_it_already_saw()
    {
        var findings = new WmiSubscriptionsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            wmi: new FakeWmiProvider(WmiRead.Partial(
                [
                    new WmiInstance(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Name"] = "Mise à jour",
                        ["CommandLineTemplate"] = @"C:\Temp\x.exe",
                    }),
                ],
                Truncated))));

        // The fake answers the same read to the three queries this collector makes, so each
        // one contributes its instance; what matters is that none of them contributes zero.
        Assert.Contains(findings, f => f.Reasons.Any(
            reason => reason.Contains("0x80041004", StringComparison.Ordinal)));

        // The two consumer walks: a payload already enumerated stays accused.
        Assert.Equal(2, findings.Count(f => f.Severity == FindingSeverity.Suspicious));

        // And the filter walk, which reported nothing at all on a failed status — no refusal
        // finding, which is right (the two above already name the namespace), but no filters
        // either, which lost what it had. Asserted on its own because it is the one branch of
        // the three that stays silent about the failure, so nothing else here would notice it
        // going back to returning early.
        Assert.Contains(findings, f => f.Source.StartsWith("__EventFilter", StringComparison.Ordinal));
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
