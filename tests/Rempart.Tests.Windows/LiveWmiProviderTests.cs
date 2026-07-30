using System.Runtime.InteropServices;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Updates;
using Rempart.Windows;
using Rempart.Windows.Wmi;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against the real WMI. Answers the question open since M0: System.Management does not
/// survive Native AOT, but the WMI COM interfaces stay accessible through interop
/// generated at compile time.
///
/// <para>
/// <b>These tests judge the decoding, not the runner's WMI.</b> A shared Windows runner
/// periodically answers every query with zero rows — five occurrences in one day, once on
/// a branch that changed no C# at all. That is a machine failing to answer, and failing
/// the build on it says nothing about Rempart. What must never be tolerated is the other
/// failure: WMI answering, and the decoding getting it wrong. So each test below asks
/// first whether WMI answered, and only then holds it to account.
/// </para>
/// <para>
/// A skipped check is stated on the test output rather than passing quietly: a test that
/// can pass vacuously has to say when it did, or it becomes a green light that means
/// nothing.
/// </para>
/// </summary>
public sealed class LiveWmiProviderTests(ITestOutputHelper output)
{
    private readonly LiveWmiProvider wmi = new();

    /// <summary>
    /// Whether WMI is answering at all on this machine, probed through a class every
    /// Windows installation carries. Zero rows here cannot mean "no such class": it means
    /// the service is not serving.
    /// </summary>
    private bool WmiAnswers(string reason)
    {
        var probe = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption"]);

        if (probe.Status == ReadStatus.Found && probe.Instances.Count > 0)
        {
            return true;
        }

        output.WriteLine(
            $"WMI n'a pas répondu sur cette machine (Win32_OperatingSystem -> {probe.Status}, "
            + $"{probe.Instances.Count} instance(s), diagnostic : {probe.Diagnostic ?? "aucun"}). "
            + $"Contrôle non exécuté : {reason}");

        return false;
    }

    [Fact]
    public void Reads_a_class_every_machine_has()
    {
        if (!WmiAnswers("lecture de Win32_OperatingSystem")) { return; }

        var read = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption", "Version"]);

        Assert.Equal(ReadStatus.Found, read.Status);
        var os = Assert.Single(read.Instances);
        Assert.StartsWith("Microsoft Windows", os.Find("Caption")!, StringComparison.Ordinal);
        Assert.StartsWith("10.", os.Find("Version")!, StringComparison.Ordinal);
    }

    [Fact]
    public void Decodes_a_numeric_property()
    {
        // A wrong VARIANT decode would return a plausible but wrong value: that is
        // the failure mode to rule out.
        if (!WmiAnswers("décodage d'une propriété numérique")) { return; }

        var read = wmi.Query(@"root\CIMV2", "Win32_ComputerSystem", ["NumberOfProcessors"]);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.True(int.TryParse(read.Instances[0].Find("NumberOfProcessors"), out var count));
        Assert.InRange(count, 1, 64);
    }

    [Fact]
    public void An_unknown_namespace_is_reported_rather_than_thrown()
    {
        var read = wmi.Query(@"root\CeNamespaceNExistePas", "Quoi", ["Rien"]);

        Assert.NotEqual(ReadStatus.Found, read.Status);
    }

    [Fact]
    public void An_unknown_class_yields_no_instances()
    {
        // Guarded like the positive checks, and for a subtler reason: a mute WMI returns
        // NotFound for everything, so without the probe this test passes exactly when the
        // machine is broken. A green that survives the failure it should detect is worse
        // than no test.
        if (!WmiAnswers("classe inconnue rendue sans instance")) { return; }

        Assert.Equal(ReadStatus.NotFound,
            wmi.Query(@"root\CIMV2", "Win32_CetteClasseNExistePas", ["Rien"]).Status);
    }

    [Fact]
    public void Repeated_queries_stay_stable_and_do_not_leak()
    {
        // Each read allocates BSTRs and COM interfaces. A missing release is invisible
        // on a single call but exhausts a full scan.
        if (!WmiAnswers("stabilité de 30 lectures répétées")) { return; }

        var first = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption"]);

        for (var i = 0; i < 30; i++)
        {
            var read = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption"]);
            Assert.Equal(first.Instances[0].Find("Caption"), read.Instances[0].Find("Caption"));
        }
    }

    [Fact]
    public void BitLocker_status_is_read_or_cleanly_refused()
    {
        // The BitLocker namespace requires elevation. Without rights, the denial must
        // be clean: the engine turns it into "not verifiable", never into a
        // non-compliance.
        var read = wmi.Query(
            @"root\CIMV2\Security\MicrosoftVolumeEncryption",
            "Win32_EncryptableVolume",
            ["DriveLetter", "ProtectionStatus"]);

        Assert.Contains(read.Status, new[] { ReadStatus.Found, ReadStatus.AccessDenied, ReadStatus.NotFound });
    }

    /// <summary>
    /// A COM failure carrying a chosen HRESULT, so that the three tests below judge the
    /// mapping rather than the runner's WMI. Synthesized because the codes that matter — a
    /// damaged repository, a service that will not start — cannot be provoked on a healthy
    /// machine, and the check above, which only asks that the status be one of three enum
    /// values, cannot tell any of them from a denial.
    /// </summary>
    private static COMException Com(uint hresult) =>
        new("échec COM simulé", unchecked((int)hresult));

    [Theory]
    [InlineData(0x80041010u)] // WBEM_E_INVALID_CLASS: damaged or partial repository
    [InlineData(0x800706BAu)] // RPC_S_SERVER_UNAVAILABLE: Winmgmt is not serving
    [InlineData(0x80041013u)] // WBEM_E_PROVIDER_LOAD_FAILURE
    [InlineData(0x80041045u)] // WBEM_E_SERVER_TOO_BUSY
    [InlineData(0x80041014u)] // WBEM_E_INITIALIZATION_FAILURE
    public void A_com_failure_names_its_hresult_instead_of_claiming_a_denial(uint hresult)
    {
        // Every one of these once returned WmiRead.AccessDenied with a null diagnostic, so
        // the four `type: wmi` rules — plus drivers, processes and unquoted service paths —
        // advised « relancer en administrateur » to a user who already was.
        var read = LiveWmiProvider.Classify(Com(hresult));

        Assert.NotNull(read.Diagnostic);
        Assert.Contains($"0x{hresult:X8}", read.Diagnostic, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0x80041003u)] // WBEM_E_ACCESS_DENIED
    [InlineData(0x80070005u)] // E_ACCESSDENIED
    [InlineData(0x80041062u)] // WBEM_E_PRIVILEGE_NOT_HELD
    public void A_genuine_refusal_stays_a_refusal_without_a_diagnostic(uint hresult)
    {
        // The counterpart: dropping one of these from the list would turn a real denial into
        // a failure, and « relancer en administrateur » would stop being said when it is the
        // right advice.
        var read = LiveWmiProvider.Classify(Com(hresult));

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Diagnostic);
    }

    [Theory]
    [InlineData(0x8004100Eu)] // WBEM_E_INVALID_NAMESPACE: feature absent from this edition
    [InlineData(0x80041002u)] // WBEM_E_NOT_FOUND
    public void An_absent_namespace_is_absence_not_refusal(uint hresult)
    {
        Assert.Equal(ReadStatus.NotFound, LiveWmiProvider.Classify(Com(hresult)).Status);
    }

    /// <summary>
    /// A stand-in for <c>IEnumWbemClassObject::Next</c>, so the tests below judge how the
    /// enumeration is bounded rather than the runner's WMI.
    ///
    /// <para>
    /// It is the only way to reach the case that matters. A WMI provider that stops
    /// answering cannot be arranged on a healthy machine, and the whole failure is that
    /// nothing comes back — a real one would hang the suite instead of failing it. So the
    /// answers are scripted, and <see cref="Waits"/> records what each call was given as its
    /// deadline, which is the value the defect was about.
    /// </para>
    /// </summary>
    private sealed class Enumeration(
        Func<int, (int Hresult, int Returned)> answer, int delayMilliseconds = 0)
    {
        /// <summary>The timeout handed to each call, in the order they were made.</summary>
        public List<int> Waits { get; } = [];

        public int Calls { get; private set; }

        public int Next(int timeout, IntPtr[] slot, out int returned)
        {
            Waits.Add(timeout);

            // A provider that answers, and takes its time doing it. Without this the fake
            // costs nothing and no budget could ever run out — which is a fake that cannot
            // reproduce what it exists to reproduce.
            if (delayMilliseconds > 0)
            {
                Thread.Sleep(delayMilliseconds);
            }

            var (hresult, count) = answer(Calls++);
            slot[0] = new IntPtr(Calls);
            returned = count;

            return hresult;
        }
    }

    /// <summary>Stands in for the COM object read, without touching COM.</summary>
    private static WmiInstance? ReadSlot(IntPtr pointer) =>
        new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Handle"] = pointer.ToString(),
        });

    private const int WbemSNoError = 0;
    private const int WbemSFalse = 1;       // no more objects
    private const int WbemSTimedout = 0x40004;

    /// <summary>
    /// The defect: <c>Next</c> was called with <c>WBEM_INFINITE</c>, so a provider that
    /// never stops answering never gives the scan back.
    ///
    /// <para>
    /// The fake gives up after 200 objects on purpose — an honest reproduction would hang
    /// this suite rather than fail it, and a test that hangs reports nothing. What is
    /// asserted is that the drain stopped long before that ceiling, on its own budget.
    /// DISM and netsh have carried one since they were written; WMI, which is read on four
    /// shipped rules plus drivers, processes and service paths, had none.
    /// </para>
    /// </summary>
    [Fact]
    public void An_enumeration_that_never_ends_stops_on_its_budget_instead_of_the_scan()
    {
        var enumeration = new Enumeration(
            call => call < 200 ? (WbemSNoError, 1) : (WbemSFalse, 0), delayMilliseconds: 5);

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromMilliseconds(120), "Win32_Process");

        Assert.NotNull(read.Diagnostic);
        Assert.Contains("Win32_Process", read.Diagnostic, StringComparison.Ordinal);

        Assert.True(enumeration.Calls < 200,
            $"{enumeration.Calls} appels à Next : l'énumération est allée au bout du faux au "
            + "lieu de s'arrêter sur son délai. Sur une vraie machine, le faux n'a pas de "
            + "fin et le scan ne rend jamais la main.");

        // And what it collected before giving up is not handed over as a lecture complète:
        // a truncated enumeration presented as Found is the silence this repository keeps
        // finding one layer down.
        Assert.NotEqual(ReadStatus.Found, read.Status);
        Assert.Empty(read.Instances);
    }

    /// <summary>
    /// The other way the deadline arrives: <c>Next</c> itself reports it.
    ///
    /// <para>
    /// <c>WBEM_S_TIMEDOUT</c> is 0x40004 — a <em>success</em> code, sign bit clear — so the
    /// loop condition « HRESULT not negative » accepted it and the zero objects it came with
    /// ended the walk. Two instances read out of a hundred were then returned as
    /// <see cref="ReadStatus.Found"/>: not a failure, not a refusal, a complete answer that
    /// happened to be short.
    /// </para>
    /// </summary>
    [Fact]
    public void A_provider_that_reports_a_timeout_names_it_instead_of_shortening_the_list()
    {
        var enumeration = new Enumeration(call =>
            call < 2 ? (WbemSNoError, 1) : (WbemSTimedout, 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        Assert.NotEqual(ReadStatus.Found, read.Status);
        Assert.NotNull(read.Diagnostic);
        Assert.Contains("Win32_SystemDriver", read.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The count the deadline used to swallow.
    ///
    /// <para>
    /// A timeout discards what the walk had collected — that is #143's decision and the two
    /// tests above pin it — but it used to discard it without a word. A report could then not
    /// tell a provider that never answered at all from one that answered two hundred times
    /// and then stopped: two different machines, two different things to go and look at, one
    /// identical sentence. The objects are still dropped here; what is asserted is that their
    /// number no longer is. It is the asymmetry with <see cref="WmiRead.Partial"/> stated,
    /// not resolved.
    /// </para>
    /// </summary>
    [Fact]
    public void A_deadline_says_how_many_objects_it_is_discarding()
    {
        var enumeration = new Enumeration(call =>
            call < 4 ? (WbemSNoError, 1) : (WbemSTimedout, 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        Assert.Empty(read.Instances);
        Assert.NotNull(read.Diagnostic);
        Assert.Contains("4 instance(s)", read.Diagnostic, StringComparison.Ordinal);

        // Still never dressed as a refusal: the deadline denied nothing, it ran out.
        Assert.DoesNotContain("administrateur", read.Diagnostic, StringComparison.OrdinalIgnoreCase);

        // And a deadline reached before anything arrived has no loss to report. « 0
        // instance(s) écartées » would claim one that never happened, which is the same kind
        // of false precision as the silence it replaces.
        var immediate = new Enumeration(_ => (WbemSTimedout, 0));

        var nothing = LiveWmiProvider.Drain(
            immediate.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_Process");

        Assert.NotNull(nothing.Diagnostic);
        Assert.DoesNotContain("instance(s)", nothing.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The third way a walk ends short, and the one the two above left standing: <c>Next</c>
    /// returns a <em>failure</em> once the enumeration is already running.
    ///
    /// <para>
    /// <c>ExecQuery</c> had succeeded, so the namespace was open and the class was there;
    /// what breaks afterwards is the provider answering the walk — a third-party WMI
    /// provider that faults, a repository that goes bad, a call cancelled underneath. The
    /// loop treated that exactly like the end of the enumeration, and handed over what it
    /// had collected as <see cref="ReadStatus.Found"/>: a truncated inventory presented as
    /// the machine's.
    /// </para>
    ///
    /// <para>
    /// Both halves are asserted together, because it is their conjunction that is the fix.
    /// Not <c>Found</c> — the list is not the machine's inventory. And not empty either:
    /// dropping the three objects that did arrive would trade one silence for another, which
    /// is what <c>ListeningPortRead.Partial</c> and <c>ScheduledTaskRead.Partial</c> exist to
    /// prevent one interface over.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(0x80041004u)] // WBEM_E_PROVIDER_FAILURE: the provider broke while answering
    [InlineData(0x80041032u)] // WBEM_E_CALL_CANCELLED
    [InlineData(0x80041015u)] // WBEM_E_TRANSPORT_FAILURE
    public void An_enumeration_broken_mid_walk_keeps_what_it_read_and_names_the_code(uint hresult)
    {
        var enumeration = new Enumeration(call =>
            call < 3 ? (WbemSNoError, 1) : (unchecked((int)hresult), 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        Assert.NotEqual(ReadStatus.Found, read.Status);
        Assert.Equal(3, read.Instances.Count);

        Assert.NotNull(read.Diagnostic);
        Assert.Contains("Win32_SystemDriver", read.Diagnostic, StringComparison.Ordinal);

        // The code, printed as itself. It is the only thing a reader can search for, and the
        // one this layer must not interpret: 0x80041004 and 0x80041045 sit two digits apart
        // and mean « ce fournisseur est cassé » and « rappelle plus tard ».
        Assert.Contains($"0x{hresult:X8}", read.Diagnostic, StringComparison.Ordinal);

        // And never « relancer en administrateur ». The query had already been accepted, so
        // nothing was denied to this scan; advising elevation to a user who has it is the
        // confusion that left WMI mute for two milestones, and #147 found it again next door.
        Assert.DoesNotContain("administrateur", read.Diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refus", read.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The boundary of the case above, and the reason it is drawn where it is.
    ///
    /// <para>
    /// <c>ExecQuery</c> is asked with <c>WBEM_FLAG_RETURN_IMMEDIATELY</c>, so it is only
    /// semi-synchronous and the query's own verdict lands on the first <c>Next</c>. An
    /// unknown class reaches this loop as <c>WBEM_E_INVALID_CLASS</c> — measured on this
    /// machine, and the reason <c>An_unknown_class_yields_no_instances</c> above passes at
    /// all. Nothing was handed over, so there is no truncated inventory to report, and
    /// calling it one would turn every class absent from a Windows edition into a failure.
    /// </para>
    ///
    /// <para>
    /// Written against the fake rather than left to the live test, which is guarded and
    /// silently skips on a runner whose WMI is not answering — the branch would then be
    /// unwatched on exactly the machines where it matters.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failure_on_the_very_first_call_is_the_query_answering_late()
    {
        var enumeration = new Enumeration(_ => (unchecked((int)0x80041010u), 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_CetteClasseNExistePas");

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Empty(read.Instances);
        Assert.Null(read.Diagnostic);
    }

    /// <summary>
    /// Every wait is what is left of the budget, not the budget again: a provider handing
    /// back one object just before each deadline would otherwise never exhaust anything, and
    /// the ceiling would bound a single call rather than the enumeration.
    /// </summary>
    [Fact]
    public void Each_wait_is_bounded_by_what_remains_of_the_budget()
    {
        var enumeration = new Enumeration(call => call < 3 ? (WbemSNoError, 1) : (WbemSFalse, 0));

        LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(2), "Win32_OperatingSystem");

        Assert.NotEmpty(enumeration.Waits);

        Assert.All(enumeration.Waits, wait => Assert.InRange(wait, 1, 2000));

        Assert.True(enumeration.Waits[^1] <= enumeration.Waits[0],
            $"Les délais passés à Next ne décroissent pas ({string.Join(", ", enumeration.Waits)}) : "
            + "chacun repart du budget entier, donc l'énumération n'en a pas.");
    }

    /// <summary>
    /// The half that must not move, and the reason the fix is not « toujours échouer » : an
    /// enumeration that finishes inside its budget answers exactly as before, and an empty
    /// one is still an absence rather than a failure.
    /// </summary>
    [Fact]
    public void An_enumeration_that_finishes_in_time_is_unchanged()
    {
        var two = new Enumeration(call => call < 2 ? (WbemSNoError, 1) : (WbemSFalse, 0));

        var read = LiveWmiProvider.Drain(
            two.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_OperatingSystem");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal(2, read.Instances.Count);
        Assert.Null(read.Diagnostic);

        var none = new Enumeration(_ => (WbemSFalse, 0));

        Assert.Equal(ReadStatus.NotFound, LiveWmiProvider.Drain(
            none.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_OperatingSystem").Status);
    }

    /// <summary>Answers the same read to every query, whatever is asked of it.</summary>
    private sealed class OneAnswer(WmiRead read) : IWmiProvider
    {
        public WmiRead Query(
            string namespacePath, string className, IReadOnlyList<string> properties) => read;
    }

    private static WmiInstance Instance(params (string Name, string Value)[] properties) =>
        new(properties.ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// The two consumers of <see cref="WmiRead"/> that live on this side of the wall, and
    /// the reason a <c>Partial</c> read had to be walked all the way through rather than
    /// just produced.
    ///
    /// <para>
    /// Both opened on « <c>Status != Found</c> → an empty list plus a sentence », which was
    /// right while the only failures were total. A partial read handed to that shape loses
    /// every driver and every process it did collect, and the report says « aucun pilote » —
    /// the very silence DET-WMI-MUET closed, re-entered through the door this fix opens.
    /// Both surfaces in one test because it is the shared shape that is the invariant.
    /// </para>
    /// </summary>
    [Fact]
    public void A_partial_read_keeps_its_drivers_and_its_processes()
    {
        const string Reason = "Interrompue sur 0x80041004 après 1 instance(s).";

        var drivers = new LiveDriverProvider(new OneAnswer(WmiRead.Partial(
            [
                Instance(
                    ("Name", "pilote"),
                    ("PathName", @"C:\Windows\System32\drivers\x.sys"),
                    ("State", "Running")),
            ],
            Reason))).Enumerate();

        Assert.NotEqual(ReadStatus.Found, drivers.Status);
        Assert.Equal("pilote", Assert.Single(drivers.Drivers).Name);
        Assert.Equal(Reason, drivers.Diagnostic);

        var processes = new LiveProcessProvider(new OneAnswer(WmiRead.Partial(
            [
                Instance(
                    ("ProcessId", "1234"),
                    ("Name", "p.exe"),
                    ("ExecutablePath", @"C:\Temp\p.exe")),
            ],
            Reason))).Enumerate();

        Assert.NotEqual(ReadStatus.Found, processes.Status);
        Assert.Equal(1234, Assert.Single(processes.Processes).Pid);
        Assert.Equal(Reason, processes.Diagnostic);
    }

    /// <summary>
    /// The half that must not move on those two: a total failure still answers an empty
    /// list, so nothing reads a refused enumeration as a machine with one driver in it.
    /// Asserted beside the case above rather than apart, because the fix is the
    /// <em>difference</em> between them.
    /// </summary>
    [Fact]
    public void A_total_failure_still_answers_an_empty_inventory()
    {
        var drivers = new LiveDriverProvider(
            new OneAnswer(WmiRead.Failed("COM 0x80041010 : dépôt endommagé."))).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, drivers.Status);
        Assert.Empty(drivers.Drivers);
        Assert.Equal("COM 0x80041010 : dépôt endommagé.", drivers.Diagnostic);

        var processes = new LiveProcessProvider(
            new OneAnswer(WmiRead.AccessDenied)).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, processes.Status);
        Assert.Empty(processes.Processes);

        // WmiRead.AccessDenied carries no diagnostic — a genuine refusal has nothing to
        // explain — so the consumer's own sentence is what reaches the report.
        Assert.Contains("administrateur", processes.Diagnostic!, StringComparison.Ordinal);
    }

    /// <summary>A slot that decodes into a running driver, so a real walk carries real ones.</summary>
    private static WmiInstance? ReadDriverSlot(IntPtr pointer) =>
        new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Name"] = $"pilote{pointer}",
            ["PathName"] = $@"C:\Windows\System32\drivers\pilote{pointer}.sys",
            ["State"] = "Running",
        });

    /// <summary>The two providers <see cref="ProviderSet"/> demands and this test never reads.</summary>
    private sealed class NoRegistry : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) => RegistryRead.NotFound;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.NotFound;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.NotFound;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.NotFound;
    }

    private sealed class SomeMachine : ISystemInfoProvider
    {
        public SystemInfo Read() => new("TEST", "10.0.26200", true, false, 8, 0, "UEFI");
    }

    /// <summary>
    /// The invariant asserted where it is actually read, rather than where it is produced.
    ///
    /// <para>
    /// Every other test here stops at the <see cref="WmiRead"/>, which leaves the claim — the
    /// HRESULT never disguises itself as a rights refusal — resting on a string that two more
    /// layers are entitled to replace. <c>LiveDriverProvider</c> holds a fallback sentence
    /// advising elevation and <c>LoadedDriversCollector</c> holds another; both fire on
    /// <c>Diagnostic == null</c>, so the whole invariant hangs on one diagnostic surviving the
    /// trip from the COM loop to the finding. Measured on the first-call branch, that trip
    /// fails: a <c>NotFound</c> with no diagnostic comes out of the report as « relancer en
    /// administrateur ». So the chain is walked here rather than assumed, real
    /// <see cref="LiveWmiProvider.Drain"/> at one end and the real collector at the other.
    /// </para>
    /// </summary>
    [Fact]
    public void A_broken_walk_reaches_the_report_as_its_code_and_never_as_a_refusal()
    {
        var enumeration = new Enumeration(call =>
            call < 2 ? (WbemSNoError, 1) : (unchecked((int)0x80041004u), 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadDriverSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        var findings = new LoadedDriversCollector(DriverBlocklist.Empty).Collect(
            new ProviderSet(new NoRegistry(), new SomeMachine(),
                drivers: new LiveDriverProvider(new OneAnswer(read))));

        var reason = Assert.Single(findings.Single(f => f.Source == "pilotes chargés").Reasons);

        Assert.Contains("0x80041004", reason, StringComparison.Ordinal);

        // The point of the whole chain, at its end rather than at its start.
        Assert.DoesNotContain("administrateur", reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refus", reason, StringComparison.OrdinalIgnoreCase);

        // And the two drivers the walk did hand over are judged, not dropped alongside the
        // failure that followed them.
        Assert.Equal(2, findings.Count(f => f.Source != "pilotes chargés"));
    }
}
