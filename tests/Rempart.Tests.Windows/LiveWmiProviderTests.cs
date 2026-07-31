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

    /// <summary>
    /// <c>WBEM_E_INVALID_CLASS</c> moved here from the failure list above, and it is the one
    /// entry of this mapping that was decided by measurement rather than by reading a header.
    ///
    /// <para>
    /// It was classified as « damaged or partial repository » — plausible, and not what the
    /// machine does. Querying <c>Win32_CetteClasseNExistePas</c> on this workstation returns
    /// 0x80041010 on the first <c>Next</c>, so it is the ordinary answer for a class a Windows
    /// edition does not carry, which is an absence and the same family as the two codes
    /// beside it. Nothing observable produced it from a damaged repository; those arrive as
    /// <c>WBEM_E_CRITICAL_ERROR</c> or <c>WBEM_E_INITIALIZATION_FAILURE</c>, which stay on the
    /// failure arm.
    /// </para>
    ///
    /// <para>
    /// The move is what lets <c>Drain</c>'s first-call branch defer to <see
    /// cref="LiveWmiProvider.Classify"/> instead of keeping a second opinion of its own: the
    /// answer an absent class already got from that branch is <c>NotFound</c>, and this is
    /// where that answer now comes from.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(0x8004100Eu)] // WBEM_E_INVALID_NAMESPACE: feature absent from this edition
    [InlineData(0x80041002u)] // WBEM_E_NOT_FOUND
    [InlineData(0x80041010u)] // WBEM_E_INVALID_CLASS: measured on an absent class
    public void An_absent_namespace_is_absence_not_refusal(uint hresult)
    {
        var read = LiveWmiProvider.Classify(Com(hresult));

        Assert.Equal(ReadStatus.NotFound, read.Status);

        // No diagnostic, and this half is load-bearing rather than incidental: a consumer
        // reads « diagnostic écrit » as « the surface failed » and routes it to AuditGap.
        // Unreadable. An absence did not fail.
        Assert.Null(read.Diagnostic);
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

        /// <summary>
        /// How many objects this fake actually put in the slot. Counted rather than derived
        /// from the script, because the exit that runs the budget out decides for itself how
        /// far it gets — and it is the exit whose objects nothing was watching.
        /// </summary>
        public int Handed { get; private set; }

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

            if (count == 1)
            {
                Handed++;
            }

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

        // And what it collected before giving up is neither presented as a lecture complète
        // — a truncated enumeration handed over as Found is the silence this repository keeps
        // finding one layer down — nor thrown away along with the deadline that ended it.
        // Exactly, not merely « non vide »: the budget is checked before each call, so every
        // call that was made handed over its object and every one of them must still be here.
        //
        // And the status on its value: NotFound would also be « pas Found » and would mean the
        // machine has no processes, which is the reading the two collectors that narrow their
        // gap branch would act on by staying silent. Failed since #177, not AccessDenied — a
        // deadline denied nothing — and those two collectors were widened to « AccessDenied or
        // Failed » in the same commit, which is why this assertion is on the value and not on
        // « pas Found »: narrowing them back turns this surface mute again.
        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Equal(enumeration.Calls, read.Instances.Count);
        Assert.NotEmpty(read.Instances);
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

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.NotNull(read.Diagnostic);
        Assert.Contains("Win32_SystemDriver", read.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The inventory the deadline used to throw away.
    ///
    /// <para>
    /// A timeout discarded what the walk had collected, then — after #153 — said how many
    /// objects it was discarding. Naming a loss is not undoing it: a walk stopped after two
    /// hundred drivers still answered « aucun pilote », on the surface a BYOVD attack lands
    /// on. It answers with the two hundred now, exactly as a walk broken by a negative
    /// HRESULT already did, and the status still says the inventory is not the machine's.
    /// </para>
    ///
    /// <para>
    /// The count stays in the sentence. It is what tells a provider mute from the first call
    /// apart from one that stopped after two hundred objects, and it is now a claim about
    /// what the reader has in hand rather than about what was thrown away.
    /// </para>
    /// </summary>
    [Fact]
    public void A_deadline_keeps_what_the_walk_had_read_and_names_the_gap()
    {
        var enumeration = new Enumeration(call =>
            call < 4 ? (WbemSNoError, 1) : (WbemSTimedout, 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        Assert.Equal(4, read.Instances.Count);

        // And never as a complete one: the four are what arrived, not what the machine runs.
        //
        // On the value and not on « pas Found », because the two are not the same claim and
        // only one of them is true. NotFound also satisfies « pas Found », and it means « the
        // machine has none » — which is how UnquotedServicePathCollector and
        // WmiSubscriptionsCollector read it: both open their gap finding on a narrow test of
        // the status, so a deadline calling itself an absence goes out of those two surfaces
        // as complete silence, no finding at all.
        //
        // Failed and not AccessDenied since #177. « A failure, not a refusal » used to be
        // spelled AccessDenied + a written diagnostic — the pair, because the status alone
        // could not say it — and it is now spelled by the status. The two collectors read
        // `AccessDenied or Failed`, so this value reaches them; narrowing either back is what
        // this assertion is against.
        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);

        Assert.NotNull(read.Diagnostic);
        Assert.Contains("Win32_SystemDriver", read.Diagnostic, StringComparison.Ordinal);
        Assert.Contains("4 instance(s)", read.Diagnostic, StringComparison.Ordinal);

        // Still never dressed as a refusal: the deadline denied nothing, it ran out.
        Assert.DoesNotContain("administrateur", read.Diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refus", read.Diagnostic, StringComparison.OrdinalIgnoreCase);

        // And the sentence no longer says objects were dropped, because none were. A reader
        // acting on « écartées » would go looking for an inventory that is in front of them.
        Assert.DoesNotContain("écart", read.Diagnostic, StringComparison.OrdinalIgnoreCase);

        // A deadline reached before anything arrived has no count to give. « 0 instance(s) »
        // would claim a prefix that never existed, which is the same false precision as the
        // silence #153 replaced.
        var immediate = new Enumeration(_ => (WbemSTimedout, 0));

        var nothing = LiveWmiProvider.Drain(
            immediate.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_Process");

        Assert.Equal(ReadStatus.Failed, nothing.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, nothing.Status);
        Assert.NotNull(nothing.Diagnostic);
        Assert.DoesNotContain("instance(s)", nothing.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The property behind the two tests above, asserted as a property rather than as three
    /// more cases.
    ///
    /// <para>
    /// <c>Drain</c> has four ways out — the enumeration ending, the budget running out,
    /// <c>WBEM_S_TIMEDOUT</c>, and a negative HRESULT — and until now they disagreed about
    /// what happens to the objects already handed over: two kept them, one dropped them, and
    /// the fourth could not have any. Enumerating the exits is exactly the coverage this
    /// repository keeps being caught doing, and it is what let the disagreement survive #153.
    /// What is asserted here is the invariant itself: <b>whatever ends the walk, the read
    /// carries every object the walk was handed</b>. A fifth exit added later either satisfies
    /// it or has to say why.
    /// </para>
    ///
    /// <para>
    /// <b>All four, including the one no HRESULT can script.</b> Three of the exits are chosen
    /// by what <c>Next</c> answers; the fourth is chosen by the clock, at the top of the loop,
    /// and a theory handing every case a thirty-second budget never reaches it. It was the
    /// exit whose objects had been thrown away, so leaving it outside the property that claims
    /// to cover it was the one gap worth closing here: replacing its <c>instances</c> with an
    /// empty list reddens <c>An_enumeration_that_never_ends_…</c> and used to leave this
    /// theory green. Hence the last case, and hence <c>Enumeration.Handed</c> — how far the
    /// clock lets a walk get is the runner's business, so what the fake actually handed over
    /// is counted rather than assumed, with <paramref name="atLeast"/> keeping the equality
    /// from being two zeroes agreeing.
    /// </para>
    /// </summary>
    /// <param name="ending">The answer that ends the walk, once the objects are exhausted.</param>
    /// <param name="offered">How many objects the script is willing to hand over.</param>
    /// <param name="budgetMilliseconds">The walk's whole budget.</param>
    /// <param name="atLeast">
    /// How many objects must really have been handed over for the case to prove anything.
    /// </param>
    [Theory]
    [InlineData(1u, 0, 30_000, 0)]           // WBEM_S_FALSE: the enumeration simply ends
    [InlineData(1u, 3, 30_000, 3)]
    [InlineData(0x40004u, 0, 30_000, 0)]     // WBEM_S_TIMEDOUT: the provider reports the deadline
    [InlineData(0x40004u, 3, 30_000, 3)]
    [InlineData(0x80041004u, 0, 30_000, 0)]  // WBEM_E_PROVIDER_FAILURE: the walk breaks
    [InlineData(0x80041004u, 3, 30_000, 3)]
    [InlineData(1u, 10_000, 120, 1)]         // the budget, reached at the top of the loop
    public void No_way_of_ending_a_walk_drops_an_object_it_was_already_handed(
        uint ending, int offered, int budgetMilliseconds, int atLeast)
    {
        var enumeration = new Enumeration(
            call => call < offered ? (WbemSNoError, 1) : (unchecked((int)ending), 0),
            delayMilliseconds: 5);

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromMilliseconds(budgetMilliseconds),
            "Win32_SystemDriver");

        Assert.Equal(enumeration.Handed, read.Instances.Count);

        Assert.True(enumeration.Handed >= atLeast,
            $"Le faux n'a rendu que {enumeration.Handed} objet(s) sur les {atLeast} attendus : "
            + "l'égalité ci-dessus est satisfaite par deux zéros et ne dit rien de la sortie "
            + "visée.");
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
    /// is what <c>ListeningPortRead.Partial</c> and <c>ScheduledTaskRead.Partially</c> exist to
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
    ///
    /// <para>
    /// This is the half that must not move now that the branch defers to
    /// <see cref="LiveWmiProvider.Classify"/>: the answer for an absent class is the same
    /// answer it always gave, and it is only where the answer comes from that changed.
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
    /// And the half that had to: every <em>other</em> code arriving on that first call.
    ///
    /// <para>
    /// The branch answered <c>NotFound</c> with no diagnostic to all of them, which is a
    /// verdict taken from the branch's position rather than from the code that reached it. It
    /// was right for one code and wrong for the rest — measured, and stated in #153's own
    /// commit: <c>WBEM_E_PROVIDER_LOAD_FAILURE</c> came out of the report as « Relancer en
    /// administrateur », because a null diagnostic is what makes every consumer fall back to
    /// its own hard-coded sentence.
    /// </para>
    ///
    /// <para>
    /// The fix is not a second list of codes here — that is the coverage-by-enumeration this
    /// review keeps rejecting, and two lists disagreeing is precisely the defect. There is one
    /// mapping in this file and the branch now asks it. So the assertion is the identity
    /// itself, over codes on all three of its arms plus one nobody has ever classified: the
    /// answer given here <em>is</em> <see cref="LiveWmiProvider.Classify"/>'s answer, so a
    /// code added to that mapping later is honoured on this path without anyone remembering
    /// to come back.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(0x80041013u)] // WBEM_E_PROVIDER_LOAD_FAILURE: the measured case
    [InlineData(0x80041010u)] // WBEM_E_INVALID_CLASS: an absent class, and still an absence
    [InlineData(0x80041003u)] // WBEM_E_ACCESS_DENIED: a genuine refusal, elevation is the answer
    [InlineData(0x80041045u)] // WBEM_E_SERVER_TOO_BUSY: never elevation
    [InlineData(0x8004100Eu)] // WBEM_E_INVALID_NAMESPACE
    [InlineData(0xDEADBEEFu)] // classified by nobody, which is the point of asserting an identity
    public void A_failure_before_the_first_object_answers_what_Classify_answers(uint hresult)
    {
        var expected = LiveWmiProvider.Classify(Com(hresult));

        var enumeration = new Enumeration(_ => (unchecked((int)hresult), 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        Assert.Equal(expected.Status, read.Status);

        // Nothing was handed over, so there is no inventory here whichever way it is read.
        Assert.Empty(read.Instances);

        // The rule every status-carrying read in this project documents, and the one the
        // consumers actually branch on: written for a failure, null for a refusal or an
        // absence. Asserted on the null-ness rather than on the text, because the two paths
        // legitimately word their reason differently — one has a COM message, the other has
        // the class it was walking.
        Assert.Equal(expected.Diagnostic is null, read.Diagnostic is null);

        if (read.Diagnostic is not null)
        {
            Assert.Contains($"0x{hresult:X8}", read.Diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(
                "administrateur", read.Diagnostic, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// The measured sentence, walked to the report rather than stopped at the read.
    ///
    /// <para>
    /// #153 measured this and left it: <c>WBEM_E_PROVIDER_LOAD_FAILURE</c> on the first
    /// <c>Next</c> reached the report as « Énumération des pilotes refusée. Relancer en
    /// administrateur », advice that repairs nothing when a WMI provider will not load. The
    /// twin of <c>A_broken_walk_reaches_the_report_as_its_code_and_never_as_a_refusal</c>
    /// below, on the branch that one does not enter, and asserted at the same end: two layers
    /// hold a fallback sentence, so the claim only holds where the reader sees it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_provider_that_will_not_load_reaches_the_report_as_its_code_not_as_elevation()
    {
        var enumeration = new Enumeration(_ => (unchecked((int)0x80041013u), 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadDriverSlot, TimeSpan.FromSeconds(30), "Win32_SystemDriver");

        var findings = new LoadedDriversCollector(DriverBlocklist.Empty).Collect(
            new ProviderSet(new NoRegistry(), new SomeMachine(),
                drivers: new LiveDriverProvider(new OneAnswer(read))));

        var gap = findings.Single(f => f.Source == "pilotes chargés");
        var reason = Assert.Single(gap.Reasons);

        Assert.Contains("0x80041013", reason, StringComparison.Ordinal);
        Assert.DoesNotContain("administrateur", reason, StringComparison.OrdinalIgnoreCase);

        // And the channel a scheduler reads, which no sentence can correct: the gap is a
        // failure, not a refusal, so the exit code stops asking for privileges the caller
        // already has.
        Assert.Equal(AuditGap.Unreadable, gap.Gap);
    }

    /// <summary>
    /// The other exit walked to the report, on a collector that branches on the status rather
    /// than on the diagnostic.
    ///
    /// <para>
    /// The twin of the test above, and on a different collector for a reason. Everything the
    /// deadline tests assert stops at the <see cref="WmiRead"/>, where « the status still says
    /// the list is not the machine's » can be read as « anything but <c>Found</c> » — and two
    /// consumers do not read it that way. <c>UnquotedServicePathCollector</c> and
    /// <c>WmiSubscriptionsCollector</c> open their gap finding on
    /// <c>Status == ReadStatus.AccessDenied</c> exactly, not on <c>Status != Found</c>. A
    /// deadline answering <see cref="ReadStatus.NotFound"/> would keep its objects and its
    /// sentence and still leave those two surfaces saying nothing at all: a wedged provider on
    /// <c>Win32_Service</c> or on <c>root\subscription</c> rendered as a machine with nothing
    /// to report, which is the silence the whole issue is about. So the claim is held here on
    /// the value, at the end a reader actually sees.
    /// </para>
    /// </summary>
    [Fact]
    public void A_deadline_reaches_the_report_as_a_gap_and_keeps_the_services_it_had_read()
    {
        var enumeration = new Enumeration(call =>
            call < 2 ? (WbemSNoError, 1) : (WbemSTimedout, 0));

        var read = LiveWmiProvider.Drain(
            enumeration.Next, ReadServiceSlot, TimeSpan.FromSeconds(30), "Win32_Service");

        var findings = new UnquotedServicePathCollector().Collect(
            new ProviderSet(new NoRegistry(), new SomeMachine(), wmi: new OneAnswer(read)));

        var gap = findings.Single(f => f.Source == "Win32_Service");
        var reason = Assert.Single(gap.Reasons);

        Assert.Contains("Win32_Service", reason, StringComparison.Ordinal);

        // A deadline denied nothing, so the channel a scheduler reads says « unreadable » and
        // the sentence stops asking for privileges the caller already has.
        Assert.Equal(AuditGap.Unreadable, gap.Gap);
        Assert.DoesNotContain("administrateur", reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refus", reason, StringComparison.OrdinalIgnoreCase);

        // And the two services the walk did hand over are judged rather than dropped with the
        // deadline that came after them.
        Assert.Equal(2, findings.Count(f => f.Source != "Win32_Service"));
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
    ///
    /// <para>
    /// The failure is spelled with 0x80041014, <c>WBEM_E_INITIALIZATION_FAILURE</c>, which is
    /// one of the two codes a genuinely damaged repository reports. It used to be spelled
    /// « 0x80041010 : dépôt endommagé », a pairing this very file has since measured to be
    /// wrong — <c>WBEM_E_INVALID_CLASS</c> is what an absent class answers, and
    /// <see cref="An_absent_namespace_is_absence_not_refusal"/> a screen above now classifies
    /// it as an absence. A stand-in string is still a sentence, and one contradicting the
    /// mapping it sits beside teaches the next reader the thing that was just corrected.
    /// </para>
    ///
    /// <para>
    /// The silent half changed in #173 and this test changed with it. It used to assert that
    /// the projection <em>replaced</em> the silence of <c>WmiRead.AccessDenied</c> with a
    /// « relancer en administrateur » sentence of its own. That substitution was the defect:
    /// <see cref="Finding.WmiGap"/> tells a denial from a repository failure by the absence of
    /// a reason, so filling it in one layer below the collector erased the only evidence the
    /// classification rests on, and every refused namespace arrived marked as a failure with
    /// an elevation sentence printed underneath it. The sentence still reaches the report —
    /// <c>LoadedDriversCollector</c> and <c>RunningProcessesCollector</c> hold it as their
    /// fallback, which is where wording for a silence belongs — and
    /// <c>LiveDriverAndProcessProviderTests</c> is what asserts it arrives.
    /// </para>
    /// </summary>
    [Fact]
    public void A_total_failure_still_answers_an_empty_inventory()
    {
        var drivers = new LiveDriverProvider(
            new OneAnswer(WmiRead.Failed("COM 0x80041014 : dépôt endommagé."))).Enumerate();

        // The status travels too, and since #177 it is what separates the two halves of this
        // test: a damaged repository projects to DriverRead's failure, a refused namespace to
        // its denial. They were the same value here until this commit, and the pair of
        // assertions below would have been one.
        Assert.Equal(ReadStatus.Failed, drivers.Status);
        Assert.Empty(drivers.Drivers);
        Assert.Equal("COM 0x80041014 : dépôt endommagé.", drivers.Diagnostic);

        var processes = new LiveProcessProvider(
            new OneAnswer(WmiRead.AccessDenied)).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, processes.Status);
        Assert.Empty(processes.Processes);

        // The silence travels. A genuine refusal has nothing to explain, and that is precisely
        // what the classification reads — so the projection forwards the null rather than
        // being helpful about it.
        Assert.Null(processes.Diagnostic);
    }

    /// <summary>
    /// A slot that decodes into a service whose path is unquoted and contains a space, so the
    /// services a truncated walk did hand over are ones the collector has something to say
    /// about — otherwise « they are still judged » would be indistinguishable from « they were
    /// dropped ».
    /// </summary>
    private static WmiInstance? ReadServiceSlot(IntPtr pointer) =>
        new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Name"] = $"service{pointer}",
            ["PathName"] = $@"C:\Program Files\Vendor\svc{pointer}.exe",
        });

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
