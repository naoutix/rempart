using Rempart.Core.Cli;
using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The exit-code contract — the only thing a caller who reads nothing else gets.
///
/// <para>
/// These six codes were decided by two ternaries and a pair of <c>catch</c> blocks in
/// <c>Program.cs</c>, and nothing observed them. CI accepts <c>0</c>, <c>3</c> or <c>5</c>
/// from a scan without telling them apart, so a build that returned 3 forever would stay
/// green, and the day someone reordered the precedence a scheduled scan would silently
/// start reporting success. That is what these tests are for.
/// </para>
/// </summary>
public sealed class ExitCodeTests
{
    [Fact]
    public void A_scan_that_read_everything_and_evaluated_everything_succeeds() =>
        Assert.Equal(ExitCode.Success, ExitCodes.ForScan(Scan(
            [CollectorStatus.Ok, CollectorStatus.Ok],
            [VerdictStatus.Pass, VerdictStatus.Pass])));

    /// <summary>
    /// Precedence, not order of appearance. A run that both broke somewhere and was
    /// refused elsewhere is a failure: that is the half which re-running as administrator
    /// will not fix.
    /// </summary>
    [Theory]
    [InlineData(CollectorStatus.Failed, CollectorStatus.InsufficientPrivileges)]
    [InlineData(CollectorStatus.InsufficientPrivileges, CollectorStatus.Failed)]
    public void A_failed_collector_outranks_a_missing_privilege(
        CollectorStatus first, CollectorStatus second) =>
        Assert.Equal(ExitCode.Failure, ExitCodes.ForScan(Scan([first, second])));

    /// <summary>
    /// The whole ladder in one place, walked rung by rung, and in both list orders because
    /// position must not decide: Failure (1) &gt; InsufficientPrivileges (3) &gt; Partial
    /// (5) &gt; Success (0).
    ///
    /// <para>
    /// Ranked by what the caller can do about it, which is the only ordering that makes a
    /// single number useful. A breakdown does not repair itself by re-running elevated; a
    /// refused collector does; a rule that could not be evaluated is the weakest of the
    /// three and still not nothing — it is the difference between "verified compliant" and
    /// "compliant as far as could be seen". Saying the weakest one while a breakdown is
    /// also present would bury the only signal that needs a human.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(CollectorStatus.Failed, CollectorStatus.InsufficientPrivileges,
        VerdictStatus.Unknown, VerdictStatus.Pass)]
    [InlineData(CollectorStatus.InsufficientPrivileges, CollectorStatus.Failed,
        VerdictStatus.Pass, VerdictStatus.Unknown)]
    public void A_failure_outranks_a_refusal_which_outranks_an_unverifiable_control(
        CollectorStatus firstCollector, CollectorStatus secondCollector,
        VerdictStatus firstVerdict, VerdictStatus secondVerdict)
    {
        CollectorStatus[] collectors = [firstCollector, secondCollector];
        VerdictStatus[] verdicts = [firstVerdict, secondVerdict];

        // All three signals at once: only the one nobody can act on by re-running is said.
        Assert.Equal(ExitCode.Failure, ExitCodes.ForScan(Scan(collectors, verdicts)));

        // Drop the breakdown and the refusal surfaces — still above the blind control.
        Assert.Equal(ExitCode.InsufficientPrivileges, ExitCodes.ForScan(Scan(
            collectors.Select(s => s == CollectorStatus.Failed ? CollectorStatus.Ok : s),
            verdicts)));

        // Drop the refusal too, and the rule with no answer is what is left to report.
        Assert.Equal(ExitCode.Partial, ExitCodes.ForScan(Scan(
            [CollectorStatus.Ok, CollectorStatus.Ok], verdicts)));

        // Answer that rule as well, and there is nothing left to say.
        Assert.Equal(ExitCode.Success, ExitCodes.ForScan(Scan(
            [CollectorStatus.Ok, CollectorStatus.Ok],
            verdicts.Select(s => s == VerdictStatus.Unknown ? VerdictStatus.Pass : s))));
    }

    [Fact]
    public void A_missing_privilege_is_not_an_execution_error()
    {
        var code = ExitCodes.ForScan(
            Scan([CollectorStatus.Ok, CollectorStatus.InsufficientPrivileges]));

        Assert.Equal(ExitCode.InsufficientPrivileges, code);
        Assert.NotEqual(ExitCode.Failure, code);
    }

    /// <summary>
    /// Freezes the current choice: "this machine has no such thing to look at" is an
    /// answer, not a breakdown. Distinct from a denial, which calls for elevation.
    /// </summary>
    [Fact]
    public void An_unavailable_collector_is_not_a_failure() =>
        Assert.Equal(ExitCode.Success,
            ExitCodes.ForScan(Scan([CollectorStatus.Ok, CollectorStatus.Unavailable])));

    [Fact]
    public void A_scan_with_no_collector_succeeds() =>
        Assert.Equal(ExitCode.Success, ExitCodes.ForScan(Scan()));

    /// <summary>
    /// Closes DET-SORTIE-PARTIELLE, and this test is the inverse of the one that used to
    /// freeze the defect.
    ///
    /// <para>
    /// The code answered for the <em>collectors</em> only. A machine where every collector
    /// read fine while rules came back <c>Unknown</c> for want of elevation exited 0, which
    /// reads exactly like a machine that was fully verified. The console and the reports
    /// have always said the score was partial; the exit code — the one channel of the
    /// caller who reads nothing else — was the one staying silent. It no longer does.
    /// </para>
    /// </summary>
    [Fact]
    public void An_unverifiable_control_reaches_the_exit_code()
    {
        var code = ExitCodes.ForScan(Scan(
            [CollectorStatus.Ok],
            [VerdictStatus.Pass, VerdictStatus.Unknown]));

        Assert.Equal(ExitCode.Partial, code);
        Assert.NotEqual(ExitCode.Success, code);
    }

    /// <summary>
    /// The other half of the same claim: the code answers for the audit, never for the
    /// posture. A machine failing half its controls was still fully audited, and reporting
    /// 5 for it would make the code fire on nearly every workstation in a fleet — as
    /// uninformative as the 0 it replaces.
    /// </summary>
    [Fact]
    public void A_failing_control_is_not_a_partial_audit() =>
        Assert.Equal(ExitCode.Success, ExitCodes.ForScan(Scan(
            [CollectorStatus.Ok],
            [VerdictStatus.Fail, VerdictStatus.NotApplicable])));

    /// <summary>
    /// What each collector status is worth, written down rather than asserted to be
    /// "one of the documented codes".
    ///
    /// <para>
    /// The first version of this guard compared the result against
    /// <see cref="ExitCodes.All"/>, which cannot fail: <c>ForScan</c> returns nothing else
    /// by construction, so the assertion held for every input — including a mutant where
    /// the status mapped to the wrong code. A guard whose claim is always true is worse
    /// than no guard, because the file it lives in opens by saying nothing observed this
    /// contract.
    /// </para>
    ///
    /// <para>
    /// Naming the expected code makes both failures visible: a status added without anyone
    /// deciding what it should exit with is absent from the table, and a decision quietly
    /// changed no longer matches it.
    /// </para>
    /// </summary>
    private static readonly Dictionary<CollectorStatus, ExitCode> CollectorCodes = new()
    {
        [CollectorStatus.Ok] = ExitCode.Success,
        [CollectorStatus.Unavailable] = ExitCode.Success,
        [CollectorStatus.InsufficientPrivileges] = ExitCode.InsufficientPrivileges,
        [CollectorStatus.Failed] = ExitCode.Failure,
    };

    [Theory]
    [MemberData(nameof(CollectorStatuses))]
    public void Every_collector_status_maps_to_the_code_it_was_given(CollectorStatus status)
    {
        Assert.True(CollectorCodes.TryGetValue(status, out var expected),
            $"Le statut de collecteur « {status} » a été ajouté sans que personne décide du "
            + "code de sortie qu'il entraîne. C'est maintenant qu'il faut le décider, pas "
            + "le jour où un appelant lira 0 sur une machine que l'outil n'a pas su lire.");

        Assert.Equal(expected, ExitCodes.ForScan(Scan([status])));
    }

    public static TheoryData<CollectorStatus> CollectorStatuses() =>
        [.. Enum.GetValues<CollectorStatus>()];

    /// <summary>
    /// The same table on the other input, which the exit code only started reading with
    /// DET-SORTIE-PARTIELLE. <c>Fail</c> maps to success on purpose: the code answers for
    /// the audit, not for the posture — a fleet where every machine fails a control would
    /// otherwise exit non-zero everywhere, which is as uninformative as the 0 it replaced.
    /// </summary>
    private static readonly Dictionary<VerdictStatus, ExitCode> VerdictCodes = new()
    {
        [VerdictStatus.Pass] = ExitCode.Success,
        [VerdictStatus.Fail] = ExitCode.Success,
        [VerdictStatus.NotApplicable] = ExitCode.Success,
        [VerdictStatus.Unknown] = ExitCode.Partial,
    };

    [Theory]
    [MemberData(nameof(VerdictStatuses))]
    public void Every_verdict_status_maps_to_the_code_it_was_given(VerdictStatus status)
    {
        Assert.True(VerdictCodes.TryGetValue(status, out var expected),
            $"Le statut de verdict « {status} » a été ajouté sans que personne décide du "
            + "code de sortie qu'il entraîne. Sans décision il tombe sur 0, et 0 est "
            + "précisément la réponse que personne ne relit.");

        Assert.Equal(expected, ExitCodes.ForScan(Scan([CollectorStatus.Ok], [status])));
    }

    public static TheoryData<VerdictStatus> VerdictStatuses() =>
        [.. Enum.GetValues<VerdictStatus>()];

    /// <summary>
    /// The third input, and the one the contract read nothing of. A finding collector has no
    /// <see cref="CollectorResult"/> to carry a status in: the sixteen of them say « je n'ai
    /// pas pu regarder » with a finding, and a finding was invisible to the exit code. Three
    /// refused surfaces exited 0 — for a scheduler, a machine that was fully checked.
    ///
    /// <para>
    /// The two gaps map to different codes because they call for different actions, which is
    /// the only ordering that makes a single number useful. A refused surface is repaired by
    /// re-running elevated; a collector that threw is not, and calling both « droits
    /// insuffisants » would send whoever reads the number to do the one thing that cannot
    /// help.
    /// </para>
    /// </summary>
    private static readonly Dictionary<AuditGap, ExitCode> GapCodes = new()
    {
        [AuditGap.Refused] = ExitCode.InsufficientPrivileges,
        [AuditGap.Broken] = ExitCode.Failure,
    };

    [Theory]
    [MemberData(nameof(AuditGaps))]
    public void Every_audit_gap_maps_to_the_code_it_was_given(AuditGap gap)
    {
        Assert.True(GapCodes.TryGetValue(gap, out var expected),
            $"La lacune d'audit « {gap} » a été ajoutée sans que personne décide du code de "
            + "sortie qu'elle entraîne. Sans décision elle tombe sur 0, et 0 est précisément "
            + "la réponse que personne ne relit.");

        Assert.Equal(expected, ExitCodes.ForScan(Scan(gaps: [gap])));
    }

    public static TheoryData<AuditGap> AuditGaps() => [.. Enum.GetValues<AuditGap>()];

    /// <summary>
    /// The guard that closes the class rather than one collector's case: whatever surface was
    /// refused, and whichever collector saw it refused, the number reaching the caller says so.
    ///
    /// <para>
    /// The collectors walked are <see cref="ScanEngine"/>'s own, so a seventeenth one is
    /// covered without anyone remembering this file exists — the alternative, one assertion
    /// per collector, is the hand-kept list this batch was opened over. Nothing else can move
    /// the code here: no field collector and no rule is wired, so the two lists the contract
    /// used to read are empty and only the findings are left to speak.
    /// </para>
    ///
    /// <para>
    /// The second assertion is what keeps the first honest. Under a machine that refuses
    /// everything, no finding can be a claim about that machine, so a finding produced without
    /// the marker is one the exit code cannot see. Written that way, a collector that
    /// hand-rolls a refusal instead of asking <see cref="Finding.Refused"/> for one fails
    /// here, which the aggregate code alone would not catch: fifteen collectors speaking up
    /// would cover for the sixteenth staying silent.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_refused_surface_reaches_the_exit_code_whichever_collector_saw_it()
    {
        var scan = RefusedEverywhere();

        // The premise, asserted rather than assumed: without it this test would pass on a
        // signal that has nothing to do with the findings.
        Assert.Empty(scan.Collectors);
        Assert.Empty(scan.Verdicts);
        Assert.NotEmpty(scan.Findings);

        Assert.All(scan.Findings, finding => Assert.True(finding.Gap is not null,
            $"Le constat « {finding.Kind} / {finding.Source} » a été produit sur une machine "
            + "qui a tout refusé, donc il ne peut pas être une affirmation sur elle — et sans "
            + "marqueur, le code de sortie ne le voit pas."));

        Assert.Equal(ExitCode.InsufficientPrivileges, ExitCodes.ForScan(scan));
    }

    /// <summary>
    /// A finding collector that throws is not a finding collector that was refused, and
    /// <c>ScanEngine</c> turned both into the same <c>Notable</c> finding. The two answers a
    /// caller can give are opposite: one re-runs elevated, the other files a bug — and
    /// re-running elevated forever is what a scheduler does with the wrong number.
    ///
    /// <para>
    /// Both signals are present at once, so the assertion is on the precedence too: a
    /// breakdown outranks a refusal, being the half that elevation will not fix.
    /// </para>
    /// </summary>
    [Fact]
    public void A_finding_collector_that_broke_outranks_the_surfaces_that_were_refused()
    {
        var scan = RefusedEverywhere([.. DefaultFindingCollectors, new BrokenFindingCollector()]);

        Assert.Contains(scan.Findings, finding => finding.Gap == AuditGap.Refused);
        Assert.Contains(scan.Findings, finding => finding.Gap == AuditGap.Broken);

        Assert.Equal(ExitCode.Failure, ExitCodes.ForScan(scan));
    }

    private static IReadOnlyList<IFindingCollector> DefaultFindingCollectors =>
        ScanEngine.DefaultFindingCollectors(DriverBlocklist.Empty, BloatwareCatalog.Empty);

    /// <summary>
    /// A scan of a machine that answers « accès refusé » to everything, run through the
    /// finding collectors the tool really ships. No field collector and no rule: the findings
    /// are then the only thing that can move the exit code.
    ///
    /// <para>
    /// The registry is the only provider that has to be written here. Every other one defaults
    /// to a refusal already — that is what <see cref="ProviderSet"/> decided a missing provider
    /// means on a surface where zero could not be true.
    /// </para>
    /// </summary>
    private static ScanResult RefusedEverywhere(
        IReadOnlyList<IFindingCollector>? findingCollectors = null) =>
        new ScanEngine([], []).Run(
            new ProviderSet(new RefusingRegistry(), new FakeSystemInfoProvider()),
            "test", "2026-07-24T09:15:00Z", findingCollectors: findingCollectors);

    /// <summary>Refuses every read, so nothing a collector reports can be about the machine.</summary>
    private sealed class RefusingRegistry : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) =>
            RegistryRead.AccessDenied;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.AccessDenied;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.AccessDenied;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.AccessDenied;
    }

    /// <summary>The collector that breaks rather than the machine that refuses.</summary>
    private sealed class BrokenFindingCollector : IFindingCollector
    {
        public string Name => "cassé";

        public IReadOnlyList<Finding> Collect(ProviderSet providers) =>
            throw new InvalidOperationException("boum");
    }

    /// <summary>
    /// The fixture that motivated the debt, mounted rather than fabricated: a capture taken
    /// without elevation whose collectors all read fine, which scores <b>100 %</b>, and
    /// which has four controls it never managed to look at. Before code 5 it exited 0 —
    /// for a scheduler, indistinguishable from a machine that was fully checked.
    ///
    /// <para>
    /// Replayed through <see cref="FixtureReplayTests.Scan"/>, the wiring the golden
    /// references use, so the claim is about the scan those references freeze rather than
    /// about a hand-built result that could be made to say anything. The score and the
    /// unknown count are asserted alongside the code: if a future change to the fixture
    /// makes it complete, this test must fail loudly rather than quietly stop proving
    /// anything.
    /// </para>
    ///
    /// <para>
    /// It exits <c>3</c> and not <c>5</c> since the finding collectors were heard: the same
    /// capture has seven surfaces it was refused outright, and elevation is what answers
    /// those, where an unevaluable rule leaves the caller nothing to do. The 5 it used to
    /// answer is still asserted, on the same scan stripped of its gaps — that claim did not
    /// stop being true, it stopped being the strongest thing this fixture has to say.
    /// </para>
    /// </summary>
    [Fact]
    public void The_fixture_that_scores_full_marks_without_seeing_everything_never_exits_zero()
    {
        var scan = FixtureReplayTests.Scan("synthetic/restricted-access");

        Assert.Equal(100, scan.Score?.Overall);
        Assert.True(scan.Score?.IsPartial);
        Assert.Equal(4, scan.Verdicts.Count(v => v.Status == VerdictStatus.Unknown));
        Assert.All(scan.Collectors, c => Assert.Equal(CollectorStatus.Ok, c.Status));

        Assert.Equal(7, scan.Findings.Count(f => f.Gap == AuditGap.Refused));
        Assert.Equal(ExitCode.InsufficientPrivileges, ExitCodes.ForScan(scan));

        Assert.Equal(ExitCode.Partial, ExitCodes.ForScan(WithoutGaps(scan)));
    }

    /// <summary>
    /// The counterweight, without which the previous test would still pass if every scan
    /// returned the same thing: the hardened capture evaluates every rule it touches, and the
    /// moment it has no gap left it exits 0.
    ///
    /// <para>
    /// It does have three, and they are why it no longer exits 0 on its own. This capture
    /// predates the collection of drivers, processes and listening ports, so its replay is
    /// told « accès refusé » on all three and says so in the report — while answering 0, which
    /// reads as a machine that was fully checked. That is REV-13 with the repository's own
    /// fixture as the witness.
    /// </para>
    ///
    /// <para>
    /// It is also the one place where the number gives advice that does not apply: re-running
    /// a <em>replay</em> elevated changes nothing, the answer is to re-capture. A snapshot
    /// provider answers <c>AccessDenied</c> for a surface the capture never held — deliberately,
    /// since « je n'ai pas regardé » must not read as « il n'y a rien » — and no collector can
    /// tell that apart from a machine saying no. Telling them apart means a fourth
    /// <c>ReadStatus</c> travelling the whole channel, which is a design question and not this
    /// fix; what is not in question is that neither of the two deserves a 0.
    /// </para>
    /// </summary>
    [Fact]
    public void The_hardened_fixture_exits_zero_only_once_nothing_was_refused()
    {
        var scan = FixtureReplayTests.Scan("synthetic/hardened-win11");

        Assert.DoesNotContain(scan.Verdicts, v => v.Status == VerdictStatus.Unknown);

        Assert.Equal(3, scan.Findings.Count(f => f.Gap == AuditGap.Refused));
        Assert.Equal(ExitCode.InsufficientPrivileges, ExitCodes.ForScan(scan));

        Assert.Equal(ExitCode.Success, ExitCodes.ForScan(WithoutGaps(scan)));
    }

    /// <summary>
    /// The same scan with nothing left it could not read — the shape both fixtures had before
    /// their gaps were audible, and the only way to keep asserting what they used to prove.
    /// </summary>
    private static ScanResult WithoutGaps(ScanResult scan) =>
        scan with { Findings = [.. scan.Findings.Where(finding => finding.Gap is null)] };

    /// <summary>
    /// A control that became unreadable calls for elevation; one that fell calls for a
    /// fix. Only the second changes the exit code — saying both with the same number would
    /// bury the one nobody would otherwise notice.
    /// </summary>
    [Theory]
    [MemberData(nameof(VerdictShifts))]
    public void A_regression_is_the_only_shift_that_changes_the_exit_code(VerdictShift shift)
    {
        var expected = shift == VerdictShift.Regression ? ExitCode.Regression : ExitCode.Success;

        Assert.Equal(expected, ExitCodes.ForDiff(WithSingleShift(shift)));
    }

    public static TheoryData<VerdictShift> VerdictShifts() => [.. Enum.GetValues<VerdictShift>()];

    [Fact]
    public void A_diff_with_nothing_to_report_succeeds() =>
        Assert.Equal(ExitCode.Success, ExitCodes.ForDiff(ScanDiff.Compare(Scan(), Scan())));

    /// <summary>
    /// The wording is compared in full, accents included: merging the two <c>catch</c>
    /// blocks into one is only safe if the sentences survived the move unchanged.
    /// </summary>
    [Fact]
    public void An_incomplete_snapshot_is_told_apart_from_any_other_failure()
    {
        Assert.Equal(
            new FailureExit(ExitCode.SnapshotIncomplete, "Instantané incomplet : clé absente"),
            ExitCodes.ForException(new SnapshotIncompleteException("clé absente")));

        Assert.Equal(
            new FailureExit(ExitCode.Failure, "Erreur : boum"),
            ExitCodes.ForException(new InvalidOperationException("boum")));
    }

    /// <summary>
    /// The test that would have caught the omission: the hand-written help line listed
    /// codes 0 to 3 and never mentioned 4, from the day code 4 was introduced.
    /// </summary>
    [Theory]
    [MemberData(nameof(Codes))]
    public void The_help_block_lists_every_exit_code(ExitCode code)
    {
        Assert.Contains($"{(int)code}", ExitCodes.HelpBlock, StringComparison.Ordinal);
        Assert.Contains(ExitCodes.Describe(code), ExitCodes.HelpBlock, StringComparison.Ordinal);
    }

    public static TheoryData<ExitCode> Codes() => [.. ExitCodes.All];

    /// <summary>
    /// Contiguous from zero, with no gap and no duplicate: a caller matching on the number
    /// has no hole to fall into, and a code reused for two meanings is caught here.
    /// </summary>
    [Fact]
    public void The_codes_are_contiguous_from_zero()
    {
        Assert.Equal([0, 1, 2, 3, 4, 5], ExitCodes.All.Select(code => (int)code));
        Assert.Equal(ExitCodes.All.Count, ExitCodes.All.Distinct().Count());
    }

    /// <summary>
    /// A comparison carrying exactly one verdict change, of the requested shift. Built by
    /// hand rather than by moving a real verdict: producing every shift from two scans
    /// would take seven fixtures, and the point here is the mapping, not the classifier —
    /// <c>ScanDiffTests</c> owns that.
    /// </summary>
    private static DiffResult WithSingleShift(VerdictShift shift) => new(
        BeforeMachine: "POSTE-01",
        AfterMachine: "POSTE-01",
        BeforeAtUtc: "2026-07-24T09:15:00Z",
        AfterAtUtc: "2026-07-25T09:15:00Z",
        SameMachine: true,
        Comparable: true,
        ComparabilityNote: string.Empty,
        ScoreBefore: 70,
        ScoreAfter: 70,
        Domains: [],
        Verdicts:
        [
            new VerdictChange("WIN-A-001", "Contrôle A", Severity.High, "réseau",
                VerdictStatus.Pass, VerdictStatus.Fail, shift),
        ],
        Findings: [],
        Transients: [],
        Fields: []);

    /// <summary>
    /// A scan reduced to the three lists the exit code reads. All default to empty so
    /// <c>Scan()</c> still stands for "a run with nothing to report" — the shape the diff
    /// tests below need.
    /// </summary>
    private static ScanResult Scan(
        IEnumerable<CollectorStatus>? collectors = null,
        IEnumerable<VerdictStatus>? verdicts = null,
        IEnumerable<AuditGap>? gaps = null) => new(
        ToolVersion: "test",
        StartedAtUtc: "2026-07-24T09:15:00Z",
        Collectors: [.. (collectors ?? []).Select(status =>
            new CollectorResult("test", status, [], []))],
        Verdicts: [.. (verdicts ?? []).Select(status =>
            new Verdict("WIN-A-001", "Contrôle A", Severity.High, "réseau", status, null, null))],

        // Built by hand rather than through the factories, which each pin one gap: the table
        // above has to be able to hand over a value nobody has written a factory for, since
        // that is the case it exists to catch.
        Findings: [.. (gaps ?? []).Select(gap => new Finding(
            "test", "surface", Finding.NoTarget, FindingSeverity.Notable, [],
            new Dictionary<string, string>(), gap))],

        // Left null on purpose, and the codes still come out right: the score is null
        // whenever nothing at all could be evaluated — the most partial scan there is —
        // so a contract reading it rather than the verdicts would answer 0 for exactly
        // the machine it exists to flag.
        Score: null,
        RulesFingerprint: "82:c3e6e3029b12",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));
}
