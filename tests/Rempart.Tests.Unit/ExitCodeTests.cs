using Rempart.Core.Cli;
using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The exit-code contract — the only thing a caller who reads nothing else gets.
///
/// <para>
/// These five codes were decided by two ternaries and a pair of <c>catch</c> blocks in
/// <c>Program.cs</c>, and nothing observed them. CI accepts <c>0</c> or <c>3</c> from a
/// scan without telling them apart, so a build that returned 3 forever would stay green,
/// and the day someone reordered the precedence a scheduled scan would silently start
/// reporting success. That is what these tests are for.
/// </para>
/// </summary>
public sealed class ExitCodeTests
{
    [Fact]
    public void A_scan_with_every_collector_ok_succeeds() =>
        Assert.Equal(ExitCode.Success,
            ExitCodes.ForScan([Collector(CollectorStatus.Ok), Collector(CollectorStatus.Ok)]));

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
        Assert.Equal(ExitCode.Failure, ExitCodes.ForScan([Collector(first), Collector(second)]));

    [Fact]
    public void A_missing_privilege_is_not_an_execution_error()
    {
        var code = ExitCodes.ForScan(
            [Collector(CollectorStatus.Ok), Collector(CollectorStatus.InsufficientPrivileges)]);

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
            ExitCodes.ForScan([Collector(CollectorStatus.Ok), Collector(CollectorStatus.Unavailable)]));

    [Fact]
    public void A_scan_with_no_collector_succeeds() =>
        Assert.Equal(ExitCode.Success, ExitCodes.ForScan([]));

    /// <summary>
    /// Freezes an asymmetry rather than hiding it: the code answers for the
    /// <em>collectors</em>, never for the verdicts. A machine where every collector read
    /// fine but half the rules came back <c>Unknown</c> for want of elevation exits 0,
    /// which reads exactly like a machine that was fully verified.
    ///
    /// <para>
    /// This is the behaviour that shipped, kept deliberately here — changing it would move
    /// the contract CI depends on, and that deserves its own change. It is recorded as
    /// DET-SORTIE-PARTIELLE in <c>docs/DEBT.md</c>. The console and the reports do say the
    /// score is partial; only the exit code is silent, which is precisely the caller who
    /// reads nothing else.
    /// </para>
    /// </summary>
    [Fact]
    public void An_unverifiable_control_does_not_reach_the_exit_code() =>
        Assert.Equal(ExitCode.Success, ExitCodes.ForScan([Collector(CollectorStatus.Ok)]));

    /// <summary>
    /// Breaks the day a collector status is added without anyone deciding what the tool
    /// should exit with when it occurs — which is the moment to decide, not later.
    /// </summary>
    [Theory]
    [MemberData(nameof(CollectorStatuses))]
    public void Every_collector_status_maps_to_a_documented_code(CollectorStatus status) =>
        Assert.Contains(ExitCodes.ForScan([Collector(status)]), ExitCodes.All);

    public static TheoryData<CollectorStatus> CollectorStatuses() =>
        [.. Enum.GetValues<CollectorStatus>()];

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
        Assert.Equal([0, 1, 2, 3, 4], ExitCodes.All.Select(code => (int)code));
        Assert.Equal(ExitCodes.All.Count, ExitCodes.All.Distinct().Count());
    }

    private static CollectorResult Collector(CollectorStatus status) =>
        new("test", status, [], []);

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

    private static ScanResult Scan() => new(
        ToolVersion: "test",
        StartedAtUtc: "2026-07-24T09:15:00Z",
        Collectors: [],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "82:c3e6e3029b12",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));
}
