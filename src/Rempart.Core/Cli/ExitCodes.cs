using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;

namespace Rempart.Core.Cli;

/// <summary>
/// What the tool tells a caller who reads nothing else.
///
/// <para>
/// A scan piped into a scheduler, a script or another tool is judged on this number alone.
/// It was decided by two ternaries buried in <c>Program.cs</c> and by a pair of
/// <c>catch</c> blocks, none of which any test observed: CI asserts that a scan exits 0,
/// 3 <em>or</em> 5 without distinguishing them, so a build that returned 3 forever would
/// stay green. Here the contract is a pure function of the scan, and it is tested.
/// </para>
/// </summary>
public enum ExitCode
{
    /// <summary>Everything the tool was asked to look at, it looked at.</summary>
    Success = 0,

    /// <summary>The run failed — a collector broke, a file could not be written.</summary>
    Failure = 1,

    /// <summary>A replayed snapshot is missing what the rules need to be evaluated.</summary>
    SnapshotIncomplete = 2,

    /// <summary>
    /// Something could not be read for lack of rights. Not an error: the answer is to
    /// re-run elevated, which is a different action from fixing a broken tool.
    /// </summary>
    InsufficientPrivileges = 3,

    /// <summary>A comparison found a control that used to pass and no longer does.</summary>
    Regression = 4,

    /// <summary>
    /// The scan ran to the end, and something still has no answer. Distinct from
    /// <see cref="InsufficientPrivileges"/>, which says a <em>collector</em> was refused:
    /// here every collector read fine and controls came back <c>Unknown</c> anyway, so the
    /// score answers for less of the machine than it appears to. The fixture
    /// <c>restricted-access</c> is the case: 100 %, four controls unverifiable, and until
    /// this code existed it exited 0 — indistinguishable, for a scheduler, from a machine
    /// that was fully checked.
    ///
    /// <para>
    /// It is also where <see cref="Findings.AuditGap.Unreadable"/> lands, and for the same
    /// reason rather than by analogy: a surface that answered with a failure leaves the caller
    /// nothing to do to the run. Elevating does not repair a WMI repository, and there is no
    /// bug to file against the tool, so neither 3 nor 1 is honest — what is true is that the
    /// scan finished and part of the machine has no answer.
    /// </para>
    /// </summary>
    Partial = 5,

    /// <summary>
    /// The command line was not understood, and nothing was run.
    ///
    /// <para>
    /// Its own code rather than <see cref="Failure"/>, and the distinction is the same one
    /// the five above are ordered by — what the caller can do about it. <c>1</c> says a run
    /// was attempted and broke: the machine is the suspect, and a scheduler that retries on
    /// it is doing something reasonable. Here nothing was attempted, the machine is not the
    /// suspect, and the remedy is to retype the line — a retry loop on <c>1</c> would run
    /// forever against a word that will never exist. Both codes fall outside what the build
    /// chain accepts from a scan, so a usage error reddens CI either way; what a new number
    /// buys is that the caller can tell the two apart, which is the whole argument for
    /// having more than two codes at all. That it really is outside is not asserted from a
    /// number retyped here but read off the workflows and <c>verify.ps1</c> themselves, by
    /// <c>BuildChainParityTests.A_usage_error_is_never_a_code_the_build_chain_accepts</c>.
    /// </para>
    ///
    /// <para>
    /// It never competes with the precedence <see cref="ExitCodes.ForScan"/> arbitrates:
    /// that function answers for a finished scan, and a line carrying an option nobody
    /// declares never reaches a scan. Seventh and contiguous, which is what
    /// <c>The_codes_are_contiguous_from_zero</c> holds.
    /// </para>
    /// </summary>
    Usage = 6,
}

/// <summary>An exit code and the sentence printed on stderr alongside it.</summary>
public sealed record FailureExit(ExitCode Code, string Message);

/// <summary>
/// The single source of the exit-code contract: the mapping, the wording, and the block
/// the help text prints. Keeping the three together is what makes the help incapable of
/// omitting a code — which it did, for code 4, from the day that code was introduced.
/// </summary>
public static class ExitCodes
{
    public static IReadOnlyList<ExitCode> All { get; } =
    [
        ExitCode.Success,
        ExitCode.Failure,
        ExitCode.SnapshotIncomplete,
        ExitCode.InsufficientPrivileges,
        ExitCode.Regression,
        ExitCode.Partial,
        ExitCode.Usage,
    ];

    public static string Describe(ExitCode code) => code switch
    {
        ExitCode.Success => "succès",
        ExitCode.Failure => "échec",
        ExitCode.SnapshotIncomplete => "instantané incomplet",
        ExitCode.InsufficientPrivileges => "droits insuffisants",
        ExitCode.Regression => "régression",
        ExitCode.Partial => "audit partiel",
        ExitCode.Usage => "erreur d'usage",
        _ => throw new ArgumentOutOfRangeException(nameof(code)),
    };

    /// <summary>
    /// The codes as the help lists them. Derived rather than retyped: the hand-written
    /// line in <c>Help()</c> had been out of date since code 4 appeared, and nothing could
    /// have noticed.
    /// </summary>
    public static string HelpBlock { get; } =
        string.Join(Environment.NewLine, All.Select(code => $"  {(int)code}  {Describe(code)}"));

    /// <summary>
    /// What a finished scan is worth to its caller.
    ///
    /// <para>
    /// Takes the whole result rather than the two lists it reads, for the reason
    /// <see cref="ForDiff"/> takes a <see cref="DiffResult"/> rather than a list of shifts:
    /// with <c>ForScan(collectors, verdicts)</c> nothing would stop a caller handing over
    /// the collectors of one scan and the verdicts of another — two same-shaped arguments,
    /// no compiler to object — and the exit code is precisely the value nobody re-reads
    /// afterwards to notice. One argument, one scan.
    /// </para>
    ///
    /// <para>
    /// Precedence, strictly in this order: <see cref="ExitCode.Failure"/>,
    /// <see cref="ExitCode.InsufficientPrivileges"/>, <see cref="ExitCode.Partial"/>,
    /// <see cref="ExitCode.Success"/>. Ranked by what the caller can do about it. A
    /// breakdown does not repair itself by re-running elevated; a refused collector does;
    /// a rule that could not be evaluated is the weakest of the three signals and is still
    /// not nothing — it separates "verified compliant" from "compliant as far as could be
    /// seen". CI relies on this precedence: it accepts 0, 3 and 5 from a scan on a runner
    /// whose rights vary, and nothing else.
    /// </para>
    ///
    /// <para>
    /// The partial case reads the verdicts, never <see cref="ScanResult.Score"/>: the score
    /// is <c>null</c> when nothing at all could be evaluated, which is the most partial
    /// scan there is, and any check going through a nullable score would answer 0 for it.
    /// An <c>Unknown</c> verdict is the same condition <see cref="ScoreCard.IsPartial"/>
    /// states, read where it is decided.
    /// </para>
    ///
    /// <para>
    /// The findings are read on all three rungs, and for the same reason: they are where the
    /// other half of the tool says it could not look. A finding collector answers with a list
    /// of findings and nothing else — it has no <see cref="CollectorResult"/> to put a status
    /// in — so a refused surface reached the report, the console and the HTML, then stopped
    /// dead at the one channel a scheduler reads. Each <see cref="AuditGap"/> lands on the
    /// rung its answer belongs to, which is what the whole precedence is ordered by: a
    /// collector that threw does not repair itself by re-running elevated, a refused surface
    /// does, and a surface that answered with a failure repairs itself by neither.
    /// </para>
    ///
    /// <para>
    /// <see cref="AuditGap.Unreadable"/> therefore joins the unevaluable rule on the weakest
    /// rung rather than taking one of its own. That is deliberate and it is what makes the
    /// change free of contract: it added no code at all, and CI already accepts
    /// <c>0</c>, <c>3</c> and <c>5</c> from a scan — see the two workflows, which check
    /// <c>-notin @(0, 3, 5)</c>. A gap that used to answer 3 now answers 5, and no caller
    /// that was green stops being green.
    /// </para>
    /// </summary>
    public static ExitCode ForScan(ScanResult scan) =>
        scan.Collectors.Any(c => c.Status == CollectorStatus.Failed)
        || scan.Findings.Any(f => f.Gap == AuditGap.Broken) ? ExitCode.Failure
        : scan.Collectors.Any(c => c.Status == CollectorStatus.InsufficientPrivileges)
          || scan.Findings.Any(f => f.Gap == AuditGap.Refused)
            ? ExitCode.InsufficientPrivileges
            : scan.Verdicts.Any(v => v.Status == VerdictStatus.Unknown)
              || scan.Findings.Any(f => f.Gap == AuditGap.Unreadable)
                ? ExitCode.Partial
                : ExitCode.Success;

    /// <summary>
    /// A regression is what the caller most likely wants to act on, so it is detectable
    /// without re-reading the output. Nothing else in a comparison changes the code: a
    /// control that became unreadable calls for elevation, not for a fix, and saying both
    /// with the same number would bury the one nobody would otherwise notice.
    /// </summary>
    public static ExitCode ForDiff(DiffResult diff) =>
        diff.Of(VerdictShift.Regression).Any() ? ExitCode.Regression : ExitCode.Success;

    /// <summary>
    /// An incomplete snapshot is told apart from any other failure, because it is the one
    /// the caller can fix by re-capturing rather than by filing a bug.
    /// </summary>
    public static FailureExit ForException(Exception exception) =>
        exception is SnapshotIncompleteException
            ? new FailureExit(ExitCode.SnapshotIncomplete, $"Instantané incomplet : {exception.Message}")
            : new FailureExit(ExitCode.Failure, $"Erreur : {exception.Message}");
}
