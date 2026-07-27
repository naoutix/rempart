using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Snapshots;

namespace Rempart.Core.Cli;

/// <summary>
/// What the tool tells a caller who reads nothing else.
///
/// <para>
/// A scan piped into a scheduler, a script or another tool is judged on this number alone.
/// It was decided by two ternaries buried in <c>Program.cs</c> and by a pair of
/// <c>catch</c> blocks, none of which any test observed: CI asserts that a scan exits 0
/// <em>or</em> 3 without distinguishing them, so a build that returned 3 forever would
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
    ];

    public static string Describe(ExitCode code) => code switch
    {
        ExitCode.Success => "succès",
        ExitCode.Failure => "échec",
        ExitCode.SnapshotIncomplete => "instantané incomplet",
        ExitCode.InsufficientPrivileges => "droits insuffisants",
        ExitCode.Regression => "régression",
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
    /// A broken collector outranks a denied one, and the order matters: a run that both
    /// failed somewhere and was refused elsewhere is a failure, because the failure is the
    /// part that will not fix itself by re-running as administrator. CI relies on this
    /// precedence — it accepts 0 and 3 from a scan on a runner whose rights vary, and
    /// nothing else.
    /// </para>
    /// </summary>
    public static ExitCode ForScan(IReadOnlyList<CollectorResult> collectors) =>
        collectors.Any(c => c.Status == CollectorStatus.Failed) ? ExitCode.Failure
        : collectors.Any(c => c.Status == CollectorStatus.InsufficientPrivileges)
            ? ExitCode.InsufficientPrivileges
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
