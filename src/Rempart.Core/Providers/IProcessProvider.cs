namespace Rempart.Core.Providers;

/// <summary>
/// A running process, reduced to what an audit needs to know.
///
/// The command line is included: two processes started from the same binary can do
/// opposite things depending on their arguments, and intent often shows there. The
/// parent PID too — an interpreter launched by an office suite means something
/// different from one launched by a terminal.
/// </summary>
public sealed record RunningProcess(
    int Pid,
    int ParentPid,
    string Name,
    string Path,
    string CommandLine);

/// <summary>
/// Enumerates running processes.
///
/// <para>
/// Abstracted like the rest (ADR-001, D5): the judgment — an unsigned binary running
/// from an unusual location — is tested against a given list, without a machine in the
/// required state.
/// </para>
/// </summary>
/// <summary>
/// The process list, plus whether it could be read at all. Same reasoning as
/// <see cref="DriverRead"/>: enumeration goes through WMI, and an empty list returned by
/// a machine that could not answer is indistinguishable from a machine running nothing.
/// </summary>
public sealed record ProcessRead(
    ReadStatus Status,
    IReadOnlyList<RunningProcess> Processes,
    string? Diagnostic = null)
    : IStatusCarryingRead<ProcessRead, RunningProcess>
{
    public static readonly ProcessRead AccessDenied = new(ReadStatus.AccessDenied, []);

    public static ProcessRead Found(IReadOnlyList<RunningProcess> processes) =>
        new(ReadStatus.Found, processes);

    public static ProcessRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);

    IReadOnlyList<RunningProcess> IStatusCarryingRead<ProcessRead, RunningProcess>.Items =>
        Processes;

    static ProcessRead IStatusCarryingRead<ProcessRead, RunningProcess>.Compose(
        ReadStatus status, IReadOnlyList<RunningProcess> items, string? diagnostic) =>
        new(status, items, diagnostic);
}

public interface IProcessProvider
{
    ProcessRead Enumerate();
}
