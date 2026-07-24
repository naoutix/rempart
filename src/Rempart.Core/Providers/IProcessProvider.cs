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
public interface IProcessProvider
{
    IReadOnlyList<RunningProcess> Enumerate();
}
