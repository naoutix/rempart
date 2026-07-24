namespace Rempart.Core.Providers;

/// <summary>
/// A scheduled task action: the program launched and its arguments.
///
/// A task can carry several actions, and some carry no executable one — send email,
/// show message, COM handler. These legacy forms still exist on real machines; omitting
/// them would make such a task look like it has no action at all.
/// </summary>
public sealed record TaskAction(string Kind, string Path, string Arguments);

/// <summary>
/// A scheduled task, reduced to what an audit needs to know.
///
/// The enabled state is part of it: a disabled task does not run, and the report must
/// be able to say so instead of implying otherwise.
/// </summary>
public sealed record ScheduledTask(
    string Path,
    string Name,
    bool Enabled,
    string State,
    string? Author,
    string? UserId,
    string? RunLevel,
    IReadOnlyList<TaskAction> Actions);

public sealed record ScheduledTaskRead(
    ReadStatus Status,
    IReadOnlyList<ScheduledTask> Tasks,

    /// <summary>
    /// Failure reason, when the failure is not a genuine access denial.
    ///
    /// Same rationale as <see cref="WmiRead.Diagnostic"/>: returning "access denied"
    /// for every failure makes a bug indistinguishable from missing privileges. That
    /// mistake has already cost time in two milestones of this project.
    /// </summary>
    string? Diagnostic = null)
{
    public static readonly ScheduledTaskRead AccessDenied = new(ReadStatus.AccessDenied, []);

    public static ScheduledTaskRead Found(IReadOnlyList<ScheduledTask> tasks) =>
        new(ReadStatus.Found, tasks);

    public static ScheduledTaskRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);
}

/// <summary>
/// Enumerates scheduled tasks.
///
/// This is the largest persistence surface on Windows: a task survives reboot, triggers
/// on a schedule, an event, or a logon, and appears in none of the <c>Run</c> keys the
/// autostart collector inspects.
///
/// Abstracted like the rest (ADR-001, D5): without this, no test could exercise the
/// judgment without a machine in the required state.
/// </summary>
public interface IScheduledTaskProvider
{
    ScheduledTaskRead Enumerate();
}
