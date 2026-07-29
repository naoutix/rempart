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
    IReadOnlyList<TaskAction> Actions,

    /// <summary>
    /// Value of <c>Settings/DeleteExpiredTaskAfter</c>, or null when the setting is
    /// absent — the common case.
    /// </summary>
    string? DeleteExpiredTaskAfter = null,

    /// <summary>Whether at least one trigger carries an <c>EndBoundary</c>.</summary>
    /// <remarks>
    /// Both raw facts are reported rather than a single "will disappear" flag: a
    /// provider describes, it does not conclude. Windows removes a task on its own only
    /// when the two hold together, and that rule belongs in the core, where it can be
    /// tested without a scheduler.
    /// </remarks>
    bool HasExpiringTrigger = false);

/// <summary>
/// A folder the enumeration could not read in full, and what it gave up there.
///
/// <para>
/// The scheduler is a tree, and it is walked one COM call at a time: a folder's tasks, its
/// subfolders, each task in turn. Every one of those calls can fail on its own, and each
/// failure abandons something — one task, one folder, a whole branch — while the folders
/// that answered still fill the inventory. The read is therefore partial far more often
/// than it is refused outright, which is the state it had no way of expressing.
/// </para>
///
/// <para>
/// The folder is a field rather than a phrase inside <see cref="ScheduledTaskRead.Diagnostic"/>,
/// and that is what makes it scrubbable: a folder outside <c>\Microsoft\</c> names an
/// installed product, and a per-user folder carries an account SID — the very labels
/// <c>Anonymiser.ScrubTask</c> hashes on the tasks stored beside it. A path buried in free
/// text cannot be cleaned reliably after the fact, which is the lesson
/// <see cref="BrowserExtensionRead.Partial"/> paid for with a Firefox profile salt.
/// </para>
/// </summary>
public sealed record TaskFolderGap(
    /// <summary>Path as the scheduler spells it: <c>\</c>, <c>\Microsoft\Windows\…</c>.</summary>
    string Folder,

    /// <summary>
    /// The call that was abandoned and the code it failed with. Carries no path, so that
    /// <see cref="Folder"/> stays the only place one has to be cleaned.
    /// </summary>
    string Reason)
{
    /// <summary><c>E_ACCESSDENIED</c>, the one HRESULT that means "elevate and retry".</summary>
    private const uint AccessDeniedHResult = 0x80070005;

    /// <summary>
    /// Names the call that failed and the code it failed with.
    ///
    /// <para>
    /// Only <c>E_ACCESSDENIED</c> is called a denial. Every other HRESULT is printed as
    /// itself — the invariant CONTRIBUTING records, "never translate a failure into access
    /// denied", which cost this project two milestones of a mute WMI that read as missing
    /// privileges. A scheduler folder is that same trap one interface over, and the walk
    /// touches five of them per folder.
    /// </para>
    /// </summary>
    public static TaskFolderGap Of(string folder, string call, int hresult) =>
        new(folder, (uint)hresult == AccessDeniedHResult
            ? $"{call} : accès refusé (0x80070005)"
            : $"{call} : échec 0x{(uint)hresult:X8}");
}

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
    string? Diagnostic = null,

    /// <summary>
    /// What the walk gave up on, or null when it gave up on nothing.
    ///
    /// <para>
    /// Added beside the tasks rather than replacing anything, so that a capture written
    /// before this field stays replayable: its absence means the walk lost nothing, which
    /// is exactly what such a capture used to claim — and, until this field existed, all it
    /// could claim.
    /// </para>
    /// </summary>
    IReadOnlyList<TaskFolderGap>? Gaps = null)
{
    public static readonly ScheduledTaskRead AccessDenied = new(ReadStatus.AccessDenied, []);

    public static ScheduledTaskRead Found(IReadOnlyList<ScheduledTask> tasks) =>
        new(ReadStatus.Found, tasks);

    public static ScheduledTaskRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);

    /// <summary>
    /// What was walked, and what the walk abandoned. Same shape as
    /// <see cref="ListeningPortRead.Partial"/> and <see cref="BrowserExtensionRead.Partial"/>,
    /// for the same reason: the tasks that were read stay in the inventory and the gap is
    /// named beside them. Dropping several hundred tasks because one folder refused would
    /// trade one silence for another, and keeping them while saying nothing is the silence
    /// this replaces.
    /// </summary>
    /// <remarks>
    /// The sentence counts and names nothing: the folders live in
    /// <see cref="TaskFolderGap.Folder"/>, one per gap, which is where the anonymiser can
    /// reach them and where a report reads them from.
    /// </remarks>
    public static ScheduledTaskRead Partial(
        IReadOnlyList<ScheduledTask> tasks, IReadOnlyList<TaskFolderGap> gaps) =>
        new(ReadStatus.AccessDenied, tasks,
            $"{gaps.Select(gap => gap.Folder).Distinct(StringComparer.Ordinal).Count()} "
            + "dossier(s) de tâches lu(s) partiellement : une tâche planifiée qui s'y "
            + "trouve n'apparaît pas dans cet inventaire.",
            gaps);
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
