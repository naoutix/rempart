namespace Rempart.Core.Providers;

/// <summary>Start mode, as declared to the service control manager.</summary>
public enum ServiceStartMode
{
    Boot,
    System,
    Automatic,
    Manual,
    Disabled,
    Unknown,
}

/// <summary>Current state of the service.</summary>
public enum ServiceState
{
    Stopped,
    Running,
    Paused,
    Unknown,
}

public sealed record ServiceInfo(string Name, ServiceState State, ServiceStartMode StartMode);

public sealed record ServiceRead(
    ReadStatus Status,
    ServiceInfo? Info,

    /// <summary>
    /// Failure reason, when the failure is not a genuine refusal.
    ///
    /// <para>
    /// The sibling of <see cref="WmiRead.Diagnostic"/>, arriving one interface later for the
    /// same reason. <c>LiveServiceStateProvider</c> ended its Win32 mapping on
    /// <c>_ =&gt; ServiceRead.AccessDenied</c>: a service control manager that could not be
    /// opened, a query that failed on any code at all, all answered « accès refusé ». Every
    /// <c>type: service</c> rule then landed under that one label at once, and its only
    /// remedy — re-running elevated — would have changed nothing.
    /// </para>
    ///
    /// <para>
    /// Null for a genuine refusal, written for a failure — that is the whole of what
    /// separates them, because <see cref="ReadStatus"/> has no member for a failure. Giving
    /// it one is the status-channel work, not this. Added <em>beside</em> the two existing
    /// fields and defaulted to null, so a capture written before it replays exactly as it
    /// did: absent means « no failure was recorded », which is what every older capture
    /// meant.
    /// </para>
    /// </summary>
    string? Diagnostic = null)
{
    public static readonly ServiceRead NotInstalled = new(ReadStatus.NotFound, null);
    public static readonly ServiceRead AccessDenied = new(ReadStatus.AccessDenied, null);

    public static ServiceRead Found(ServiceInfo info) => new(ReadStatus.Found, info);

    /// <summary>
    /// A read that failed, naming what failed. <see cref="ReadStatus.AccessDenied"/> like
    /// every other failed read in this namespace — the enum has no fourth member — so the
    /// verdict it produces is unchanged: <c>Unknown</c>, excluded from the score, never
    /// <c>Fail</c>.
    ///
    /// <para>
    /// What changes is that the reason reaches <c>Verdict.Observed</c>, and from there every
    /// rendering. It reached only the JSON at first: the « non vérifiable » sections of the
    /// console, the HTML and the Markdown listed the rule and nothing else under a heading
    /// reading « accès refusé », so a service control manager that would not open was
    /// announced as a missing privilege — as the WMI diagnostic had been before it. The three
    /// heads now print the reason where there is one, and claim no cause at all where there
    /// is none — a control that explained nothing may equally be a class holding no instance,
    /// so what they offer there is the remedy for a missing right, not a verdict on what
    /// happened, and only on a scan that has not already tried it.
    /// </para>
    /// </summary>
    public static ServiceRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, null, reason);
}

/// <summary>
/// Queries the service control manager.
///
/// The registry does not show this: a service can be configured for automatic start and
/// still be stopped, because it failed or someone stopped it. For Windows Update or the
/// firewall, an audit must establish whether the service is actually running, not just
/// whether it is supposed to run.
/// </summary>
public interface IServiceStateProvider
{
    ServiceRead Read(string serviceName);
}
