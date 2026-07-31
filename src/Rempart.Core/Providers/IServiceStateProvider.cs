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
    /// Null for a genuine refusal, written for a failure. That used to be the <em>whole</em>
    /// of what separated them, because <see cref="ReadStatus"/> had no member for a failure;
    /// since #173 it has one and since #177 this read uses it, so the separation is now in the
    /// field a caller branches on and this one only decides what gets printed. Added
    /// <em>beside</em> the two existing fields and defaulted to null, so a capture written
    /// before it replays exactly as it did: absent means « no failure was recorded », which is
    /// what every older capture meant.
    /// </para>
    /// </summary>
    string? Diagnostic = null)
{
    public static readonly ServiceRead NotInstalled = new(ReadStatus.NotFound, null);
    public static readonly ServiceRead AccessDenied = new(ReadStatus.AccessDenied, null);

    public static ServiceRead Found(ServiceInfo info) => new(ReadStatus.Found, info);

    /// <summary>
    /// A read that failed, naming what failed. <see cref="ReadStatus.Failed"/> since #177 —
    /// it said <see cref="ReadStatus.AccessDenied"/> while the enum had no fourth member, and
    /// went on saying it for two issues after one was added. The verdict it produces is
    /// deliberately unchanged: <c>Unknown</c>, excluded from the score, never <c>Fail</c>.
    /// <c>CheckReader.ReadService</c> is what keeps that true, and it had to be widened in the
    /// same commit — a check whose read fell through to « absent » would have been compared
    /// against the rule and could have come back <c>Fail</c> for a service control manager
    /// nobody managed to open.
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
        new(ReadStatus.Failed, null, reason);
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
