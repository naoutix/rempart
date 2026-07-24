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

public sealed record ServiceRead(ReadStatus Status, ServiceInfo? Info)
{
    public static readonly ServiceRead NotInstalled = new(ReadStatus.NotFound, null);
    public static readonly ServiceRead AccessDenied = new(ReadStatus.AccessDenied, null);

    public static ServiceRead Found(ServiceInfo info) => new(ReadStatus.Found, info);
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
