namespace Rempart.Core.Providers;

/// <summary>Mode de démarrage, tel que déclaré au gestionnaire de services.</summary>
public enum ServiceStartMode
{
    Boot,
    System,
    Automatic,
    Manual,
    Disabled,
    Unknown,
}

/// <summary>État courant du service.</summary>
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
/// Interroge le gestionnaire de services.
///
/// Ce que le registre ne dit pas : un service peut être configuré en démarrage
/// automatique et se trouver arrêté — parce qu'il a échoué, ou qu'on l'a stoppé. Pour
/// Windows Update ou le pare-feu, la différence entre « censé tourner » et « tourne »
/// est exactement ce qu'un audit doit établir.
/// </summary>
public interface IServiceStateProvider
{
    ServiceRead Read(string serviceName);
}
