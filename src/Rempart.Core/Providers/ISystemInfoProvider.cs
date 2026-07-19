namespace Rempart.Core.Providers;

public sealed record SystemInfo(
    string MachineName,
    string OsVersion,
    bool Is64BitOperatingSystem,
    bool IsElevated,
    int ProcessorCount,
    long UptimeSeconds,
    string FirmwareType);

/// <summary>
/// Informations système qui ne viennent pas du registre. Abstrait pour la même raison
/// que <see cref="IRegistryProvider"/> : un instantané doit pouvoir être rejoué à
/// l'identique, y compris pour des valeurs volatiles comme l'uptime.
/// </summary>
public interface ISystemInfoProvider
{
    SystemInfo Read();
}

/// <summary>Les providers dont dispose un collecteur.</summary>
public sealed class ProviderSet(IRegistryProvider registry, ISystemInfoProvider systemInfo)
{
    public IRegistryProvider Registry { get; } = registry;

    public ISystemInfoProvider SystemInfo { get; } = systemInfo;
}
