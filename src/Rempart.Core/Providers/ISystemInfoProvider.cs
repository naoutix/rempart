namespace Rempart.Core.Providers;

public sealed record SystemInfo(
    string MachineName,
    string OsVersion,
    bool Is64BitOperatingSystem,
    bool IsElevated,
    int ProcessorCount,
    long UptimeSeconds,
    string FirmwareType,

    /// <summary>
    /// Machine jointe à un domaine Active Directory.
    ///
    /// Sert de condition d'applicabilité : plusieurs durcissements n'ont de sens que
    /// sous stratégie de groupe centrale, et les appliquer sur un poste autonome
    /// retire des fonctionnalités sans rien apporter.
    /// </summary>
    bool IsDomainJoined = false);

/// <summary>
/// Informations système qui ne viennent pas du registre. Abstrait pour la même raison
/// que <see cref="IRegistryProvider"/> : un instantané doit pouvoir être rejoué à
/// l'identique, y compris pour des valeurs volatiles comme l'uptime.
/// </summary>
public interface ISystemInfoProvider
{
    SystemInfo Read();
}

/// <summary>Les providers dont disposent collecteurs et règles.</summary>
public sealed class ProviderSet(
    IRegistryProvider registry,
    ISystemInfoProvider systemInfo,
    IServiceStateProvider? services = null)
{
    public IRegistryProvider Registry { get; } = registry;

    public ISystemInfoProvider SystemInfo { get; } = systemInfo;

    /// <summary>
    /// Absent tant qu'aucun appelant n'en fournit : les contrôles portant sur les
    /// services rendent alors « non vérifiable » plutôt que d'échouer. Un provider
    /// manquant est une lacune de couverture, pas une non-conformité de la machine.
    /// </summary>
    public IServiceStateProvider Services { get; } = services ?? UnavailableServices.Instance;
}

/// <summary>Répond « accès refusé » à toute question : aucune conclusion n'en sort.</summary>
internal sealed class UnavailableServices : IServiceStateProvider
{
    public static readonly UnavailableServices Instance = new();

    public ServiceRead Read(string serviceName) => ServiceRead.AccessDenied;
}
