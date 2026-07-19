using Rempart.Core.Collectors;
using Rempart.Core.Providers;

namespace Rempart.Core.Engine;

public sealed record ScanResult(
    string ToolVersion,
    string StartedAtUtc,
    List<CollectorResult> Collectors);

/// <summary>
/// Exécute les collecteurs. Un collecteur qui échoue est signalé et le scan continue :
/// un rapport partiel et honnête vaut mieux qu'aucun rapport.
/// </summary>
public sealed class ScanEngine(IReadOnlyList<ICollector> collectors)
{
    public static IReadOnlyList<ICollector> DefaultCollectors => [new InventoryCollector()];

    public ScanResult Run(ProviderSet providers, string toolVersion, string startedAtUtc)
    {
        var results = new List<CollectorResult>(collectors.Count);

        foreach (var collector in collectors)
        {
            try
            {
                results.Add(collector.Collect(providers));
            }
            catch (Exception ex)
            {
                results.Add(new CollectorResult(
                    collector.Name,
                    CollectorStatus.Failed,
                    [],
                    [$"Le collecteur a échoué : {ex.Message}"]));
            }
        }

        return new ScanResult(toolVersion, startedAtUtc, results);
    }
}
