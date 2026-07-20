using Rempart.Core.Collectors;
using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Core.Engine;

public sealed record ScanResult(
    string ToolVersion,
    string StartedAtUtc,
    List<CollectorResult> Collectors,
    List<Verdict> Verdicts,
    ScoreCard? Score);

/// <summary>
/// Exécute les collecteurs, puis évalue les règles.
///
/// Deux étapes distinctes et volontairement découplées : les collecteurs décrivent la
/// machine, les règles la jugent. Un collecteur ne porte aucun seuil, une règle ne lit
/// jamais Windows autrement qu'à travers les providers.
///
/// Un collecteur qui échoue est signalé et le scan continue : un rapport partiel et
/// honnête vaut mieux qu'aucun rapport.
/// </summary>
public sealed class ScanEngine(IReadOnlyList<ICollector> collectors, IReadOnlyList<Rule> rules)
{
    public static IReadOnlyList<ICollector> DefaultCollectors => [new InventoryCollector()];

    public ScanEngine(IReadOnlyList<ICollector> collectors)
        : this(collectors, [])
    {
    }

    public static ScanEngine Default() => new(DefaultCollectors, RuleCatalog.Load());

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

        var verdicts = rules
            .Select(rule => RuleEvaluator.Evaluate(rule, providers.Registry))
            .ToList();

        return new ScanResult(
            toolVersion,
            startedAtUtc,
            results,
            verdicts,
            verdicts.Count > 0 ? Scoring.Compute(verdicts) : null);
    }
}
