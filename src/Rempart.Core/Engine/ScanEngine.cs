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

    public static ScanEngine Default(string? externalRules = null) =>
        new(DefaultCollectors, RuleCatalog.Load(externalRules));

    /// <summary>
    /// Lit toutes les clés que les règles pourraient consulter, sans rien évaluer.
    ///
    /// Sans cela, un instantané ne contiendrait que les lectures réellement effectuées
    /// sur la machine d'origine : une règle hors périmètre là-bas — non jointe à un
    /// domaine, RDP éteint — n'aurait rien enregistré, et le rejeu échouerait dès qu'on
    /// change de contexte. Une fixture doit être rejouable partout, pas seulement dans
    /// les conditions de sa capture.
    /// </summary>
    public void Prefetch(ProviderSet providers)
    {
        foreach (var rule in rules)
        {
            Read(rule.Check);

            if (rule.AppliesWhen?.Registry is { } condition)
            {
                Read(condition);
            }
        }

        void Read(Rules.CheckSpec check)
        {
            if (check.Kind == Rules.CheckKind.RegistryKey)
            {
                providers.Registry.KeyExists(check.Path);
            }
            else if (check.ValueName is { } value)
            {
                providers.Registry.ReadValue(check.Path, value);
            }
        }
    }

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

        // Les conditions d'applicabilite s'appuient sur des faits machine autant que
        // sur le registre : l'evaluateur a besoin des deux.
        var system = providers.SystemInfo.Read();

        var verdicts = rules
            .Select(rule => RuleEvaluator.Evaluate(rule, providers.Registry, system))
            .ToList();

        return new ScanResult(
            toolVersion,
            startedAtUtc,
            results,
            verdicts,
            verdicts.Count > 0 ? Scoring.Compute(verdicts) : null);
    }
}
