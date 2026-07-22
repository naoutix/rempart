using Rempart.Core.Collectors;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Core.Engine;

public sealed record ScanResult(
    string ToolVersion,
    string StartedAtUtc,
    List<CollectorResult> Collectors,
    List<Verdict> Verdicts,
    List<Finding> Findings,
    ScoreCard? Score,
    /// <summary>Identifie le catalogue evalue : deux rapports ne sont comparables
    /// que s'ils partagent la meme empreinte.</summary>
    string RulesFingerprint,
    /// <summary>Age des donnees evaluees au moment du scan (ADR-002, D15).</summary>
    DataAge DataAge);

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

    /// <summary>
    /// Collecteurs de constats. Separes des collecteurs de champs : ils enumerent ce
    /// qui est present au lieu de decrire des valeurs connues d'avance.
    /// </summary>
    /// <summary>
    /// Collecteurs de constats, armés de la liste de pilotes en vigueur. La liste vient
    /// du magasin de mises à jour (D12) ; à défaut, elle est vide et le collecteur juge
    /// les pilotes sur leur seule signature.
    /// </summary>
    public static IReadOnlyList<IFindingCollector> DefaultFindingCollectors(
        Updates.DriverBlocklist blocklist) =>
    [
        new AutorunsCollector(),
        new WmiSubscriptionsCollector(),
        new ScheduledTasksCollector(),
        new LoadedDriversCollector(blocklist),
        new RunningProcessesCollector(),
        new LogonExtensibilityCollector(),
        new LsaPackagesCollector(),
        new UnquotedServicePathCollector(),
        new ComHijackCollector(),
        new ListeningPortsCollector(),
        new DnsResolverCollector(),
        new HostsFileCollector(),
        new ProxyCollector(),
        new WifiProfileCollector(),
    ];

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
            Rules.CheckReader.Touch(rule.Check, providers);

            if (rule.AppliesWhen?.Registry is { } condition)
            {
                Rules.CheckReader.Touch(condition, providers);
            }
        }
    }

    public ScanResult Run(
        ProviderSet providers, string toolVersion, string startedAtUtc, string? dataAsOfUtc = null,
        IReadOnlyList<IFindingCollector>? findingCollectors = null)
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
            .Select(rule => RuleEvaluator.Evaluate(rule, providers, system))
            .ToList();

        var findings = new List<Finding>();
        foreach (var collector in findingCollectors
            ?? DefaultFindingCollectors(Updates.DriverBlocklist.Empty))
        {
            try
            {
                findings.AddRange(collector.Collect(providers));
            }
            catch (Exception ex)
            {
                // Un collecteur de constats qui echoue ne doit pas emporter le scan.
                findings.Add(new Finding(collector.Name, "collecteur", collector.Name,
                    FindingSeverity.Notable, [$"Enumeration interrompue : {ex.Message}"], new Dictionary<string, string>()));
            }
        }

        return new ScanResult(
            toolVersion,
            startedAtUtc,
            results,
            verdicts,
            findings,
            verdicts.Count > 0 ? Scoring.Compute(verdicts) : null,
            RuleCatalog.Fingerprint(rules),
            // Contre l'heure du scan : en direct c'est l'heure réelle, en rejeu l'heure
            // figée de la capture. La date de référence est celle du catalogue embarqué,
            // ou celle de la mise à jour appliquée si l'appelant en fournit une.
            DataFreshness.At(dataAsOfUtc ?? RuleCatalog.EmbeddedAsOfUtc, startedAtUtc));
    }
}
