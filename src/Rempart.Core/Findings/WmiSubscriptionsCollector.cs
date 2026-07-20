using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Abonnements WMI permanents.
///
/// Une persistance sans fichier : rien dans les clés Run, rien dans les tâches
/// planifiées, rien sur le disque à part le dépôt WMI lui-même. Elle survit au
/// redémarrage et se déclenche sur un événement — ouverture de session, heure fixe,
/// démarrage d'un processus.
///
/// Les outils grand public ne l'affichent pas. C'est précisément ce qui la rend
/// intéressante pour un attaquant, et ce qui justifie de l'énumérer ici.
///
/// Sur une machine de particulier, un abonnement permanent est rare. Sur un parc
/// administré, il est courant — les agents de gestion en posent. Le collecteur
/// signale donc sans accuser, sauf pour les consommateurs qui exécutent du code.
/// </summary>
public sealed class WmiSubscriptionsCollector : IFindingCollector
{
    private const string Namespace = @"root\subscription";

    public string Name => "wmi-subscriptions";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        // Consommateurs qui executent du code. Ce sont eux qui portent la charge
        // utile : un filtre seul ne fait rien.
        Collect(providers, findings, "CommandLineEventConsumer",
            ["Name", "CommandLineTemplate", "ExecutablePath"],
            "Exécute une ligne de commande à chaque déclenchement.");

        Collect(providers, findings, "ActiveScriptEventConsumer",
            ["Name", "ScriptFileName", "ScriptText"],
            "Exécute un script à chaque déclenchement, sans passer par un fichier.");

        // Les filtres seuls ne s'executent pas, mais leur presence dit ce qui est
        // surveille — et un filtre sans consommateur est un reste, ou une moitie
        // d'installation.
        CollectFilters(providers, findings);

        return findings;
    }

    private static void Collect(
        ProviderSet providers, List<Finding> findings,
        string className, string[] properties, string why)
    {
        var read = providers.Wmi.Query(Namespace, className, properties);

        if (read.Status == ReadStatus.AccessDenied)
        {
            // Ne pas se taire : un espace de noms illisible n'est pas un espace de
            // noms vide, et c'est justement là que se cache ce qu'on cherche.
            findings.Add(new Finding(
                "wmi-subscription", $"{Namespace}:{className}", "—",
                FindingSeverity.Notable,
                [read.Diagnostic ?? "Énumération refusée. Relancer en administrateur : "
                    + "un abonnement permanent resterait invisible."],
                new Dictionary<string, string>()));
            return;
        }

        foreach (var instance in read.Instances)
        {
            var details = properties
                .Select(p => (p, instance.Find(p)))
                .Where(x => !string.IsNullOrWhiteSpace(x.Item2))
                .ToDictionary(x => x.p, x => x.Item2!, StringComparer.Ordinal);

            findings.Add(new Finding(
                "wmi-subscription",
                $"{className} / {instance.Find("Name") ?? "?"}",
                instance.Find("ExecutablePath") ?? instance.Find("ScriptFileName") ?? className,
                FindingSeverity.Suspicious,
                [why, "Persistance sans fichier : invisible des clés Run et des tâches planifiées."],
                details));
        }
    }

    /// <summary>
    /// Filtres livres avec Windows. Presents sur toute machine : les signaler a chaque
    /// scan ajouterait du bruit permanent, et c'est le bruit qui fait qu'on cesse de
    /// lire un rapport.
    /// </summary>
    private static readonly string[] BuiltIn =
    [
        "SCM Event Log Filter",
        "BVTFilter",
    ];

    private static void CollectFilters(ProviderSet providers, List<Finding> findings)
    {
        var read = providers.Wmi.Query(Namespace, "__EventFilter", ["Name", "Query"]);

        if (read.Status != ReadStatus.Found)
        {
            return;
        }

        foreach (var instance in read.Instances)
        {
            var query = instance.Find("Query") ?? string.Empty;
            var name = instance.Find("Name") ?? "?";

            var known = BuiltIn.Contains(name, StringComparer.OrdinalIgnoreCase);

            findings.Add(new Finding(
                "wmi-subscription",
                $"__EventFilter / {instance.Find("Name") ?? "?"}",
                query,
                known ? FindingSeverity.Benign : FindingSeverity.Notable,
                known
                    ? []
                    : ["Filtre d'événement enregistré. Seul il n'exécute rien ; associé à "
                       + "un consommateur, il déclenche du code."],
                new Dictionary<string, string>(StringComparer.Ordinal) { ["requête"] = query }));
        }
    }
}
