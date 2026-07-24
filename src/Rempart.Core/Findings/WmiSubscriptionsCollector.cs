using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Permanent WMI event subscriptions.
///
/// Fileless persistence: nothing in the Run keys, nothing in scheduled tasks, nothing
/// on disk except the WMI repository itself. It survives reboot and triggers on an
/// event — logon, fixed time, process start.
///
/// Consumer-grade tools do not display it. That makes it attractive to an attacker,
/// and is the reason it is enumerated here.
///
/// On a personal machine, a permanent subscription is rare. On a managed fleet, it is
/// common — management agents create them. The collector therefore reports without
/// accusing, except for consumers that execute code.
/// </summary>
public sealed class WmiSubscriptionsCollector : IFindingCollector
{
    private const string Namespace = @"root\subscription";

    public string Name => "wmi-subscriptions";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        // Consumers that execute code. They carry the payload: a filter alone does
        // nothing.
        Collect(providers, findings, "CommandLineEventConsumer",
            ["Name", "CommandLineTemplate", "ExecutablePath"],
            "Exécute une ligne de commande à chaque déclenchement.");

        Collect(providers, findings, "ActiveScriptEventConsumer",
            ["Name", "ScriptFileName", "ScriptText"],
            "Exécute un script à chaque déclenchement, sans passer par un fichier.");

        // Filters alone do not execute, but their presence shows what is being
        // watched — and a filter without a consumer is a leftover, or half of an
        // installation.
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
            // Report the failure: an unreadable namespace is not an empty namespace,
            // and it is exactly where what this collector looks for would hide.
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
    /// Filters shipped with Windows. Present on every machine: reporting them on each
    /// scan would add permanent noise and make the report harder to read.
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
