using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Tâches planifiées.
///
/// La plus grande surface de persistance de Windows, et la moins visible : une tâche
/// survit au redémarrage, se déclenche sur un horaire, un événement ou une ouverture
/// de session, et n'apparaît dans aucune des clés <c>Run</c> qu'inspecte le collecteur
/// de démarrage automatique.
///
/// <para>
/// Windows en livre plusieurs centaines. Les énumérer toutes est nécessaire — on ne
/// peut pas savoir qu'une tâche est légitime sans la regarder — mais les afficher
/// toutes ne l'est pas : le rapport ne détaille que ce qui mérite un examen, et se
/// contente de compter le reste. Un rapport qui noie trois problèmes dans trois cents
/// lignes vertes ne sera pas lu.
/// </para>
/// </summary>
public sealed class ScheduledTasksCollector : IFindingCollector
{
    public string Name => "scheduled-tasks";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var read = providers.ScheduledTasks.Enumerate();

        if (read.Status != ReadStatus.Found)
        {
            // Ne pas se taire : un planificateur illisible n'est pas un planificateur
            // vide. Rendre zéro tâche sans le dire ferait passer une panne pour une
            // machine saine — exactement la confusion qui a rendu WMI inopérant deux
            // lots durant.
            return
            [
                new Finding(
                    "scheduled-task", "planificateur de tâches", "—",
                    FindingSeverity.Notable,
                    [read.Diagnostic ?? "Énumération refusée. Relancer en administrateur : "
                        + "une tâche planifiée resterait invisible."],
                    new Dictionary<string, string>()),
            ];
        }

        var findings = new List<Finding>();

        // Les tâches du système partagent une poignée d'exécutables. Vérifier chaque
        // signature une seule fois évite quelques centaines de recherches de catalogue
        // identiques, dont chacune coûte un accès disque.
        var judged = new Dictionary<string, SignatureJudgement>(StringComparer.OrdinalIgnoreCase);

        foreach (var task in read.Tasks)
        {
            findings.Add(Examine(task, providers.Signatures, judged));
        }

        return findings;
    }

    private static Finding Examine(
        ScheduledTask task,
        ISignatureProvider signatures,
        Dictionary<string, SignatureJudgement> judged)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["état"] = task.Enabled ? task.State : "désactivée",
        };

        Set(details, "auteur", task.Author);
        Set(details, "compte", task.UserId);
        Set(details, "élévation", task.RunLevel);

        var executables = task.Actions
            .Where(a => a.Kind == "exec" && a.Path.Length > 0)
            .ToList();

        if (executables.Count == 0)
        {
            return NotJudged(task, details);
        }

        details["commande"] = string.Join(" ; ", executables
            .Select(a => a.Arguments.Length > 0 ? $"{a.Path} {a.Arguments}" : a.Path));

        // Une tâche peut porter plusieurs actions. Le constat retient la plus grave :
        // une seule action non signée suffit à mériter un regard.
        var reasons = new List<string>();
        var severity = FindingSeverity.Benign;
        var target = executables[0].Path;
        SignatureJudgement? worst = null;

        foreach (var action in executables)
        {
            // Le planificateur résout un nom nu à l'exécution ; si la résolution a
            // échoué en amont, la signature ne peut pas porter sur un fichier connu.
            // Le dire vaut mieux que de conclure « le fichier n'existe pas » — il
            // existe probablement, c'est nous qui ne l'avons pas trouvé.
            if (!IsResolved(action.Path))
            {
                if (severity < FindingSeverity.Notable)
                {
                    severity = FindingSeverity.Notable;
                    target = action.Path;
                    reasons =
                    [
                        "Chemin non résolu : la tâche désigne l'exécutable par son seul "
                        + "nom, introuvable dans System32 ni dans le PATH. Sa signature "
                        + "n'a donc pas été vérifiée.",
                    ];
                }

                continue;
            }

            if (!judged.TryGetValue(action.Path, out var judgement))
            {
                judgement = SignatureLadder.Judge(action.Path, signatures);
                judged[action.Path] = judgement;
            }

            if (worst is null || judgement.Severity > severity)
            {
                severity = judgement.Severity > severity ? judgement.Severity : severity;
                target = action.Path;
                reasons = [.. judgement.Reasons];
                worst = judgement;
            }
        }

        // Décrite dans tous les cas, y compris valide. Ne consigner la signature que
        // lorsqu'elle pose problème rendrait « signée par Microsoft » indiscernable de
        // « jamais vérifiée » — un rapport doit dire ce qu'il a regardé, pas seulement
        // ce qu'il reproche.
        if (worst is not null)
        {
            SignatureLadder.Describe(worst.Signature, details);
        }

        // Dit, jamais déduit d'un silence : une tâche désactivée ne s'exécute pas, et
        // le lecteur doit pouvoir en tenir compte sans que le constat disparaisse —
        // ce qui est désactivé se réactive.
        if (!task.Enabled && severity != FindingSeverity.Benign)
        {
            reasons.Add("Tâche désactivée : elle ne s'exécute pas en l'état.");
        }

        return new Finding("scheduled-task", task.Path, target, severity, reasons, details);
    }

    /// <summary>
    /// Tâche sans action exécutable : gestionnaire COM, envoi de courriel, message.
    /// Ces formes héritées existent encore sur des machines réelles.
    ///
    /// Énumérée sans être jugée, comme un raccourci du dossier de démarrage : il n'y a
    /// pas de fichier dont vérifier la signature, et le rapport le dit plutôt que de
    /// laisser croire à une vérification qui n'a pas eu lieu.
    /// </summary>
    private static Finding NotJudged(ScheduledTask task, Dictionary<string, string> details)
    {
        var kinds = task.Actions.Select(a => a.Kind).Distinct(StringComparer.Ordinal).ToList();

        details["type"] = kinds.Count > 0 ? string.Join(", ", kinds) : "aucune action";
        details["note"] = kinds.Count > 0
            ? "Action sans exécutable : aucune signature à vérifier."
            : "Aucune action lisible dans la définition de la tâche.";

        return new Finding(
            "scheduled-task", task.Path, task.Name, FindingSeverity.Benign, [], details);
    }

    /// <summary>
    /// Un chemin sans dossier n'a pas été résolu : le provider rend le nom tel quel
    /// quand ni System32 ni le PATH ne le contiennent.
    ///
    /// Les séparateurs sont écrits en dur plutôt que pris de <c>Path</c> : ces chemins
    /// viennent d'une machine Windows et le restent, y compris quand l'instantané est
    /// rejoué sur Linux — ce que fait la CI, et qui a effectivement fait passer tout
    /// chemin Windows pour non résolu.
    /// </summary>
    private static bool IsResolved(string path) => path.Contains('\\') || path.Contains('/');

    private static void Set(IDictionary<string, string> details, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            details[key] = value;
        }
    }
}
