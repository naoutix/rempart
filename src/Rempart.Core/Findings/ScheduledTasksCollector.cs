using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Scheduled tasks.
///
/// The largest persistence surface in Windows, and the least visible: a task survives
/// reboot, triggers on a schedule, an event or a logon, and appears in none of the
/// <c>Run</c> keys the autoruns collector inspects.
///
/// <para>
/// Windows ships several hundred tasks. Enumerating them all is necessary — a task
/// cannot be known legitimate without looking at it — but displaying them all is not:
/// the report only details what deserves review, and just counts the rest. A report
/// that buries three problems in three hundred green lines will not be read.
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
            // Report the failure: an unreadable scheduler is not an empty scheduler.
            // Returning zero tasks silently would make an outage look like a healthy
            // machine — the same confusion that left WMI broken for two batches.
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

        // System tasks share a handful of executables. Verifying each signature only
        // once avoids a few hundred identical catalog lookups, each of which costs a
        // disk access.
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

        // A task can carry several actions. The finding keeps the most severe one: a
        // single unsigned action is enough to deserve review.
        var reasons = new List<string>();
        var severity = FindingSeverity.Benign;
        var target = executables[0].Path;
        SignatureJudgement? worst = null;

        foreach (var action in executables)
        {
            // The scheduler resolves a bare name at run time; if resolution failed
            // upstream, the signature cannot be checked against a known file. Saying
            // so is better than concluding "the file does not exist" — it probably
            // exists, we just did not find it.
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

        // Recorded in all cases, including valid. Recording the signature only when
        // it is a problem would make "signed by Microsoft" indistinguishable from
        // "never verified" — the report must state what it checked, not only what it
        // flags.
        if (worst is not null)
        {
            SignatureLadder.Describe(worst.Signature, details);
        }

        // Stated explicitly, never inferred from silence: a disabled task does not
        // run, and the reader must be able to factor that in without the finding
        // disappearing — a disabled task can be re-enabled.
        if (!task.Enabled && severity != FindingSeverity.Benign)
        {
            reasons.Add("Tâche désactivée : elle ne s'exécute pas en l'état.");
        }

        return new Finding("scheduled-task", task.Path, target, severity, reasons, details);
    }

    /// <summary>
    /// Task with no executable action: COM handler, e-mail, message box. These legacy
    /// forms still exist on real machines.
    ///
    /// Enumerated without being judged, like a startup-folder shortcut: there is no
    /// file whose signature could be verified, and the report says so rather than
    /// implying a verification that never happened.
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
    /// A path without a directory was not resolved: the provider returns the name
    /// as-is when neither System32 nor the PATH contains it.
    ///
    /// The separators are hard-coded rather than taken from <c>Path</c>: these paths
    /// come from a Windows machine and stay Windows paths, including when the snapshot
    /// is replayed on Linux — which CI does, and which actually made every Windows
    /// path look unresolved.
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
