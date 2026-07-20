namespace Rempart.Core.Providers;

/// <summary>
/// Une action de tâche planifiée : le programme lancé et ses arguments.
///
/// Une tâche peut en porter plusieurs, et certaines n'en portent aucune d'exécutable —
/// envoi de courriel, message, gestionnaire COM. Ces formes héritées existent encore
/// sur des machines réelles ; les taire reviendrait à dire qu'une tâche est sans action.
/// </summary>
public sealed record TaskAction(string Kind, string Path, string Arguments);

/// <summary>
/// Une tâche planifiée, réduite à ce qu'un audit doit en savoir.
///
/// L'état d'activation en fait partie : une tâche désactivée ne s'exécute pas, et le
/// rapport doit pouvoir le dire plutôt que de laisser croire au contraire.
/// </summary>
public sealed record ScheduledTask(
    string Path,
    string Name,
    bool Enabled,
    string State,
    string? Author,
    string? UserId,
    string? RunLevel,
    IReadOnlyList<TaskAction> Actions);

public sealed record ScheduledTaskRead(
    ReadStatus Status,
    IReadOnlyList<ScheduledTask> Tasks,

    /// <summary>
    /// Raison de l'échec quand il ne s'agit pas d'un refus d'accès légitime.
    ///
    /// Même motif que <see cref="WmiRead.Diagnostic"/> : rendre « accès refusé » pour
    /// toute défaillance rend un bug indiscernable d'un manque de droits. Cela a déjà
    /// coûté deux lots sur ce projet.
    /// </summary>
    string? Diagnostic = null)
{
    public static readonly ScheduledTaskRead AccessDenied = new(ReadStatus.AccessDenied, []);

    public static ScheduledTaskRead Found(IReadOnlyList<ScheduledTask> tasks) =>
        new(ReadStatus.Found, tasks);

    public static ScheduledTaskRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);
}

/// <summary>
/// Énumère les tâches planifiées.
///
/// C'est la plus grande surface de persistance de Windows : une tâche survit au
/// redémarrage, se déclenche sur un horaire, un événement ou une ouverture de session,
/// et n'apparaît dans aucune des clés <c>Run</c> qu'inspecte le collecteur de
/// démarrage automatique.
///
/// Abstrait comme le reste (ADR-001, D5) : sans cela, aucun test ne pourrait porter
/// sur le jugement sans une machine dans l'état voulu.
/// </summary>
public interface IScheduledTaskProvider
{
    ScheduledTaskRead Enumerate();
}
