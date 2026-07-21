namespace Rempart.Core.Providers;

/// <summary>
/// Un processus en cours, réduit à ce qu'un audit doit en savoir.
///
/// La ligne de commande en fait partie : deux processus lancés depuis le même binaire
/// peuvent faire des choses opposées selon leurs arguments, et c'est souvent là que se
/// lit une intention. Le parent aussi — un interpréteur lancé par une suite bureautique
/// n'a pas la même signification que lancé par un terminal.
/// </summary>
public sealed record RunningProcess(
    int Pid,
    int ParentPid,
    string Name,
    string Path,
    string CommandLine);

/// <summary>
/// Énumère les processus en cours d'exécution.
///
/// <para>
/// Abstrait comme le reste (ADR-001, D5) : le jugement — un binaire non signé qui
/// tourne, lancé depuis un emplacement inhabituel — se teste sur une liste donnée, sans
/// une machine dans l'état voulu.
/// </para>
/// </summary>
public interface IProcessProvider
{
    IReadOnlyList<RunningProcess> Enumerate();
}
