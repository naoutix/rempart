namespace Rempart.Core.Providers;

/// <summary>
/// Un point d'écoute réseau : un protocole, une adresse et un port sur lesquels un
/// processus attend des connexions.
///
/// <para>
/// L'adresse de liaison est le fait qui compte. <c>127.0.0.1</c> (ou <c>::1</c>) n'écoute
/// que la machine elle-même — un service local, hors de portée du réseau. <c>0.0.0.0</c>
/// (ou <c>::</c>) écoute toutes les interfaces : le service est joignable depuis
/// l'extérieur. Deux processus sur le même port n'ont pas la même surface d'exposition
/// selon cette seule adresse.
/// </para>
/// </summary>
public sealed record ListeningPort(string Protocol, string LocalAddress, int Port, int Pid)
{
    /// <summary>
    /// Vrai si l'écoute n'est que locale. <c>0.0.0.0</c> et <c>::</c> écoutent toutes les
    /// interfaces ; une adresse de boucle ou une interface nommée n'expose pas au réseau
    /// de la même façon — seule <c>0.0.0.0</c>/<c>::</c> est une exposition générale.
    /// </summary>
    public bool IsLoopbackOnly =>
        LocalAddress.StartsWith("127.", StringComparison.Ordinal)
        || LocalAddress == "::1";

    public bool IsAllInterfaces =>
        LocalAddress is "0.0.0.0" or "::";
}

/// <summary>
/// Énumère les points d'écoute TCP et UDP.
///
/// Abstrait comme le reste (ADR-001, D5) : le jugement — un binaire non signé qui expose
/// un port à toutes les interfaces — se teste sur une liste donnée, sans ouvrir de vrai
/// socket.
/// </summary>
public interface IListeningPortProvider
{
    IReadOnlyList<ListeningPort> Enumerate();
}
