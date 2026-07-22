namespace Rempart.Core.Providers;

/// <summary>
/// Lit le fichier <c>hosts</c>, ligne à ligne et brut.
///
/// <para>
/// Le fichier <c>hosts</c> court-circuite le DNS : une correspondance qui y figure est
/// consultée avant tout serveur de noms. C'est un levier des deux bords — un bloqueur de
/// publicités y neutralise des domaines vers une adresse nulle, un maliciel y redirige la
/// mise à jour de Windows vers une adresse qu'il contrôle. L'analyse se fait dans le cœur ;
/// le provider ne fait que rendre les lignes, pour que le jugement se teste sans fichier.
/// </para>
/// </summary>
public interface IHostsFileProvider
{
    IReadOnlyList<string> ReadLines();
}
