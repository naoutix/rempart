using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Lit le fichier <c>hosts</c> sur le disque.
///
/// <para>
/// Son emplacement est fixe — <c>%SystemRoot%\System32\drivers\etc\hosts</c>. Un fichier
/// absent ou illisible rend une liste vide plutôt qu'une erreur : le scan des autres
/// surfaces doit se poursuivre, et « pas de fichier hosts » se juge comme « aucune
/// correspondance », pas comme un échec.
/// </para>
/// </summary>
public sealed class LiveHostsFileProvider : IHostsFileProvider
{
    public IReadOnlyList<string> ReadLines()
    {
        var root = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var path = $@"{root}\System32\drivers\etc\hosts";

        try
        {
            return File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
