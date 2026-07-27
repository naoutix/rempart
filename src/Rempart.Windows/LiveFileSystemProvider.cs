using Rempart.Core.Providers;

namespace Rempart.Windows;

public sealed class LiveFileSystemProvider : IFileSystemProvider
{
    public DirectoryRead ListFiles(string directory)
    {
        try
        {
            return Directory.Exists(directory)
                ? DirectoryRead.Found(Directory.GetFiles(directory))
                : DirectoryRead.Absent;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Swallowed, but no longer silent (DET-FICHIERS-MUET): the other locations still
            // need scanning, and this one is named instead of coming back as an empty folder.
            return DirectoryRead.Failed(
                $"Dossier « {directory} » illisible : {Reason(ex)}. Un programme déposé là "
                + "s'exécuterait à l'ouverture de session sans apparaître dans ce rapport.");
        }
    }

    /// <summary>
    /// The category of the failure, not the exception's own message.
    ///
    /// <c>ex.Message</c> is localised by the running system, so recording it would make a
    /// capture taken on a French install differ, character for character, from the same
    /// capture taken on an English one — and the fixture references compare text.
    /// </summary>
    private static string Reason(Exception ex) =>
        ex is UnauthorizedAccessException ? "accès refusé" : "erreur d'entrée/sortie";
}
