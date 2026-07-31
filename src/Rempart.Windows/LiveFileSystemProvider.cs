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
        // Swallowed, but no longer silent (DET-FICHIERS-MUET): the other locations still need
        // scanning, and this one is named instead of coming back as an empty folder.
        //
        // Two catches where there was one. They were merged behind a single filter, and the
        // read they both returned was documented « the listing was refused » — so an ACL and a
        // folder held open by another process arrived at AutorunsCollector as the same state,
        // and it quoted that sentence to answer AuditGap.Refused for both. Elevation opens the
        // first and does nothing for the second.
        catch (UnauthorizedAccessException)
        {
            return DirectoryRead.Refused(
                $"Dossier « {directory} » illisible : accès refusé. Un programme déposé là "
                + "s'exécuterait à l'ouverture de session sans apparaître dans ce rapport.");
        }
        catch (IOException)
        {
            // Not a denial and no longer returned as one. The wording was already honest here
            // — « erreur d'entrée/sortie », never « accès refusé » — which is precisely what
            // made the defect survive three rounds of review: the sentence was right and the
            // state beside it was wrong, and the collector branches on the state.
            //
            // A fixed category rather than ex.Message, which the two catches used to share a
            // helper for: the framework localises that message, so recording it would make a
            // capture taken on a French install differ character for character from the same
            // capture taken on an English one — and the fixture references compare text.
            return DirectoryRead.Failed(
                $"Dossier « {directory} » illisible : erreur d'entrée/sortie. Un programme "
                + "déposé là s'exécuterait à l'ouverture de session sans apparaître dans ce "
                + "rapport.");
        }
    }
}
