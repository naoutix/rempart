using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Lists a directory, and says which of the four states the attempt ended in.
/// </summary>
/// <param name="enumerate">
/// How the files are read, <c>Directory.GetFiles</c> in production.
///
/// <para>
/// A parameter for one reason, and it is the reason #173 stayed open through three rounds:
/// the mapping below — <c>UnauthorizedAccessException</c> to a denial, <c>IOException</c> to a
/// failure — is the whole contract this file carries, and nothing could reach it. A real
/// folder can be staged as <em>refused</em> (<c>System Volume Information</c>) but not as
/// <em>failing</em>: an <c>IOException</c> out of <c>Directory.GetFiles</c> wants a volume
/// pulled mid-listing. So the branch that names the defect was the one branch no test could
/// enter, and merging the two <c>catch</c> blocks back together left both suites green.
/// <c>LiveHostsFileProvider</c> has taken its system root since REV-12 for exactly this, which
/// is why the same defect on that channel had a guard and this one did not.
/// </para>
/// </param>
public sealed class LiveFileSystemProvider(Func<string, string[]>? enumerate = null)
    : IFileSystemProvider
{
    private readonly Func<string, string[]> files = enumerate ?? Directory.GetFiles;

    public DirectoryRead ListFiles(string directory)
    {
        try
        {
            // Directory.Exists is left out of the seam deliberately: it does not throw, it
            // answers false, so it decides Absent and never which catch is taken.
            return Directory.Exists(directory)
                ? DirectoryRead.Found(files(directory))
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
