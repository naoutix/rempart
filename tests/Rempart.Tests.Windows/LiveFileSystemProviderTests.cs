using Rempart.Core.Providers;
using Rempart.Windows;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// The directory listing the autoruns collector walks.
///
/// <para>
/// The smallest provider in the layer — a dozen lines around <c>Directory.GetFiles</c> — and
/// the one whose contract matters most to a collector that judges what it finds. It feeds the
/// startup folders to the signature check, so what comes back has to be something the
/// signature check can open: full paths, not bare names. A listing of names would make every
/// startup item come back « fichier introuvable », which reads as a verdict and is not one.
/// </para>
///
/// <para>
/// No <c>diagnose</c> command and no descent into Core, deliberately. There is no judgement
/// here to move down — no parsing, no decision, nothing a fake could exercise that the BCL
/// does not already define — and nothing that could behave differently under Native AOT:
/// <c>Directory.GetFiles</c> is managed code with no interop and no reflection. What is worth
/// pinning is the <em>shape of what it returns</em>, and that only a real filesystem can say.
/// That shape is four states rather than a list (DET-FICHIERS-MUET, then #173), and the four
/// are what these tests separate.
/// </para>
///
/// <para>
/// Three of the four are staged against the real filesystem. The fourth cannot be: an
/// <c>IOException</c> out of <c>Directory.GetFiles</c> wants a volume pulled mid-listing, so
/// the last test drives the provider's listing seam instead. What it asserts is not the
/// filesystem's behaviour but this file's own — which exception becomes which state — and that
/// is precisely the sentence <c>IFileSystemProvider</c> documents.
/// </para>
/// </summary>
public sealed class LiveFileSystemProviderTests(ITestOutputHelper output)
{
    private readonly LiveFileSystemProvider files = new();

    /// <summary>
    /// Refuses to be silent. <c>System32</c> holds thousands of files on every Windows
    /// installation and needs no privilege to list: an empty answer here can only be a
    /// failure to look.
    /// </summary>
    [Fact]
    public void A_real_directory_yields_paths_that_open()
    {
        var directory = Environment.SystemDirectory;
        var read = files.ListFiles(directory);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.NotEmpty(read.Files);

        // Full paths, not names. This is the property the autoruns collector depends on and
        // the one a rewrite would most plausibly break, since GetFiles returns names when
        // handed a relative directory.
        var relative = read.Files.Where(path => !Path.IsPathRooted(path)).Take(3).ToList();
        Assert.True(relative.Count == 0,
            $"Chemin(s) non absolu(s) rendus pour {directory} : {string.Join(", ", relative)}. "
            + "La vérification de signature ne les ouvrirait pas, et chaque élément de "
            + "démarrage sortirait « fichier introuvable » — ce qui se lit comme un verdict.");

        // And they designate files that exist: a listing nobody can open is a listing of
        // nothing, whatever its length.
        Assert.Contains(read.Files, path =>
            path.EndsWith(@"\kernel32.dll", StringComparison.OrdinalIgnoreCase));
        Assert.All(read.Files.Take(20), path => Assert.True(File.Exists(path), path));
    }

    /// <summary>
    /// A folder that is not there is not an error: the scan walks a fixed list of startup
    /// locations and most machines have several of them missing.
    ///
    /// <para>
    /// <c>NotFound</c> and not <c>Found</c> with an empty list, and the distinction is the
    /// whole reason this state exists: « j'ai listé ce dossier, il était vide » is a claim,
    /// and about a folder that is not on disk the scan never made it. It stays silent all the
    /// same — the collector reports refusals, not absences.
    /// </para>
    /// </summary>
    [Fact]
    public void A_directory_that_does_not_exist_is_absent_rather_than_empty()
    {
        var read = files.ListFiles(@"C:\Rempart-ce-dossier-n-existe-pas-42");

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Empty(read.Files);
    }

    /// <summary>
    /// The silence this provider used to leave behind, now removed — DET-FICHIERS-MUET, the
    /// fifth occurrence of the DET-*-MUET shape and the last one phase 2 had left open.
    ///
    /// <para>
    /// A refused directory used to come back as an empty list, exactly like an empty one, so
    /// a startup folder the scan could not read was reported as a startup folder with nothing
    /// in it and « aucun autorun » read like good news. The previous version of this test was
    /// named <c>A_directory_the_scan_may_not_read_yields_nothing_and_says_nothing</c> and
    /// froze that behaviour on purpose, on the grounds that fixing it changed what a snapshot
    /// stores. It now does: the status sits beside the listing, and this test asserts the
    /// opposite of what its predecessor did.
    /// </para>
    ///
    /// <para>
    /// The directory is confronted with the raw BCL call rather than assumed to be denied: on
    /// a machine where it is readable — an agent running as SYSTEM — the check says so and
    /// stands down, instead of failing for a reason that has nothing to do with the provider.
    /// </para>
    /// </summary>
    [Fact]
    public void A_directory_the_scan_may_not_read_says_so_instead_of_looking_empty()
    {
        const string Denied = @"C:\System Volume Information";

        if (!Directory.Exists(Denied))
        {
            output.WriteLine($"{Denied} absent : contrôle non exécuté.");
            return;
        }

        try
        {
            Directory.GetFiles(Denied);
            output.WriteLine(
                $"{Denied} est lisible par ce processus (agent SYSTEM ?) : il ne peut pas "
                + "servir de dossier refusé. Contrôle non exécuté.");
            return;
        }
        catch (UnauthorizedAccessException)
        {
            // Denied, as expected: the provider must swallow this rather than propagate it.
        }
        catch (IOException ex)
        {
            // Not a denial, so not this test's subject — and since #173 not this test's
            // answer either. The filter used to take both exceptions because both produced
            // AccessDenied; now an IOException would satisfy the precondition and fail the
            // assertion below over a machine state that has nothing to do with the provider.
            output.WriteLine(
                $"{Denied} échoue sans être refusé ({ex.GetType().Name}) : il ne peut pas "
                + "servir de dossier refusé. Contrôle non exécuté.");
            return;
        }

        var read = files.ListFiles(Denied);

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Empty(read.Files);

        // The diagnostic names the folder, because the collector walks several of them and
        // « accès refusé » without a path says nothing about which surface went unseen.
        Assert.NotNull(read.Diagnostic);
        Assert.Contains(Denied, read.Diagnostic, StringComparison.Ordinal);

        // And it is the category of the failure, not the BCL's own localised sentence: that
        // string would differ between a French and an English install and land, character
        // for character, inside a capture.
        Assert.Contains("accès refusé", read.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The pair that ties the <c>catch</c> blocks to the sentence <c>IFileSystemProvider</c>
    /// documents, which is the whole of #173 and the one thing the fix for it left unguarded.
    ///
    /// <para>
    /// The defect was a single <c>catch (Exception ex) when (ex is UnauthorizedAccessException
    /// or IOException)</c> behind a factory the interface called « the listing was refused »,
    /// so <c>AutorunsCollector</c> sent the reader to elevate over a folder held open by
    /// another process. Splitting the <c>catch</c> made the two states <em>expressible</em>;
    /// only this pair makes them <em>true</em> — merge the blocks back and the failure half
    /// goes red here, which is what nothing did before.
    /// </para>
    ///
    /// <para>
    /// Both halves, because only the pair is a claim: asserting the failure alone is satisfied
    /// by a provider that answers <c>Failed</c> to everything, and that provider would report
    /// « rien à faire » about the commonest gap this tool has. The directory is real and
    /// exists — the seam replaces the listing, not the existence check, so the read reaches
    /// the <c>catch</c> the same way a live one does.
    /// </para>
    /// </summary>
    [Fact]
    public void A_denied_listing_and_a_failed_listing_do_not_arrive_as_the_same_state()
    {
        var directory = Environment.SystemDirectory;

        var denied = new LiveFileSystemProvider(
            _ => throw new UnauthorizedAccessException()).ListFiles(directory);

        Assert.Equal(ReadStatus.AccessDenied, denied.Status);
        Assert.Empty(denied.Files);
        Assert.NotNull(denied.Diagnostic);
        Assert.Contains("accès refusé", denied.Diagnostic, StringComparison.Ordinal);

        var failed = new LiveFileSystemProvider(
            _ => throw new IOException("volume retiré")).ListFiles(directory);

        Assert.Equal(ReadStatus.Failed, failed.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, failed.Status);
        Assert.Empty(failed.Files);

        // Named, not silent: the collector prints this, and a failure with nothing to say
        // costs the report the folder as surely as an empty listing did.
        Assert.NotNull(failed.Diagnostic);
        Assert.Contains(directory, failed.Diagnostic, StringComparison.Ordinal);

        // And it says what happened rather than borrowing the other branch's word — the
        // invariant CONTRIBUTING records, and the sentence the state now agrees with.
        Assert.DoesNotContain("accès refusé", failed.Diagnostic, StringComparison.Ordinal);

        // The BCL's own message stays out of both: it is localised, and a diagnostic reaches
        // a capture whose references are compared character for character.
        Assert.DoesNotContain("volume retiré", failed.Diagnostic, StringComparison.Ordinal);
    }
}
