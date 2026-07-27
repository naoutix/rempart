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
/// That shape is now three states rather than a list (DET-FICHIERS-MUET), and the three are
/// what these tests separate.
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
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Denied, as expected: the provider must swallow this rather than propagate it.
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
}
