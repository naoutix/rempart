using Rempart.Windows;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// The directory listing the autoruns collector walks.
///
/// <para>
/// The smallest provider in the layer — twelve lines around <c>Directory.GetFiles</c> — and
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
        var listed = files.ListFiles(directory);

        Assert.NotEmpty(listed);

        // Full paths, not names. This is the property the autoruns collector depends on and
        // the one a rewrite would most plausibly break, since GetFiles returns names when
        // handed a relative directory.
        var relative = listed.Where(path => !Path.IsPathRooted(path)).Take(3).ToList();
        Assert.True(relative.Count == 0,
            $"Chemin(s) non absolu(s) rendus pour {directory} : {string.Join(", ", relative)}. "
            + "La vérification de signature ne les ouvrirait pas, et chaque élément de "
            + "démarrage sortirait « fichier introuvable » — ce qui se lit comme un verdict.");

        // And they designate files that exist: a listing nobody can open is a listing of
        // nothing, whatever its length.
        Assert.Contains(listed, path =>
            path.EndsWith(@"\kernel32.dll", StringComparison.OrdinalIgnoreCase));
        Assert.All(listed.Take(20), path => Assert.True(File.Exists(path), path));
    }

    /// <summary>
    /// A folder that is not there is not an error: the scan walks a fixed list of startup
    /// locations and most machines have several of them missing.
    /// </summary>
    [Fact]
    public void A_directory_that_does_not_exist_yields_nothing_rather_than_an_exception() =>
        Assert.Empty(files.ListFiles(@"C:\Rempart-ce-dossier-n-existe-pas-42"));

    /// <summary>
    /// The documented degradation, and the silence it leaves behind — pinned rather than
    /// praised.
    ///
    /// <para>
    /// A refused directory comes back as an empty list, exactly like an empty one. On this
    /// surface that is the DET-*-MUET shape phase 2 spent itself removing elsewhere: a
    /// startup folder the scan could not read is reported as a startup folder with nothing in
    /// it, and « aucun autorun » reads like good news. It is left as it is here because
    /// changing it means giving <c>IFileSystemProvider</c> a status channel, which changes
    /// what a snapshot stores — a decision of its own, not a side effect of a test. What this
    /// test buys is that the behaviour is a decision somebody took and can be found again.
    /// </para>
    ///
    /// <para>
    /// The directory is confronted with the raw BCL call rather than assumed to be denied: on
    /// a machine where it is readable — an agent running as SYSTEM — the check says so and
    /// stands down, instead of failing for a reason that has nothing to do with the provider.
    /// </para>
    /// </summary>
    [Fact]
    public void A_directory_the_scan_may_not_read_yields_nothing_and_says_nothing()
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

        Assert.Empty(files.ListFiles(Denied));
    }
}
