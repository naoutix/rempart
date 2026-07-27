namespace Rempart.Tests.Unit;

/// <summary>
/// Reads a file of the working tree by its path relative to the repository root.
///
/// <para>
/// Several guards in this suite hold an invariant that spans two files no compiler relates
/// to one another — a coverage filter and the workflow that asks for it, a workflow and the
/// script that claims to replay it. Each of them needs the same three lines to find the
/// root, and the third copy is where the copies start disagreeing about what the root is.
/// </para>
///
/// <para>
/// <c>CommandSurfaceTests</c> keeps its own locator on purpose and is not folded in here:
/// it finds the root by looking for <c>src/Rempart.Cli</c>, which is the very directory it
/// then enumerates. Locating by the thing under test means that renaming it fails loudly
/// instead of yielding an empty enumeration and a green test.
/// </para>
///
/// <para>
/// <see cref="Path"/> is legitimate in this file: these are real paths on the machine
/// running the tests, not Windows paths captured on one machine and replayed on another —
/// the case <c>Rempart.Core</c> is forbidden from touching.
/// </para>
/// </summary>
internal static class RepositoryFiles
{
    /// <summary>The file's whole text. Throws if it is absent, which is the point.</summary>
    public static string Read(string relativePath) => File.ReadAllText(Resolve(relativePath));

    public static string Resolve(string relativePath) =>
        Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar));

    public static string Root { get; } = Locate();

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".github")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Racine du dépôt introuvable.");
    }
}
