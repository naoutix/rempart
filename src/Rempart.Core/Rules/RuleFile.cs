namespace Rempart.Core.Rules;

/// <summary>
/// What counts as a rule file, held in one place.
///
/// <para>
/// Both spellings of the YAML extension are equally common, and every place that
/// discovers rule files — the resources embedded in the binary, an external directory,
/// the kind a signed dataset is routed to — has to recognise exactly the same set. They
/// did not: a directory holding <c>a.yaml</c> next to <c>b.yml</c> loaded the first and
/// dropped the second without a word, because each site spelled the extension out on
/// its own and the file count was non-zero either way.
/// </para>
///
/// <para>
/// A rule that disappears in silence is the false negative this tool exists to prevent,
/// so the list lives here and a test refuses any other file of the core spelling one out
/// again.
/// </para>
/// </summary>
public static class RuleFile
{
    /// <summary>
    /// The accepted spellings. Comparison is case-insensitive on purpose: the same
    /// directory is read on Windows, where the file system ignores case, and replayed
    /// on Linux in CI, where it does not.
    /// </summary>
    public static readonly IReadOnlyList<string> Extensions = [".yaml", ".yml"];

    /// <summary>
    /// Whether a file name — or a resource name, or a dataset name — designates rules.
    /// </summary>
    public static bool Matches(string name) =>
        Extensions.Any(extension => name.EndsWith(extension, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The spellings as a message names them. An error that lists only half of what is
    /// accepted is how the other half ends up written by mistake.
    /// </summary>
    public static string Expected =>
        string.Join(" ou ", Extensions.Select(extension => $"« {extension} »"));
}
