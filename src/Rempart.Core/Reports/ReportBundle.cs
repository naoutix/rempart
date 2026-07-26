using System.Text;
using Rempart.Core.Engine;
using Rempart.Core.Json;

namespace Rempart.Core.Reports;

/// <summary>One produced file: its name, and its whole content.</summary>
public sealed record ReportFile(string Name, string Content);

/// <summary>
/// The three files a scan leaves behind, and the folder that holds them.
///
/// <para>
/// Three formats because they answer to three readers, not out of completeness. The
/// HTML is what gets opened and looked at; the Markdown is what gets pasted into a
/// ticket; the JSON is the only complete one — it keeps every benign finding, which
/// the other two summarise — and it is what <c>rempart report</c> re-renders from, and
/// what <c>diff</c> (M7) will compare.
/// </para>
///
/// <para>
/// Building returns content rather than writing it. Rendering stays a pure function of
/// the scan, testable without a filesystem, and the caller decides where bytes land —
/// which matters on a read-only USB stick, where that decision has to be revisited.
/// </para>
/// </summary>
public static class ReportBundle
{
    public const string HtmlName = "rapport.html";
    public const string MarkdownName = "rapport.md";
    public const string JsonName = "rapport.json";

    /// <summary>The stick's report folder: <c>&lt;hostname&gt;-&lt;date&gt;</c>.</summary>
    public static string FolderName(ScanResult result) =>
        $"{Sanitise(ReportView.From(result).MachineName)}-{ReportView.DateOf(result.StartedAtUtc)}";

    public static IReadOnlyList<ReportFile> Build(ScanResult result) =>
    [
        new ReportFile(HtmlName, HtmlReport.Render(result)),
        new ReportFile(MarkdownName, MarkdownReport.Render(result)),
        new ReportFile(JsonName, RempartJson.Serialise(result)),
    ];

    /// <summary>
    /// Turns a machine name into a folder name.
    ///
    /// The name is not always a hostname: replaying an anonymised capture yields
    /// something like <c>anon:3f2a…</c>, and a colon is not a legal path component on
    /// Windows — the write would fail with a message about the path rather than about
    /// the anonymisation. Anything outside letters, digits, dash and underscore
    /// therefore becomes a dash, consecutive dashes collapse, and the result is capped:
    /// the folder sits inside an already long path on a USB stick.
    /// </summary>
    internal static string Sanitise(string machineName)
    {
        var name = new StringBuilder(machineName.Length);

        foreach (var character in machineName)
        {
            if (char.IsAsciiLetterOrDigit(character) || character is '-' or '_')
            {
                name.Append(character);
            }
            else if (name.Length > 0 && name[^1] != '-')
            {
                name.Append('-');
            }
        }

        while (name.Length > 0 && name[^1] == '-')
        {
            name.Length--;
        }

        if (name.Length > 48)
        {
            name.Length = 48;
        }

        // Accented or non-Latin hostnames can reduce to nothing. A folder named after
        // the date alone would still be usable, but "machine" says why it has no name.
        return name.Length == 0 ? "machine" : name.ToString();
    }
}
