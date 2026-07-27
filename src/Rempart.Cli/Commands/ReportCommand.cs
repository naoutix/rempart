using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Reports;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Re-renders a report from the JSON a scan produced.
///
/// <para>
/// The JSON is the complete artifact — the HTML and the Markdown summarise it — so
/// getting the other two formats back never requires scanning the machine again. It
/// also runs anywhere: re-rendering reads a file, so an audit captured on a Windows
/// machine can be turned into a report on any machine at all.
/// </para>
/// </summary>
internal static class ReportCommand
{
    public static int Run(string[] args)
    {
        var source = OptionValue(args, "--from");

        if (source is null || !File.Exists(source))
        {
            Console.Error.WriteLine(
                "Indiquer le rapport JSON à rendre : rempart report --from <rapport.json>.");
            return 1;
        }

        ScanResult result;
        try
        {
            result = RempartJson.DeserialiseScanResult(File.ReadAllText(source));
        }
        catch (System.Text.Json.JsonException ex)
        {
            Console.Error.WriteLine($"{source} n'est pas un JSON lisible : {ex.Message}");
            return 1;
        }

        // A capture and a report are both JSON produced by this tool. Deserialising one as
        // the other yields empty fields rather than an error, and would write an empty
        // report that looks like a machine with nothing to report.
        if (string.IsNullOrEmpty(result.StartedAtUtc) || result.Collectors is null)
        {
            Console.Error.WriteLine(
                $"{source} ne ressemble pas à un rapport de scan. « rempart scan --json » en " +
                "produit un ; « rempart capture » produit un instantané, qui se rejoue avec " +
                "« rempart scan --from ».");
            return 1;
        }

        var wanted = OptionValue(args, "--format") switch
        {
            null or "all" => (string[])[ReportBundle.HtmlName, ReportBundle.MarkdownName, ReportBundle.JsonName],
            "html" => [ReportBundle.HtmlName],
            "markdown" or "md" => [ReportBundle.MarkdownName],
            "json" => [ReportBundle.JsonName],
            var other => throw new ArgumentException(
                $"Format inconnu « {other} ». Attendu : html, markdown, json, all."),
        };

        // Here --out is the folder itself, not a root: the caller named a destination for
        // one known report, where "scan" was filing an unknown number of them.
        var directory = OptionValue(args, "--out") ?? ".";
        Directory.CreateDirectory(directory);

        foreach (var file in ReportBundle.Build(result).Where(f => wanted.Contains(f.Name)))
        {
            File.WriteAllText(Path.Combine(directory, file.Name), file.Content);
            Console.WriteLine($"Écrit : {Path.Combine(directory, file.Name)}");
        }

        return 0;
    }
}
