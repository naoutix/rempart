using Rempart.Core.Cli;
using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Reports;
using Rempart.Core.Survey;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// One key, across every machine that has been captured.
///
/// <para>
/// Reads the folder <c>index</c> and <c>drift</c> read, along a third axis: they answer
/// "which machine next" and "what has this machine been doing", this one answers "does this
/// value depend on the Windows build". That is the question <c>DET-WINDEFAULT</c> asks of
/// some sixty defaults validated on a single machine, and the one the deferred TLS and IPv6
/// rules are waiting on.
/// </para>
/// </summary>
internal static class SurveyCommand
{
    public static int Run(string[] args)
    {
        var positional = Positional(args, CommandSurface.ValueTaking("survey"));

        if (positional.Count == 0)
        {
            Console.Error.WriteLine(
                "Indiquer ce qu'il faut relever : rempart survey <champ|règle> [dossier]. "
                + "Par exemple « tls.1_2.client.enabled » ou « WIN-LEG-003 ».");
            return 1;
        }

        var name = positional[0];
        var root = positional.Count > 1
            ? positional[1]
            : Path.Combine(AppContext.BaseDirectory, "reports");

        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine(
                $"Dossier introuvable : {root}. « rempart scan --report » y dépose des rapports.");
            return 1;
        }

        var reports = new List<ScanResult>();
        var unreadable = 0;

        foreach (var path in Directory
                     .EnumerateFiles(root, ReportBundle.JsonName, SearchOption.AllDirectories)
                     .OrderBy(p => p, StringComparer.Ordinal))
        {
            try
            {
                var report = RempartJson.DeserialiseScanResult(File.ReadAllText(path));

                if (string.IsNullOrEmpty(report.StartedAtUtc))
                {
                    unreadable++;
                    continue;
                }

                reports.Add(report);
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException)
            {
                unreadable++;
                Console.Error.WriteLine($"Ignoré, illisible : {path} ({ex.Message})");
            }
        }

        if (reports.Count == 0)
        {
            Console.Error.WriteLine(
                $"Aucun rapport lisible dans {root}"
                + (unreadable > 0 ? $" ({unreadable} illisible(s))." : "."));
            return 1;
        }

        if (unreadable > 0)
        {
            Console.Error.WriteLine($"{unreadable} rapport(s) illisible(s), ignorés.");
        }

        Console.Write(ConsoleReport.Survey(FieldSurvey.Of(name, reports), root));

        // Nothing here is a verdict about a machine: the command answers a question the
        // maintainer asked, and disagreement between builds is the interesting answer rather
        // than a failure. Exiting non-zero on it would make a discovery look like a fault.
        return 0;
    }
}
