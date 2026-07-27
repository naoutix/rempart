using Rempart.Core.Cli;
using Rempart.Core.Json;
using Rempart.Core.Reports;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Builds the fleet page from a folder of reports.
///
/// Reads every <c>rapport.json</c> it finds, however the folders are arranged: the stick
/// layout produces one directory per scan, but a folder assembled by hand from several
/// sticks works just as well.
/// </summary>
internal static class IndexCommand
{
    public static int Run(string[] args)
    {
        var positional = Positional(args, CommandSurface.ValueTaking("index"));
        var root = positional.Count > 0
            ? positional[0]
            : Path.Combine(AppContext.BaseDirectory, "reports");

        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine(
                $"Dossier introuvable : {root}. « rempart scan --report » y dépose des rapports.");
            return 1;
        }

        var entries = new List<FleetEntry>();
        var unreadable = 0;

        foreach (var path in Directory
                     .EnumerateFiles(root, ReportBundle.JsonName, SearchOption.AllDirectories)
                     .OrderBy(p => p, StringComparer.Ordinal))
        {
            try
            {
                var result = RempartJson.DeserialiseScanResult(File.ReadAllText(path));

                if (string.IsNullOrEmpty(result.StartedAtUtc))
                {
                    unreadable++;
                    continue;
                }

                entries.Add(FleetEntry.From(result, Path.GetRelativePath(root, path)));
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException)
            {
                // One unreadable report must not cost the whole page; it is counted and
                // reported, never skipped in silence.
                unreadable++;
                Console.Error.WriteLine($"Ignoré, illisible : {path} ({ex.Message})");
            }
        }

        var outPath = OptionValue(args, "--out") ?? Path.Combine(root, FleetIndex.FileName);
        File.WriteAllText(outPath, FleetIndex.Render(entries));

        Console.Write(ConsoleReport.Fleet(entries, outPath, unreadable));

        return entries.Count > 0 ? 0 : 1;
    }
}
