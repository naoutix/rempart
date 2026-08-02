using Rempart.Core.Cli;
using Rempart.Core.Drift;
using Rempart.Core.Json;
using Rempart.Core.Reports;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Reads a folder of reports as a series rather than as a fleet.
///
/// <para>
/// Same folder <c>index</c> reads, other axis: <c>index</c> answers "which machine next",
/// this answers "what has this machine been doing". Reports, never machines — nothing here
/// needs Windows, and a folder assembled by hand from several sticks works as well as the
/// one <c>scan --report</c> writes.
/// </para>
/// </summary>
internal static class DriftCommand
{
    public static int Run(string[] args)
    {
        var positional = Positional(args, CommandSurface.ValueTaking("drift"));
        var root = positional.Count > 0
            ? positional[0]
            : Path.Combine(AppContext.BaseDirectory, "reports");

        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine(
                $"Dossier introuvable : {root}. « rempart scan --report » y dépose des rapports.");
            return 1;
        }

        var points = new List<DriftPoint>();
        var unreadable = 0;
        long bytesOnDisk = 0;

        foreach (var path in Directory
                     .EnumerateFiles(root, ReportBundle.JsonName, SearchOption.AllDirectories)
                     .OrderBy(p => p, StringComparer.Ordinal))
        {
            try
            {
                bytesOnDisk += new FileInfo(path).Length;
                var point = DriftPoint.From(
                    RempartJson.DeserialiseScanResult(File.ReadAllText(path)));

                if (point is null)
                {
                    // Not a report a series can place in time. Counted and named rather than
                    // skipped: a folder where half the files failed to parse must not read
                    // like a folder with half as many scans.
                    unreadable++;
                    Console.Error.WriteLine($"Ignoré, sans date lisible : {path}");
                    continue;
                }

                points.Add(point);
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException)
            {
                unreadable++;
                Console.Error.WriteLine($"Ignoré, illisible : {path} ({ex.Message})");
            }
        }

        var reports = DriftSeries.Build(points, DateTimeOffset.UtcNow);
        var outPath = OptionValue(args, "--out") ?? Path.Combine(root, DriftPage.FileName);

        try
        {
            File.WriteAllText(outPath, DriftPage.Render(reports));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Page non écrite dans {outPath} : {ex.Message}");
            return 1;
        }

        Console.Write(ConsoleReport.Drift(reports, outPath, unreadable, bytesOnDisk));

        return (int)ExitCodes.ForDrift(reports);
    }
}
