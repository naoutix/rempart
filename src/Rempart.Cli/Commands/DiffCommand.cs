using Rempart.Core.Cli;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Reports;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Compares two scans.
///
/// <para>
/// Reads reports, never machines: the comparison needs neither of them present, and it
/// runs anywhere. One argument compares against the stick's baseline — the reference
/// posture a fleet is held to; two arguments compare whatever is handed over.
/// </para>
/// </summary>
internal static class DiffCommand
{
    public static int Run(string[] args)
    {
        var positional = Positional(args, CommandSurface.ValueTaking("diff"));

        var (beforePath, afterPath) = positional.Count switch
        {
            >= 2 => (positional[0], positional[1]),
            1 => (OptionValue(args, "--baseline") ?? BaselinePath(), positional[0]),
            _ => (null, null),
        };

        if (beforePath is null || afterPath is null)
        {
            Console.Error.WriteLine(
                "Indiquer deux rapports : rempart diff <avant.json> <après.json>. " +
                "Avec un seul, la comparaison se fait contre la baseline de la clé " +
                $"({BaselinePath()}).");
            return 1;
        }

        if (!File.Exists(beforePath))
        {
            Console.Error.WriteLine(
                positional.Count >= 2
                    ? $"Rapport introuvable : {beforePath}"
                    : $"Aucune baseline dans {beforePath}. En poser une : copier le rapport JSON " +
                      $"d'une machine de référence sous ce nom, ou indiquer --baseline <fichier>.");
            return 1;
        }

        if (!File.Exists(afterPath))
        {
            Console.Error.WriteLine($"Rapport introuvable : {afterPath}");
            return 1;
        }

        ScanResult before, after;
        try
        {
            before = RempartJson.DeserialiseScanResult(File.ReadAllText(beforePath));
            after = RempartJson.DeserialiseScanResult(File.ReadAllText(afterPath));
        }
        catch (System.Text.Json.JsonException ex)
        {
            Console.Error.WriteLine($"Rapport illisible : {ex.Message}");
            return 1;
        }

        if (string.IsNullOrEmpty(before.StartedAtUtc) || string.IsNullOrEmpty(after.StartedAtUtc))
        {
            Console.Error.WriteLine(
                "L'un des fichiers n'est pas un rapport de scan. « rempart scan --json » en produit un.");
            return 1;
        }

        var diff = ScanDiff.Compare(before, after);
        Console.Write(ConsoleReport.Diff(diff));

        if (HasFlag(args, "--report"))
        {
            // OptionalValue, like "scan" reads the same option — not OptionValue, which
            // takes whatever follows. On "rempart diff --report --baseline b.json a.json"
            // it returned "--baseline", and the comparison was filed into a folder of that
            // name while Positional, applying the no-dash rule, had already decided
            // --report carried no value. Two readers, one spelling, two answers
            // (DET-ARITE-REPORT). They now agree by construction: both refuse a value that
            // starts with a dash, so the bare form falls back to the current folder.
            var directory = OptionalValue(args, "--report") ?? ".";

            try
            {
                Directory.CreateDirectory(directory);

                foreach (var file in DiffReport.Build(diff))
                {
                    File.WriteAllText(Path.Combine(directory, file.Name), file.Content);
                    Console.WriteLine($"Écrit : {Path.Combine(directory, file.Name)}");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Comparaison non écrite dans {directory} : {ex.Message}");
                return 1;
            }
        }

        // A regression is what the caller most likely wants to act on, so it is detectable
        // without re-reading the output.
        return (int)ExitCodes.ForDiff(diff);
    }
}
