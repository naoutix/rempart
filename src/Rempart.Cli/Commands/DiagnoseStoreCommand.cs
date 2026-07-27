using Rempart.Core.Providers;
using Rempart.Core.Reports;
using Rempart.Windows;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Checks that the servicing stack answers, and shows what it answered.
///
/// <para>
/// Same reason to exist as <c>diagnose-wmi</c> and <c>diagnose-tasks</c>, applied to a
/// different fragility: here the risk is not COM interop but a text format. The labels
/// this parser looks for come from a tool whose output can change with a Windows update,
/// and a parser that stopped recognising them would report a machine with nothing to
/// reclaim rather than an error.
/// </para>
///
/// <para>
/// <c>--raw</c> prints the output verbatim, which is what confronting the parser with a
/// real elevated run requires.
/// </para>
/// </summary>
internal static class DiagnoseStoreCommand
{
    public static int Run(string[] args)
    {
        RequireWindows();

        var diagnosis = new LiveComponentStoreProvider().Diagnose();
        var read = diagnosis.Read;

        Console.WriteLine($"magasin de composants -> {read.Status} (code {diagnosis.ExitCode})");

        if (HasFlag(args, "--raw"))
        {
            Console.WriteLine();
            Console.WriteLine(diagnosis.RawOutput);
            Console.WriteLine();
        }

        if (read.Diagnostic is { } diagnostic)
        {
            Console.WriteLine($"  défaillance : {diagnostic}");
        }

        if (read.Status != ReadStatus.Found)
        {
            Console.Error.WriteLine(
                read.Status == ReadStatus.AccessDenied
                    ? "Relancer depuis une console administrateur."
                    : "L'analyse n'a rien rendu d'exploitable. « --raw » montre la sortie brute, "
                      + "à confronter aux libellés attendus par le lecteur.");
            return 1;
        }

        foreach (var (label, value) in new (string, string?)[]
                 {
                     ("taille réelle", Size(read.ActualSizeBytes)),
                     ("partagé avec Windows", Size(read.SharedWithWindowsBytes)),
                     ("sauvegardes et fonctionnalités désactivées", Size(read.BackupsAndDisabledFeaturesBytes)),
                     ("cache et données temporaires", Size(read.CacheAndTemporaryBytes)),
                     ("récupérable", Size(read.ReclaimableBytes)),
                     ("paquets récupérables", read.ReclaimablePackages?.ToString()),
                     ("nettoyage recommandé", read.CleanupRecommended?.ToString()),
                     ("dernier nettoyage", read.LastCleanup),
                 })
        {
            Console.WriteLine($"  {label,-42} {value ?? "non indiqué"}");
        }

        // Every layer null while the anchor parsed means the format moved under us.
        if (read.ReclaimableBytes is null)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine(
                "Taille lue, mais aucune couche détaillée : les libellés attendus ont changé. " +
                "Relancer avec « --raw » et corriger ComponentStoreParser.");
            return 1;
        }

        return 0;
    }

    private static string? Size(long? bytes) => bytes is { } value ? ReportLabels.Bytes(value) : null;
}
