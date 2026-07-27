using Rempart.Core.Providers;
using static Rempart.Cli.CliHost;

namespace Rempart.Cli.Commands;

/// <summary>
/// Verifies that the running-process enumeration answers from the published binary.
///
/// <para>
/// The companion of <c>diagnose-drivers</c>, and it fails the same way: the inventory
/// comes from a single <c>Win32_Process</c> query whose rows are then filtered on
/// <c>ExecutablePath</c>, so a decode that returns blank for that property yields an
/// empty inventory rather than an error. DET-WMI-MUET gave <c>ProcessRead</c> a status
/// channel precisely because a scan cannot tell that apart from a quiet machine —
/// except that a machine running zero processes does not exist.
/// </para>
///
/// <para>
/// The strongest thing this command can assert is that the enumeration found
/// <em>itself</em>. It costs nothing, it needs no elevation, and it holds two decodes at
/// once: the process identifier, which <c>LiveProcessProvider</c> turns into <c>0</c>
/// when parsing fails, and the fact that the query really covers this machine rather than
/// returning rows from somewhere plausible.
/// </para>
/// </summary>
internal static class DiagnoseProcessesCommand
{
    /// <summary>Ignores its arguments, like <see cref="DiagnoseWmiCommand.Run"/>.</summary>
    public static int Run(string[] args)
    {
        _ = args;
        RequireWindows();

        var read = new Rempart.Windows.LiveProcessProvider().Enumerate();

        Console.WriteLine($"processus -> {read.Status}, {read.Processes.Count} processus");

        if (read.Diagnostic is { } diagnostic)
        {
            Console.WriteLine($"  défaillance : {diagnostic}");
        }

        if (read.Status != ReadStatus.Found || read.Processes.Count == 0)
        {
            Console.Error.WriteLine(
                "Aucun processus rendu. Aucune machine allumée n'en exécute zéro : c'est " +
                "l'énumération qui est en cause, pas l'environnement. Un scan dans cet " +
                "état rendrait un inventaire vide, indistinguable d'une machine propre.");
            return 1;
        }

        // Stated, never asserted on. A process owned by another user keeps its command
        // line hidden without elevation — that is a permissions gap and a legitimate
        // answer, so failing on it would make this command red on every unelevated run.
        // The number is still worth printing: a sudden zero says the decode broke.
        var described = read.Processes.Count(process => process.CommandLine.Length > 0);
        Console.WriteLine($"  dont {described} avec une ligne de commande lue");

        // The one thing that cannot be a permissions gap: this very process is running,
        // it belongs to the caller, and its path is readable. Absent from the inventory,
        // the enumeration is not enumerating this machine.
        var self = read.Processes.FirstOrDefault(process => process.Pid == Environment.ProcessId);

        if (self is null)
        {
            Console.Error.WriteLine(
                $"Le processus courant (PID {Environment.ProcessId}) est absent de " +
                "l'inventaire : l'énumération répond mais ne décrit pas cette machine, " +
                "ou le décodage de ProcessId rend une valeur plausible et fausse.");
            return 1;
        }

        Console.WriteLine($"  exemple : {self.Pid} {self.Name} → {self.Path}");
        return 0;
    }
}
