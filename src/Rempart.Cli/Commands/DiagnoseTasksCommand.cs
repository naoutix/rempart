using Rempart.Core.Providers;
using static Rempart.Cli.CliHost;

namespace Rempart.Cli.Commands;

/// <summary>
/// Verifies that the Task Scheduler responds from the published binary.
///
/// Same reason to exist as <c>diagnose-wmi</c>, and exactly the same risk: the
/// scheduler's COM interop is generated at compile time, its interfaces derive
/// from <c>IDispatch</c>, and an offset of a single vtable slot is invisible
/// under JIT as at compile time.
///
/// A scan that found no tasks would produce a healthy-looking report. That is
/// precisely what happened with WMI for two batches, and the reason this command
/// exists before the problem arises.
///
/// Every Windows machine carries dozens of tasks; basic enumeration does not
/// require elevation. A failure here indicts the interop, not the environment.
/// </summary>
internal static class DiagnoseTasksCommand
{
    /// <summary>Ignores its arguments, like <see cref="DiagnoseWmiCommand.Run"/>.</summary>
    public static int Run(string[] args)
    {
        _ = args;
        RequireWindows();

        var read = new Rempart.Windows.Tasks.LiveScheduledTaskProvider().Enumerate();

        Console.WriteLine($"planificateur -> {read.Status}, {read.Tasks.Count} tâche(s)");

        if (read.Diagnostic is { } diagnostic)
        {
            Console.WriteLine($"  défaillance : {diagnostic}");
        }

        foreach (var gap in read.Gaps ?? [])
        {
            Console.WriteLine($"  dossier incomplet : {gap.Folder} — {gap.Reason}");
        }

        // A Windows with no tasks at all does not exist: zero indicts the enumeration, not
        // the machine. The bar stays low — a CI runner carries fewer than a real machine.
        //
        // The count alone, and no longer the status beside it. A walk refused in one folder
        // now reports AccessDenied while answering with everything else, which proves the
        // interop works rather than that it is broken; failing on it would blame the vtables
        // for an ACL, on the one command whose whole job is to tell those two apart.
        if (read.Tasks.Count == 0)
        {
            Console.Error.WriteLine(
                "Le planificateur ne rend aucune tâche. Toute installation de Windows en " +
                "porte : c'est l'interop COM qui est en cause, pas l'environnement.");
            return 1;
        }

        // The XML definition is read by a call separate from the enumeration. Counting
        // tasks therefore proves nothing about being able to read them.
        var withAction = read.Tasks.Count(t => t.Actions.Count > 0);
        Console.WriteLine($"  dont {withAction} avec au moins une action lue");

        if (withAction == 0)
        {
            Console.Error.WriteLine(
                "Aucune définition lisible : l'énumération répond mais get_Xml non. " +
                "Un scan rendrait des tâches sans jamais juger ce qu'elles lancent.");
            return 1;
        }

        Console.WriteLine($"  exemple : {read.Tasks[0].Path}");
        return 0;
    }
}
