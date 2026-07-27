using Rempart.Core.Providers;
using static Rempart.Cli.CliHost;

namespace Rempart.Cli.Commands;

/// <summary>
/// Verifies that the loaded-driver enumeration answers from the published binary.
///
/// <para>
/// Same reason to exist as <c>diagnose-wmi</c>, one layer up: the enumeration goes
/// through WMI, so it inherits every COM interop risk that command exists for, and adds
/// one of its own. <c>Win32_SystemDriver</c> is decoded property by property, and the
/// collector then <em>filters</em> on two of them — it keeps only rows whose
/// <c>State</c> reads <c>Running</c> and whose <c>PathName</c> is not blank. A VARIANT
/// decode that came back plausible and wrong on either property empties the list without
/// failing anything.
/// </para>
///
/// <para>
/// And an empty list is the worst possible answer here: the driver table is the surface
/// a BYOVD attack lands on, so zero drivers reads as a clean kernel rather than as a
/// failed read. DET-WMI-MUET gave <c>DriverRead</c> a status channel so the scan can say
/// so; this command is what makes CI notice before a user does.
/// </para>
///
/// <para>
/// No Windows machine runs zero kernel drivers, and enumerating them needs no elevation:
/// a failure here indicts the interop, not the environment.
/// </para>
/// </summary>
internal static class DiagnoseDriversCommand
{
    /// <summary>Ignores its arguments, like <see cref="DiagnoseWmiCommand.Run"/>.</summary>
    public static int Run(string[] args)
    {
        _ = args;
        RequireWindows();

        var read = new Rempart.Windows.LiveDriverProvider().Enumerate();

        Console.WriteLine($"pilotes -> {read.Status}, {read.Drivers.Count} pilote(s) chargé(s)");

        if (read.Diagnostic is { } diagnostic)
        {
            Console.WriteLine($"  défaillance : {diagnostic}");
        }

        // The bar stays as low as diagnose-tasks': a CI runner carries fewer drivers than
        // a workstation, but never none.
        if (read.Status != ReadStatus.Found || read.Drivers.Count == 0)
        {
            Console.Error.WriteLine(
                "Aucun pilote chargé rendu. Toute machine allumée en porte : c'est " +
                "l'énumération qui est en cause, pas l'environnement. Un scan dans cet " +
                "état rendrait un noyau d'apparence saine.");
            return 1;
        }

        // Counting drivers proves nothing about being able to judge them. PathName is the
        // only thing the collector hands to the signature check, so a path the filesystem
        // does not resolve turns every driver into « fichier introuvable » — a report full
        // of non-verdicts that reads like a verdict. This is the same File.Exists the
        // signature provider does, asked one step earlier where it is still readable.
        var resolvable = read.Drivers.Count(driver => File.Exists(driver.Path));
        Console.WriteLine($"  dont {resolvable} dont le chemin désigne un fichier lisible");

        if (resolvable == 0)
        {
            Console.Error.WriteLine(
                "Aucun chemin de pilote ne désigne un fichier : l'énumération répond mais " +
                "PathName non. Le scan jugerait chaque pilote « fichier introuvable ».");
            return 1;
        }

        Console.WriteLine($"  exemple : {read.Drivers[0].Name} → {read.Drivers[0].Path}");
        return 0;
    }
}
