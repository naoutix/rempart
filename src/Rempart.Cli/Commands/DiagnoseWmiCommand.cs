using Rempart.Core.Providers;
using static Rempart.Cli.CliHost;

namespace Rempart.Cli.Commands;

/// <summary>
/// Verifies that WMI actually responds — intended for CI, run against the Native AOT
/// binary.
///
/// Exists because a COM interop bug left WMI inoperative in the published binary
/// with nothing reporting it: checks came back "unverifiable", the scan exited
/// with 0, and the publish job declared it healthy. The tests, for their part, only
/// ran under JIT, where the bug does not show.
///
/// Queries a namespace present on every Windows machine and available without
/// elevation: a failure here indicts the interop, not the environment.
/// </summary>
internal static class DiagnoseWmiCommand
{
    /// <summary>
    /// Takes the arguments it never reads, so that the dispatch table holds one shape of
    /// delegate rather than two — a table of exceptions is a table nobody checks.
    /// </summary>
    public static int Run(string[] args)
    {
        _ = args;
        RequireWindows();

        const string Namespace = @"root\CIMV2";
        const string Class = "Win32_OperatingSystem";
        const string Property = "Caption";

        var read = new Rempart.Windows.Wmi.LiveWmiProvider().Query(Namespace, Class, [Property]);
        var value = read.Instances.Count > 0 ? read.Instances[0].Find(Property) : null;

        Console.WriteLine($"{Namespace}:{Class} -> {read.Status}, {read.Instances.Count} instance(s)");
        if (read.Diagnostic is { } diagnostic)
        {
            Console.WriteLine($"  défaillance : {diagnostic}");
        }

        if (read.Status != ReadStatus.Found || string.IsNullOrWhiteSpace(value))
        {
            Console.Error.WriteLine(
                "WMI ne répond pas. Sur un espace de noms accessible sans élévation, " +
                "c'est l'interop COM qui est en cause, pas l'environnement.");
            return 1;
        }

        Console.WriteLine($"  {Property} = {value}");
        return 0;
    }
}
