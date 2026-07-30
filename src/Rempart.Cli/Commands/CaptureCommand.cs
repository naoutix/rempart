using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Windows;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Records the machine's raw state as a snapshot a test can replay — the producing half
/// of the capture → snapshot → replay path.
/// </summary>
internal static class CaptureCommand
{
    public static int Run(string[] args)
    {
        RequireWindows();

        var raw = HasFlag(args, "--raw");
        var snapshot = new MachineSnapshot { CapturedAtUtc = UtcNow() };

        // The live set, wrapped one provider at a time so the scan below writes down
        // everything it reads. Both halves are single lists now — LiveProviders.All in the
        // Windows layer, SnapshotProviders.Recording in Core — and both carry a guard, which
        // this file could not: Rempart.Cli is not compiled by the Linux job, so a twenty-
        // line wiring written here was watched by nobody.
        var providers = SnapshotProviders.Recording(LiveProviders.All(), snapshot);

        // The full engine, rules included: a fixture must be able to replay everything a
        // scan does, otherwise it would only test half the path. The update store is
        // resolved here too, so a capture prefetches the keys of rules added by an update
        // and stays replayable.
        //
        // Its blocklist and its catalog go along with its rules. The snapshot is the same
        // either way — a capture records reads, and neither list changes what is read, only
        // how what came back is judged — but the engine now demands them, and a command that
        // resolved the store and then kept one of its three lists would read as an oversight
        // rather than a decision.
        var resolution = ResolveLiveCatalog(args);
        var engine = new ScanEngine(CollectorsFor(args), resolution.Rules);
        engine.Run(providers, ToolVersion(), snapshot.CapturedAtUtc,
            ScanEngine.DefaultFindingCollectors(resolution.Blocklist, resolution.Catalog));

        // Then every key the rules could read in another context, so the snapshot stays
        // replayable elsewhere than on the machine that produced it.
        engine.Prefetch(providers);

        // Anonymised by default: fixtures end up under version control.
        if (!raw)
        {
            Anonymiser.Apply(snapshot);
        }

        var suffix = raw ? "raw" : "anon";
        var path = OptionValue(args, "--out")
            ?? $"rempart-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{suffix}.capture.json";

        File.WriteAllText(path, RempartJson.Serialise(snapshot));

        Console.WriteLine($"Instantané écrit : {path}");
        Console.WriteLine($"  lectures enregistrées : {snapshot.Registry.Count} registre, " +
                          $"{snapshot.Services.Count} services");
        Console.WriteLine(raw
            ? "  ATTENTION : capture brute, non anonymisée. Ne pas versionner tel quel."
            : "  anonymisé : hostname, numéros de série et propriétaire remplacés par des empreintes.");

        return 0;
    }
}
