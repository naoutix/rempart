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

        var providers = new ProviderSet(
            new RecordingRegistryProvider(new LiveRegistryProvider(), snapshot),
            new RecordingSystemInfoProvider(new LiveSystemInfoProvider(), snapshot),
            services: new RecordingServiceStateProvider(new LiveServiceStateProvider(), snapshot),
            policy: new RecordingSecurityPolicyProvider(new LiveSecurityPolicyProvider(), snapshot),
            wmi: new RecordingWmiProvider(new Rempart.Windows.Wmi.LiveWmiProvider(), snapshot),
            signatures: new RecordingSignatureProvider(new LiveSignatureProvider(), snapshot),
            files: new RecordingFileSystemProvider(new LiveFileSystemProvider(), snapshot),
            scheduledTasks: new RecordingScheduledTaskProvider(
                new Rempart.Windows.Tasks.LiveScheduledTaskProvider(), snapshot),
            drivers: new RecordingDriverProvider(new LiveDriverProvider(), snapshot),
            processes: new RecordingProcessProvider(new LiveProcessProvider(), snapshot),
            listeningPorts: new RecordingListeningPortProvider(new LiveListeningPortProvider(), snapshot),
            firewall: new RecordingFirewallProvider(new LiveFirewallProvider(), snapshot),
            dns: new RecordingDnsProvider(new LiveDnsProvider(), snapshot),
            hostsFile: new RecordingHostsFileProvider(new LiveHostsFileProvider(), snapshot),
            proxy: new RecordingProxyProvider(new LiveProxyProvider(), snapshot),
            wifi: new RecordingWifiProfileProvider(new LiveWifiProfileProvider(), snapshot),
            softwareInventory: new RecordingSoftwareInventoryProvider(
                new LiveSoftwareInventoryProvider(), snapshot),
            browserExtensions: new RecordingBrowserExtensionProvider(
                new LiveBrowserExtensionProvider(), snapshot),
            componentStore: new RecordingComponentStoreProvider(
                new LiveComponentStoreProvider(), snapshot));

        // The full engine, rules included: a fixture must be able to replay everything a
        // scan does, otherwise it would only test half the path. The update store is
        // resolved here too, so a capture prefetches the keys of rules added by an update
        // and stays replayable.
        var engine = new ScanEngine(CollectorsFor(args), ResolveLiveCatalog(args).Rules);
        engine.Run(providers, ToolVersion(), snapshot.CapturedAtUtc);

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
