using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// The two whole-set wirings of the capture → snapshot → replay path, each written once.
///
/// <para>
/// Every provider appears in <see cref="ProviderSet"/> four times: the live wiring, the
/// recording wiring that produces a capture, the replay wiring that reads one back, and —
/// until this class existed — a second copy of that replay wiring inside the test suite.
/// D2, D2b and the component store are the same accident three times over: a provider added
/// to the set and forgotten in one of those lists, so the matching collector ran on nothing
/// and the reference froze « rien trouvé » over a capture that held the data.
/// </para>
///
/// <para>
/// Two of the four lists are now this file. That is what closes the loophole rather than
/// merely shortening it: <c>Every_provider_is_wired_into_the_replay</c> used to inspect the
/// test's own copy, so <c>rempart scan --from</c> could lose a provider with every guard
/// still green. The guard now reads <see cref="Replaying"/>, which is the list the shipped
/// command uses, and a second guard reads <see cref="Recording"/> — the direction nothing
/// watched at all, and the one whose failure is worse: a capture missing a provider records
/// nothing, so no later replay can recover what was never written down.
/// </para>
///
/// <para>
/// It sits in Core rather than beside the commands for the reason ADR-005 records twice:
/// <c>Rempart.Cli</c> targets <c>net10.0-windows</c> and the Linux job does not compile it,
/// so a wiring living there could carry no guard that CI runs.
/// </para>
/// </summary>
public static class SnapshotProviders
{
    /// <summary>
    /// Every provider reading from a snapshot instead of from Windows — what
    /// <c>rempart scan --from</c> and the fixture replay both run on.
    ///
    /// <para>
    /// Named arguments throughout, and that is not style: twenty parameters of which
    /// eighteen are optional means a positional list silently accepts a shorter one, and
    /// two same-shaped providers swapped by hand would compile.
    /// </para>
    /// </summary>
    public static ProviderSet Replaying(MachineSnapshot snapshot) =>
        new(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot),
            services: new SnapshotServiceStateProvider(snapshot),
            policy: new SnapshotSecurityPolicyProvider(snapshot),
            wmi: new SnapshotWmiProvider(snapshot),
            signatures: new SnapshotSignatureProvider(snapshot),
            files: new SnapshotFileSystemProvider(snapshot),
            scheduledTasks: new SnapshotScheduledTaskProvider(snapshot),
            drivers: new SnapshotDriverProvider(snapshot),
            processes: new SnapshotProcessProvider(snapshot),
            listeningPorts: new SnapshotListeningPortProvider(snapshot),
            firewall: new SnapshotFirewallProvider(snapshot),
            dns: new SnapshotDnsProvider(snapshot),
            hostsFile: new SnapshotHostsFileProvider(snapshot),
            proxy: new SnapshotProxyProvider(snapshot),
            wifi: new SnapshotWifiProfileProvider(snapshot),
            softwareInventory: new SnapshotSoftwareInventoryProvider(snapshot),
            browserExtensions: new SnapshotBrowserExtensionProvider(snapshot),
            componentStore: new SnapshotComponentStoreProvider(snapshot),
            dynamicPortRange: new SnapshotDynamicPortRangeProvider(snapshot));

    /// <summary>
    /// The same set, each provider wrapped so that everything the scan reads is written into
    /// <paramref name="snapshot"/> on the way past.
    ///
    /// <para>
    /// Takes the live set rather than building it: Core cannot name a single Windows type,
    /// and that constraint is what lets this wiring — and its guard — live on the Linux job.
    /// The caller supplies what it has, and a caller that supplies nothing gets the no-op
    /// defaults of <see cref="ProviderSet"/> wrapped as they are, which records exactly the
    /// « personne n'a regardé » they already answer.
    /// </para>
    /// </summary>
    public static ProviderSet Recording(ProviderSet live, MachineSnapshot snapshot) =>
        new(
            new RecordingRegistryProvider(live.Registry, snapshot),
            new RecordingSystemInfoProvider(live.SystemInfo, snapshot),
            services: new RecordingServiceStateProvider(live.Services, snapshot),
            policy: new RecordingSecurityPolicyProvider(live.Policy, snapshot),
            wmi: new RecordingWmiProvider(live.Wmi, snapshot),
            signatures: new RecordingSignatureProvider(live.Signatures, snapshot),
            files: new RecordingFileSystemProvider(live.Files, snapshot),
            scheduledTasks: new RecordingScheduledTaskProvider(live.ScheduledTasks, snapshot),
            drivers: new RecordingDriverProvider(live.Drivers, snapshot),
            processes: new RecordingProcessProvider(live.Processes, snapshot),
            listeningPorts: new RecordingListeningPortProvider(live.ListeningPorts, snapshot),
            firewall: new RecordingFirewallProvider(live.Firewall, snapshot),
            dns: new RecordingDnsProvider(live.Dns, snapshot),
            hostsFile: new RecordingHostsFileProvider(live.HostsFile, snapshot),
            proxy: new RecordingProxyProvider(live.Proxy, snapshot),
            wifi: new RecordingWifiProfileProvider(live.Wifi, snapshot),
            softwareInventory: new RecordingSoftwareInventoryProvider(live.SoftwareInventory, snapshot),
            browserExtensions: new RecordingBrowserExtensionProvider(live.BrowserExtensions, snapshot),
            componentStore: new RecordingComponentStoreProvider(live.ComponentStore, snapshot),
            dynamicPortRange: new RecordingDynamicPortRangeProvider(live.DynamicPortRange, snapshot));
}
