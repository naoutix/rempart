using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// The third and last whole-set wiring: every provider reading the machine it runs on.
///
/// <para>
/// The two others live in <c>Rempart.Core.Snapshots.SnapshotProviders</c>, which cannot name
/// a Windows type. This one has to sit here for exactly that reason, and it is the reason it
/// gets its own guard in the Windows suite rather than sharing theirs.
/// </para>
///
/// <para>
/// What it removes is the last hand-copied list of twenty providers. A provider added to
/// <see cref="ProviderSet"/> and forgotten here does not fail to compile: the parameter is
/// optional and the set falls back to its no-op, so the scan reports « aucun fournisseur
/// n'a été fourni » — or worse, an empty inventory — on a machine that would have answered.
/// That accident has shipped three times (D2, D2b, the component store), each time in one of
/// these lists.
/// </para>
/// </summary>
public static class LiveProviders
{
    /// <summary>
    /// Constructs the set. Nothing is read here — every provider queries Windows on its
    /// first call — so building the set costs nothing and cannot fail on a denied API.
    /// </summary>
    public static ProviderSet All() =>
        new(
            new LiveRegistryProvider(),
            new LiveSystemInfoProvider(),
            services: new LiveServiceStateProvider(),
            policy: new LiveSecurityPolicyProvider(),
            wmi: new Wmi.LiveWmiProvider(),
            signatures: new LiveSignatureProvider(),
            files: new LiveFileSystemProvider(),
            scheduledTasks: new Tasks.LiveScheduledTaskProvider(),
            drivers: new LiveDriverProvider(),
            processes: new LiveProcessProvider(),
            listeningPorts: new LiveListeningPortProvider(),
            firewall: new LiveFirewallProvider(),
            dns: new LiveDnsProvider(),
            hostsFile: new LiveHostsFileProvider(),
            proxy: new LiveProxyProvider(),
            wifi: new LiveWifiProfileProvider(),
            softwareInventory: new LiveSoftwareInventoryProvider(),
            browserExtensions: new LiveBrowserExtensionProvider(),
            componentStore: new LiveComponentStoreProvider(),
            dynamicPortRange: new LiveDynamicPortRangeProvider());
}
