using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

/// <summary>
/// How much space the component store occupies, and how much of it a cleanup could
/// actually free.
///
/// <para>
/// A field collector, not a finding collector: the answer is a handful of figures known
/// in advance, not an enumeration to judge. Nothing here is a security verdict — a large
/// <c>WinSxS</c> is normal, not a weakness — so the numbers stay out of the score and
/// are reported as what they are: reclaimable space, by layer.
/// </para>
///
/// <para>
/// Reports, never deletes (ADR-001, D2). The distinction between the layer shared with
/// Windows and the rest is the whole point: the shared part is most of the store and is
/// not reclaimable, so the widespread advice to "empty WinSxS" targets a number that is
/// largely made of the files Windows is currently running on.
/// </para>
/// </summary>
public sealed class ComponentStoreCollector : ICollector
{
    public string Name => "component-store";

    public CollectorResult Collect(ProviderSet providers)
    {
        var read = providers.ComponentStore.Read();

        if (read.Status != ReadStatus.Found)
        {
            return new CollectorResult(
                Name,
                read.Status == ReadStatus.AccessDenied
                    ? CollectorStatus.InsufficientPrivileges
                    : CollectorStatus.Failed,
                [],
                read.Diagnostic is null ? [] : [read.Diagnostic]);
        }

        // Byte counts rather than "6,9 Gio": these are what rempart diff (M7) will
        // compare, and a rounded string does not subtract. The report formats them.
        var fields = new Dictionary<string, string?>
        {
            ["store.actualSizeBytes"] = read.ActualSizeBytes?.ToString(),
            ["store.sharedWithWindowsBytes"] = read.SharedWithWindowsBytes?.ToString(),
            ["store.backupsAndDisabledFeaturesBytes"] = read.BackupsAndDisabledFeaturesBytes?.ToString(),
            ["store.cacheAndTemporaryBytes"] = read.CacheAndTemporaryBytes?.ToString(),
            ["store.reclaimableBytes"] = read.ReclaimableBytes?.ToString(),
            ["store.reclaimablePackages"] = read.ReclaimablePackages?.ToString(),
            ["store.cleanupRecommended"] = read.CleanupRecommended?.ToString(),
            ["store.lastCleanup"] = read.LastCleanup,
        };

        return new CollectorResult(Name, CollectorStatus.Ok, fields, []);
    }
}
