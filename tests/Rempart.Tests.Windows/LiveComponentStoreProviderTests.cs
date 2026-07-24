using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The component store analysis against the real servicing stack.
///
/// Two things are worth pinning here and nowhere else: that this provider only ever
/// asks the tool to <em>report</em>, and that a run without elevation degrades instead
/// of throwing — which is the case on a CI runner and on any machine started normally.
/// </summary>
public sealed class LiveComponentStoreProviderTests
{
    /// <summary>
    /// v1 writes nothing (ADR-001, D2). The same executable that reports the store size
    /// also empties it, one verb away, and this provider is the only place in the
    /// project that hands arguments to a program that can delete.
    /// </summary>
    [Fact]
    public void The_analysis_never_asks_for_a_cleanup()
    {
        var arguments = string.Join(' ', LiveComponentStoreProvider.Arguments);

        Assert.Contains("/AnalyzeComponentStore", arguments, StringComparison.Ordinal);

        foreach (var destructive in new[]
                 {
                     "/StartComponentCleanup", "/ResetBase", "/SPSuperseded",
                     "/RestoreHealth", "/Cleanup-Mountpoints", "/Remove",
                 })
        {
            Assert.DoesNotContain(destructive, arguments, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// English output is requested so the parser faces one set of labels. Without it the
    /// figures would be read on a machine in English and nowhere else — and the failure
    /// would be silent, since unrecognised output yields no numbers.
    /// </summary>
    [Fact]
    public void The_analysis_asks_for_english_output() =>
        Assert.Contains("/English", LiveComponentStoreProvider.Arguments);

    /// <summary>
    /// Whatever the privileges, the provider answers. Unelevated, the tool refuses with
    /// code 740 before doing any work, and that must come back as a denial — never as an
    /// exception, and never as a store of zero bytes.
    /// </summary>
    [Fact]
    public void A_run_without_elevation_degrades_instead_of_failing()
    {
        var read = new LiveComponentStoreProvider(TimeSpan.FromMinutes(2)).Read();

        Assert.True(
            read.Status is ReadStatus.Found or ReadStatus.AccessDenied or ReadStatus.NotFound,
            $"Statut inattendu : {read.Status}");

        if (read.Status == ReadStatus.Found)
        {
            // Elevated run: the anchor figure must be a real size, not a default.
            Assert.NotNull(read.ActualSizeBytes);
            Assert.True(read.ActualSizeBytes > 0);
        }
        else
        {
            // Degraded run: it says why, and invents nothing.
            Assert.NotNull(read.Diagnostic);
            Assert.Null(read.ActualSizeBytes);
            Assert.Null(read.ReclaimableBytes);
        }
    }
}
