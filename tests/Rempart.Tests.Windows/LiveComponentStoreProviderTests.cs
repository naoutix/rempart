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
    /// Whatever the privileges, the provider answers — never an exception, never a store
    /// of zero bytes. There are three answers, not two, and this test accepts all three
    /// because which one a given machine gives is not ours to choose: the analysis
    /// succeeds, or the tool refuses with code 740 before doing any work — a denial — or
    /// the servicing stack does not answer within the budget, which is a failure.
    ///
    /// <para>
    /// That third answer is why the set below names <see cref="ReadStatus.Failed"/>. Until
    /// this batch the timeout was spelled <see cref="ReadStatus.NotFound"/>, so it slipped
    /// through as an absence and this list did not have to mention it. A runner busy enough
    /// to exceed the budget is the ordinary case, not the edge one — it is where this
    /// distinction was found.
    /// </para>
    /// </summary>
    [Fact]
    public void A_run_without_elevation_degrades_instead_of_failing()
    {
        var read = new LiveComponentStoreProvider(TimeSpan.FromMinutes(2)).Read();

        Assert.True(
            read.Status is ReadStatus.Found or ReadStatus.AccessDenied
                or ReadStatus.NotFound or ReadStatus.Failed,
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

    /// <summary>
    /// A servicing stack that does not answer in time is a <b>failure</b>, not an absence.
    ///
    /// <para>
    /// The test above accepts whichever answer the machine happens to give, so on a fast
    /// machine it never reaches the timeout and the mapping goes unread — which is exactly
    /// how the old spelling survived: the branch only fires on a loaded runner. Squeezing
    /// the budget to nothing reaches it on any machine, and pins the distinction rather
    /// than waiting for a busy one to reveal it.
    /// </para>
    ///
    /// <para>
    /// The distinction is not cosmetic. An absence is a legitimate answer about the
    /// machine; a timeout is the tool admitting it did not look. Only the second one must
    /// keep the reader from concluding anything about the store.
    /// </para>
    /// </summary>
    [Fact]
    public void A_store_that_does_not_answer_in_time_fails_rather_than_going_missing()
    {
        var read = new LiveComponentStoreProvider(TimeSpan.FromMilliseconds(1)).Read();

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotNull(read.Diagnostic);
        Assert.Contains("n'a pas répondu", read.Diagnostic, StringComparison.Ordinal);

        // Nothing is invented on the way out, exactly as in the denial branch.
        Assert.Null(read.ActualSizeBytes);
        Assert.Null(read.ReclaimableBytes);
    }
}
