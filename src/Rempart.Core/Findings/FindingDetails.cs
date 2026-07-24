namespace Rempart.Core.Findings;

/// <summary>
/// Detail keys that mean something to more than the collector that wrote them.
///
/// Most details are free-form and read by a human. The ones here are read by code —
/// today by <c>rempart diff</c> — so they are named in one place rather than spelled out
/// at each end, where a typo would silently disable the behaviour instead of failing.
/// </summary>
public static class FindingDetails
{
    /// <summary>
    /// Marks something Windows itself removes in the ordinary course of running.
    ///
    /// <para>
    /// The value is the explanation shown to the reader; the presence of the key is what
    /// matters to code. Two scans taken minutes apart differ on these without anything
    /// having happened — a <c>RunOnce</c> entry is consumed at the next boot, a task set
    /// to be deleted once expired disappears on its own. Reporting them as posture
    /// changes would make every diff carry noise, and a diff that always shows movement
    /// stops being read.
    /// </para>
    ///
    /// <para>
    /// The judgement belongs to the collector, which knows the mechanism, rather than to
    /// the diff, which would have to infer it from a source path. Any collector that
    /// enumerates something self-removing can set this key and be handled correctly
    /// without the diff learning anything new.
    /// </para>
    /// </summary>
    public const string Transient = "transitoire";

    /// <summary>
    /// Marks something whose <em>identity</em> churns by design, in both directions.
    ///
    /// <para>
    /// Distinct from <see cref="Transient"/>, and the difference matters. A
    /// <c>RunOnce</c> entry disappearing is expected but one appearing is news — that is
    /// how you get code run at the next boot. An ephemeral socket is not like that: the
    /// operating system hands out a different port number every time, so the one that
    /// vanished and the one that showed up are the same fact wearing another number.
    /// Suppressing only the disappearance would halve the noise and keep the report
    /// wrong.
    /// </para>
    ///
    /// <para>
    /// Found by running the comparison rather than by reasoning about it: two scans
    /// fourteen seconds apart on the test machine differed by three Chrome UDP sockets
    /// and nothing else. The roadmap had listed two transients before this batch; this
    /// is the third.
    /// </para>
    /// </summary>
    public const string Ephemeral = "éphémère";
}
