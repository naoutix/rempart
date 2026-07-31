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

    /// <summary>
    /// Names the detail that says <em>which</em> place, where one source addresses several.
    ///
    /// <para>
    /// <c>rempart diff</c> folds a disappearance and an appearance at one place into a single
    /// « le même emplacement lance autre chose », and refuses to when the source designates
    /// more than one thing — two entries of the same <c>hosts</c> file are not a substitution
    /// for one another. That took the source for the place, which held until #193: Windows
    /// binds the two TCP/IP stacks of an adapter under one GUID, so a card that resolves on
    /// both carries two <c>dns-resolver</c> findings under one source, told apart by the stack
    /// and nothing else. The key knew no such dimension, so a resolver repointed on such a card
    /// came out as two unrelated lines — and a v4 resolver dropped while a v6 one was set came
    /// out as one substitution that never happened.
    /// </para>
    ///
    /// <para>
    /// The value is the detail key carrying the coordinate — <c>"pile"</c> — or several
    /// separated by <c>", "</c> where a source is addressed along more than one axis. Named
    /// rather than duplicated, so the row a reader needs keeps the word that reader needs:
    /// <c>DnsResolverCollector</c> writes <c>pile</c> because the stack is also what says which
    /// <c>netsh</c> command undoes the finding.
    /// </para>
    ///
    /// <para>
    /// Which detail that is belongs to the collector, for the reason <see cref="Transient"/>
    /// does: the collector knows how its surface is indexed, and the diff would be inferring
    /// it from a source path. A collector that names nothing keeps the key it had, so a family
    /// sharing one source across its whole enumeration goes on refusing the merge without
    /// having to know this key exists. What none of this can check is a collector naming one
    /// axis of two — the diff sees the details, never the surface they were read from.
    /// </para>
    /// </summary>
    public const string Place = "emplacement";
}
