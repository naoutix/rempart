namespace Rempart.Core.Providers;

/// <summary>
/// A read that carries its own status: a list, whether it could be obtained, and why not
/// when it could not.
///
/// <para>
/// Eight reads have exactly this shape — drivers, processes, listening ports, browser
/// extensions, directory listings, the <c>hosts</c> file, the DNS interfaces and the software
/// inventory — and they got it one at a time, over DET-WMI-MUET, DET-EXT-MUET, DET-PORTS-MUET,
/// DET-FICHIERS-MUET, REV-12 and #184. What they share is not just the
/// record: it is the <em>three-way reading of a capture</em> that <see cref="StatusChannel"/>
/// holds, and that reading was copied four times before this class existed. A fifth copy was
/// where the next mistake would have sat, because the subtle branch — a capture taken before
/// the status field existed, which recorded a list and nothing else — is the one no test on a
/// current fixture exercises. <see cref="DirectoryRead"/> is that fifth read and it reuses
/// this instead, which is the whole point of the class being here.
/// </para>
///
/// <para>
/// The directory read is also the one that shows the abstraction was not over-fitted: its
/// three snapshot fields are three <em>maps</em> rather than three properties, because
/// <c>ListFiles</c> takes the directory as an argument. Nothing here had to change for that —
/// the helpers take the three values, not the place they are stored.
/// </para>
///
/// <para>
/// <c>static abstract</c> rather than a factory delegate handed in at each call site: the
/// call is resolved at compile time through the type parameter, so this survives Native AOT
/// (ADR-001) with no reflection, no <c>Activator</c> and no type resolved at run time.
/// </para>
///
/// <para>
/// <see cref="Items"/> is implemented explicitly by each read, so it adds no public property:
/// <c>DriverRead.Drivers</c> and <c>ListeningPortRead.Ports</c> keep the names their callers
/// read, and — the reason that matters — nothing new appears in any serialised shape.
/// </para>
/// </summary>
/// <typeparam name="TSelf">The read itself, so <see cref="Compose"/> can return it.</typeparam>
/// <typeparam name="TItem">What the read is a list of.</typeparam>
public interface IStatusCarryingRead<TSelf, TItem>
    where TSelf : IStatusCarryingRead<TSelf, TItem>
{
    ReadStatus Status { get; }

    string? Diagnostic { get; }

    /// <summary>What was read, under the name this generalisation can use.</summary>
    IReadOnlyList<TItem> Items { get; }

    /// <summary>Rebuilds the read from the three fields a capture stores it as.</summary>
    static abstract TSelf Compose(
        ReadStatus status, IReadOnlyList<TItem> items, string? diagnostic);
}

/// <summary>
/// The two halves of the status channel's capture path, written once for the five reads
/// that have it.
///
/// <para>
/// The status is stored <em>beside</em> the list in a snapshot rather than replacing it —
/// the decision phase 2 took and this repository has re-taken three times since: turning
/// <c>drivers</c> from a JSON array into an object would make every existing capture
/// unreadable, real-machine ones kept outside the repository included. Three loose fields is
/// the price of that promise, and it is what forces the reading below to be a decision
/// instead of a deserialisation.
/// </para>
/// </summary>
public static class StatusChannel
{
    /// <summary>
    /// What a capture holds, read back. Three cases, and the middle one is the whole point.
    ///
    /// <list type="number">
    ///   <item>A status was recorded: the read is rebuilt exactly as it was taken, failure
    ///   included — a capture made while WMI was mute must replay as « je n'ai pas pu
    ///   regarder », never as a machine with nothing loaded.</item>
    ///   <item>A list and no status: a capture predating the status field. It is read as the
    ///   success it was taken to be, which is the best available reading of what it recorded
    ///   and no worse than what that capture used to produce.</item>
    ///   <item>Neither: the surface was never collected. What <paramref name="absent"/>
    ///   answers is a judgement and not a shape — zero driver cannot be true of a running
    ///   machine, so it fails; zero browser extension is ordinary, so it succeeds. That
    ///   asymmetry is deliberate and is why this parameter exists rather than a constant.
    ///   The directory read shows it is not a two-way split either: an empty <em>listing</em>
    ///   is an answer there, while a directory the capture holds <em>nothing</em> about is
    ///   not, and only the caller knows which of its states it is naming.</item>
    /// </list>
    /// </summary>
    public static TRead Replay<TRead, TItem>(
        ReadStatus? status, List<TItem>? items, string? diagnostic, Func<TRead> absent)
        where TRead : IStatusCarryingRead<TRead, TItem> => status switch
    {
        { } recorded => TRead.Compose(recorded, items ?? [], diagnostic),
        _ when items is { } recorded => TRead.Compose(ReadStatus.Found, recorded, null),
        _ => absent(),
    };

    /// <summary>
    /// The recording half: read the machine once, write the three fields down, hand back
    /// what was read.
    ///
    /// <para>
    /// Already recorded means already read — a capture asks each surface once, and the scan
    /// that produces it walks the collectors twice (run, then prefetch). Re-querying would
    /// make the snapshot depend on which of the two passes happened to catch the machine in
    /// a better mood, and a fixture that is not the same twice is not a fixture.
    /// </para>
    ///
    /// <para>
    /// Only two cases here, against three above: a snapshot being filled in cannot hold a
    /// list without the status that was written beside it in the same statement.
    /// </para>
    /// </summary>
    public static TRead Record<TRead, TItem>(
        ReadStatus? status, List<TItem>? items, string? diagnostic,
        Func<TRead> read, Action<TRead> store)
        where TRead : IStatusCarryingRead<TRead, TItem>
    {
        if (status is { } recorded)
        {
            return TRead.Compose(recorded, items ?? [], diagnostic);
        }

        var fresh = read();
        store(fresh);
        return fresh;
    }
}
