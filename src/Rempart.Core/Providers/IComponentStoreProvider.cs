namespace Rempart.Core.Providers;

/// <summary>
/// What the component store (<c>WinSxS</c>) analysis reports, in bytes.
///
/// <para>
/// Every figure is nullable and stays null when the analysis did not state it. A missing
/// number is said to be missing; it is never replaced by zero, which would read as
/// "nothing to reclaim" — the opposite of "we do not know".
/// </para>
/// </summary>
public sealed record ComponentStoreRead(
    ReadStatus Status,

    /// <summary>Size the store really occupies, hard links accounted for.</summary>
    long? ActualSizeBytes,

    /// <summary>
    /// The part shared with the live Windows installation. Not reclaimable: these are
    /// the files Windows is running on, seen through the store.
    /// </summary>
    long? SharedWithWindowsBytes,

    /// <summary>Superseded component backups and payloads of disabled features.</summary>
    long? BackupsAndDisabledFeaturesBytes,

    /// <summary>Cache and temporary data of the servicing stack.</summary>
    long? CacheAndTemporaryBytes,

    /// <summary>Date of the last cleanup, as reported, or null when never run.</summary>
    string? LastCleanup,

    int? ReclaimablePackages,

    /// <summary>Whether the servicing stack itself recommends a cleanup.</summary>
    bool? CleanupRecommended,

    /// <summary>Why the read is not <see cref="ReadStatus.Found"/>. Never silent.</summary>
    string? Diagnostic)
{
    public static ComponentStoreRead Denied(string diagnostic) =>
        new(ReadStatus.AccessDenied, null, null, null, null, null, null, null, diagnostic);

    public static ComponentStoreRead Failed(string diagnostic) =>
        new(ReadStatus.NotFound, null, null, null, null, null, null, null, diagnostic);

    /// <summary>
    /// What a cleanup could actually free: backups, disabled features, cache and
    /// temporary data — never the part shared with Windows.
    ///
    /// Null unless at least one of the two layers was reported, so that "unknown" and
    /// "nothing to reclaim" stay distinguishable.
    /// </summary>
    public long? ReclaimableBytes =>
        BackupsAndDisabledFeaturesBytes is null && CacheAndTemporaryBytes is null
            ? null
            : (BackupsAndDisabledFeaturesBytes ?? 0) + (CacheAndTemporaryBytes ?? 0);
}

/// <summary>
/// Reads the size of the component store, by layer.
///
/// <para>
/// The only source for it is the servicing stack itself, through
/// <c>DISM /Cleanup-Image /AnalyzeComponentStore</c>. Walking <c>WinSxS</c> on disk
/// would give a number three times too large: most of what is in there is hard-linked
/// into the live Windows installation and counted twice by any naive traversal.
/// </para>
///
/// <para>
/// Read-only by construction: the analysis verb reports, it deletes nothing. The
/// cleanup verbs of the same tool exist and are deliberately never invoked — v1 writes
/// nothing (ADR-001, D2), and a report saying how much could be freed is exactly the
/// point of stopping there.
/// </para>
/// </summary>
public interface IComponentStoreProvider
{
    ComponentStoreRead Read();
}
