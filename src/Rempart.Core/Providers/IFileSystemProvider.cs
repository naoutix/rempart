namespace Rempart.Core.Providers;

/// <summary>
/// The files of one directory, plus whether that directory could be listed at all.
///
/// <para>
/// The fifth surface to need this channel (DET-FICHIERS-MUET), after drivers and processes
/// (DET-WMI-MUET), browser profiles (DET-EXT-MUET) and the listening tables
/// (DET-PORTS-MUET). Before it, <c>ListFiles</c> returned a bare list and a <b>refused</b>
/// startup folder came back exactly like an <b>empty</b> one, so the report said « aucun
/// autorun » about a surface nobody had been able to read — on the first place an attacker
/// drops a persistence.
/// </para>
///
/// <para>
/// Three states, and the middle one is why this is not a boolean:
/// <list type="bullet">
///   <item><see cref="Found"/> — the directory was listed. <b>An empty list here is an
///   answer, not a silence</b>: an empty startup folder is the ordinary state of most
///   machines, and turning that into a finding would cry wolf on every scan. That is the
///   asymmetry phase 2 settled — zero driver cannot be true, zero startup item obviously
///   can.</item>
///   <item><see cref="Absent"/> — the directory is not on disk. Also an answer: the scan
///   walks a fixed list of startup locations and several are legitimately missing. Recorded
///   as its own state rather than folded into <see cref="Found"/>, because « j'ai listé ce
///   dossier et il était vide » is a claim, and the scan did not make it.</item>
///   <item><see cref="Refused"/> — the listing was denied. Re-running elevated is the
///   answer, and it is the commonest gap this tool has.</item>
///   <item><see cref="Failed"/> — the listing was attempted and did not complete, without
///   being denied: a folder held open, a volume that went away. No amount of rights changes
///   this one.</item>
/// </list>
/// </para>
///
/// <para>
/// <b>The last two used to be a single <c>Failed</c> documented as « the listing was
/// refused », and that sentence was false</b> — <c>LiveFileSystemProvider</c> caught
/// <c>IOException</c> through it as readily as <c>UnauthorizedAccessException</c>. Nothing
/// tied the sentence to the <c>catch</c> beside it, so the two drifted and
/// <c>AutorunsCollector</c>, which quoted the sentence to justify
/// <see cref="Findings.AuditGap.Refused"/>, sent the reader to elevate over a folder no
/// privilege would open. Splitting the factory is what makes the state the caller branches on
/// the same object as the state the documentation describes.
/// </para>
///
/// <para>
/// <b>No <c>Partial</c> factory, unlike <see cref="ListeningPortRead"/>, and the difference
/// is the argument.</b> A port read spans four tables (TCP/UDP × IPv4/IPv6) behind a single
/// call, so it can come back half-read and needs a shape that says so. Here the directory is
/// a parameter: one call is one directory, and <c>Directory.GetFiles</c> either returns the
/// whole listing or throws. The partiality is real but it lives one level up, in the
/// collector's loop over startup folders — a refused machine folder must not cost the files
/// of the readable user folder — which is where <c>AutorunsCollector</c> handles it and where
/// the test for it sits.
/// </para>
/// </summary>
public sealed record DirectoryRead(
    ReadStatus Status,
    IReadOnlyList<string> Files,
    string? Diagnostic = null)
    : IStatusCarryingRead<DirectoryRead, string>
{
    /// <summary>The directory is not on disk. Nothing runs from a folder that is not there.</summary>
    public static readonly DirectoryRead Absent = new(ReadStatus.NotFound, []);

    public static DirectoryRead Found(IReadOnlyList<string> files) =>
        new(ReadStatus.Found, files);

    /// <summary>The listing was denied. Elevation is the answer.</summary>
    /// <param name="reason">
    /// What happened, in French — it reaches the report. <b>Only a genuine denial may come
    /// through here.</b> An <c>IOException</c> is not one, and <see cref="Failed"/> is where it
    /// goes: printing « accès refusé » over it is the invariant CONTRIBUTING records.
    /// </param>
    public static DirectoryRead Refused(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);

    /// <summary>
    /// The listing was attempted and did not complete, without being denied.
    ///
    /// <para>
    /// Kept under the name the old both-meanings factory had, deliberately: every existing
    /// caller that meant « failed » — a scan wired with no file provider, a capture holding
    /// nothing at this path — keeps compiling and now says something true, while the callers
    /// that meant a denial had to be looked at one by one and moved to <see cref="Refused"/>.
    /// The rename that would have been silent is the one that was avoided.
    /// </para>
    /// </summary>
    public static DirectoryRead Failed(string reason) =>
        new(ReadStatus.Failed, [], reason);

    // Explicit, so "Files" stays the only name a caller sees and nothing new appears in any
    // serialised shape. See IStatusCarryingRead.
    IReadOnlyList<string> IStatusCarryingRead<DirectoryRead, string>.Items => Files;

    static DirectoryRead IStatusCarryingRead<DirectoryRead, string>.Compose(
        ReadStatus status, IReadOnlyList<string> items, string? diagnostic) =>
        new(status, items, diagnostic);
}

/// <summary>
/// Lists the files of a directory.
///
/// Abstracted for the same reason as the registry (ADR-001, D5): a snapshot must be
/// replayable offline, and a directory enumeration is part of what a scan observes.
/// </summary>
public interface IFileSystemProvider
{
    /// <summary>
    /// Files in the directory, as full paths, and whether they could be listed.
    ///
    /// Enumeration of the other locations must continue whatever this one answers: the
    /// caller walks several directories and a failure on one is not a failure of the scan.
    /// </summary>
    DirectoryRead ListFiles(string directory);
}
