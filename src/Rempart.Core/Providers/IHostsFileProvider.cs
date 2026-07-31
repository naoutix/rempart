namespace Rempart.Core.Providers;

/// <summary>
/// The lines of the <c>hosts</c> file, and whether it could be read at all.
///
/// <para>
/// The sixth surface to need this channel, and the one where the silence served an attacker
/// most directly: <b>denying read access to <c>hosts</c> is precisely the technique that
/// protects a redirection already in place</b>, and the read answered it with the same empty
/// list as the comment-only file every Windows installation ships. Nothing was reported —
/// the <c>CriticalFragments</c> the collector exists to catch included.
/// </para>
///
/// <para>
/// Four states — two answers about the machine, two holes in what the scan saw — and no one
/// of them folds into another, exactly as for <see cref="DirectoryRead"/>:
/// <list type="bullet">
///   <item><see cref="Found"/> — the file was read. <b>No entry is an answer, not a
///   silence</b>: a <c>hosts</c> file holding nothing but comments is the default state of
///   Windows, and flagging it would cry wolf on every scan.</item>
///   <item><see cref="Absent"/> — there is no file. Also an answer: a machine without one
///   resolves through DNS alone, which is what an empty one means too. This is the half the
///   old summary had right, and the half it folded the other two into.</item>
///   <item><see cref="Refused"/> — the read was denied. The ACL that protects a redirection
///   already in place lands here, and elevation is the answer.</item>
///   <item><see cref="Failed"/> — the read was attempted and did not complete without being
///   denied: the file held open with no sharing, as ordinary a way to keep a redirection
///   unread as an ACL and not a question of rights.</item>
/// </list>
/// </para>
///
/// <para>
/// <b>The last two used to be one factory.</b> The prose already told them apart — the live
/// read has separated the two <c>catch</c> blocks since REV-12 and prints each in its own
/// words — but both returned <see cref="ReadStatus.AccessDenied"/>, so the only thing a
/// collector could branch on said « denied » either way. <c>HostsFileCollector</c> answered
/// <see cref="Findings.AuditGap.Refused"/> for both and its own comment conceded the point.
/// An honest sentence beside a machine-readable field that contradicts it is still a
/// contradiction; this is the field catching up with the sentence.
/// </para>
/// </summary>
public sealed record HostsFileRead(
    ReadStatus Status,
    IReadOnlyList<string> Lines,
    string? Diagnostic = null)
    : IStatusCarryingRead<HostsFileRead, string>
{
    /// <summary>No <c>hosts</c> file at that path. Nothing resolves through a file that is
    /// not there.</summary>
    public static readonly HostsFileRead Absent = new(ReadStatus.NotFound, []);

    public static HostsFileRead Found(IReadOnlyList<string> lines) =>
        new(ReadStatus.Found, lines);

    /// <summary>A read that was denied. Elevation is the answer.</summary>
    /// <param name="reason">
    /// What happened, in French — it reaches the report. <b>Only a genuine denial may be
    /// called one.</b> A file held open with no sharing — as ordinary a way to protect a
    /// redirection as an ACL — throws <c>IOException</c> and is no question of rights;
    /// printing « accès refusé » there is the invariant CONTRIBUTING records, and it already
    /// cost this project two milestones of a WMI that read as missing privileges.
    /// </param>
    public static HostsFileRead Refused(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);

    /// <summary>
    /// A read that was attempted, did not complete, and was not denied. Kept under the old
    /// name for the reason <see cref="DirectoryRead.Failed"/> gives: the callers that already
    /// meant this keep compiling, the ones that meant a denial had to be moved by hand.
    /// </summary>
    public static HostsFileRead Failed(string reason) =>
        new(ReadStatus.Failed, [], reason);

    // Explicit, so "Lines" stays the only name a caller sees and nothing new appears in any
    // serialised shape. See IStatusCarryingRead.
    IReadOnlyList<string> IStatusCarryingRead<HostsFileRead, string>.Items => Lines;

    static HostsFileRead IStatusCarryingRead<HostsFileRead, string>.Compose(
        ReadStatus status, IReadOnlyList<string> items, string? diagnostic) =>
        new(status, items, diagnostic);
}

/// <summary>
/// Reads the <c>hosts</c> file, line by line, unparsed.
///
/// <para>
/// The <c>hosts</c> file bypasses DNS: a mapping in it is consulted before any name
/// server. It is used from both sides — an ad blocker maps domains to a null address,
/// and malware redirects Windows Update to an address it controls. Parsing happens in
/// the core; the provider only returns the lines, so the judgment can be tested without
/// a file.
/// </para>
/// </summary>
public interface IHostsFileProvider
{
    HostsFileRead ReadLines();
}
