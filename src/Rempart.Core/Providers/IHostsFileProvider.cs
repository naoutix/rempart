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
/// Three states, and the middle one is why this is not a boolean, exactly as for
/// <see cref="DirectoryRead"/>:
/// <list type="bullet">
///   <item><see cref="Found"/> — the file was read. <b>No entry is an answer, not a
///   silence</b>: a <c>hosts</c> file holding nothing but comments is the default state of
///   Windows, and flagging it would cry wolf on every scan.</item>
///   <item><see cref="Absent"/> — there is no file. Also an answer: a machine without one
///   resolves through DNS alone, which is what an empty one means too. This is the half the
///   old summary had right, and the half it folded the other two into.</item>
///   <item><see cref="Failed"/> — the read was attempted and did not complete. The only one
///   that speaks.</item>
/// </list>
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

    /// <summary>A read that was attempted and did not complete.</summary>
    /// <param name="reason">
    /// What happened, in French — it reaches the report. <b>Only a genuine denial may be
    /// called one.</b> A file held open with no sharing — as ordinary a way to protect a
    /// redirection as an ACL — throws <c>IOException</c> and is no question of rights;
    /// printing « accès refusé » there is the invariant CONTRIBUTING records, and it already
    /// cost this project two milestones of a WMI that read as missing privileges.
    /// </param>
    public static HostsFileRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);

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
