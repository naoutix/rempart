namespace Rempart.Core.Providers;

/// <summary>
/// Outcome of a read. Distinguishing <see cref="NotFound"/> from
/// <see cref="AccessDenied"/> is essential: a missing key is information, a denied
/// access is a gap in the audit. Conflating them would produce a report that misleads
/// by omission.
/// </summary>
public enum ReadStatus
{
    Found,
    NotFound,
    AccessDenied,

    /// <summary>
    /// The read was attempted, did not complete, and <b>was not denied</b> — a file held open
    /// by another process, a volume that went away mid-listing. Nothing about the caller's
    /// rights changes this answer.
    ///
    /// <para>
    /// Added because its absence is what made a documented contract untrue. With three values
    /// a channel that wanted to speak had exactly one way to do it, so
    /// <c>DirectoryRead.Failed</c> and <c>HostsFileRead.Failed</c> returned
    /// <see cref="AccessDenied"/> for an <c>IOException</c> as much as for an ACL, while their
    /// interfaces documented that state as « the listing was refused ». The collectors read the
    /// documentation, answered <see cref="Findings.AuditGap.Refused"/>, and a startup folder
    /// held open by another process told its reader to re-run as administrator — the invariant
    /// CONTRIBUTING records, « never translate a failure into access denied », broken by the
    /// vocabulary rather than by any one <c>catch</c>.
    /// </para>
    ///
    /// <para>
    /// <b>What naming the fourth state buys, exactly, and what it does not.</b> It makes the
    /// distinction <em>expressible</em>, so a collector can branch on the state instead of on a
    /// sentence of prose — that part is structural and holds without anyone remembering it. It
    /// does not make the documentation true by construction: nothing in the type stops a
    /// <c>catch</c> from mapping <c>IOException</c> onto <see cref="AccessDenied"/> again, and
    /// the first fix here shipped with exactly that mutation passing both suites, because the
    /// one branch that names the defect was the one branch no test could reach. Each live read
    /// therefore carries a seam and a test asserting its own mapping —
    /// <c>LiveFileSystemProviderTests</c> and <c>LiveHostsFileProviderTests</c>. The type plus
    /// those two is what closes it; the type alone was still discipline.
    /// </para>
    ///
    /// <para>
    /// <b>Appended last, and produced by every read that can fail — since #177, and not
    /// before.</b> The two issues that introduced it left thirteen factories named
    /// <c>Failed</c> or <c>Partial</c> still spelling their failures <see cref="AccessDenied"/>,
    /// so this member was the vocabulary of two channels rather than of the layer. It is now
    /// the layer's, and <c>ReadFactoryNamingTests</c> holds the two apart: a factory whose name
    /// states a cause carries it, and <see cref="AccessDenied"/> is reached either through a
    /// name that says « refused » or through a <see cref="StatusFoldAttribute"/> that delegates
    /// to one — because it is the only status the report turns into an instruction to its
    /// reader. Four <c>== AccessDenied</c> comparisons had to be widened to
    /// <c>is AccessDenied or Failed</c> in the same commit — the two WMI-backed collectors and
    /// <c>CheckReader.ReadService</c>, which read « anything the layer could not give » through
    /// a test that named only the denial.
    /// </para>
    ///
    /// <para>
    /// Statuses are serialised by name, so a capture taken before this value simply never
    /// carries it and replays exactly as it did — a snapshot recording <see cref="AccessDenied"/>
    /// on a surface a scan run today would call <see cref="Failed"/> still answers what it
    /// answered when it was written.
    /// </para>
    /// </summary>
    Failed,
}

/// <summary>
/// Marks a read factory that states no cause of its own and picks among the ones that do.
///
/// <para>
/// The vocabulary of this layer is that a factory's name states a cause and
/// <see cref="ReadStatus"/> is the same statement in a form a caller can branch on:
/// <c>Found</c>, <c>Absent</c>/<c>NotFound</c>/<c>NotInstalled</c>,
/// <c>Refused</c>/<c>Denied</c>/<c>AccessDenied</c>, <c>Failed</c>. A fold cannot obey that,
/// and not for want of a better name: <c>ScheduledTaskRead.Partially</c> answers a refusal on
/// one input and a failure on another, so any single word it could be called would be a lie on
/// one of the two. What it does instead is read the cause off its arguments — in one place,
/// beside where the HRESULTs are already read — and call the named factory for it.
/// </para>
///
/// <para>
/// <b>This attribute exists because the guard could not otherwise tell a fold from a defect.</b>
/// <c>ReadFactoryNamingTests</c> builds every factory on three shapes of argument and asserts on
/// the statuses it reaches; a factory that answers differently between them either is a fold and
/// says so here, or is exactly the bug #177 was opened over — a name promising one state and a
/// field holding another, on the input that actually occurs. Declaring it is therefore not an
/// exemption granted quietly: the guard pins the set of members carrying this attribute, refuses
/// one that does not really fold, and requires a named test per branch.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class StatusFoldAttribute : Attribute;

public sealed record RegistryValue(string Kind, string? Text, long? Number)
{
    public static RegistryValue OfText(string text) => new("String", text, null);

    public static RegistryValue OfNumber(long number) => new("DWord", null, number);

    public override string ToString() => Text ?? Number?.ToString() ?? string.Empty;
}

public sealed record RegistryRead(ReadStatus Status, RegistryValue? Value)
{
    public static readonly RegistryRead NotFound = new(ReadStatus.NotFound, null);
    public static readonly RegistryRead AccessDenied = new(ReadStatus.AccessDenied, null);

    public static RegistryRead Found(RegistryValue value) => new(ReadStatus.Found, value);
}

/// <summary>
/// The values of one key, and whether they could be enumerated at all.
///
/// <para>
/// <see cref="RegistryRead"/> has carried a status since the first milestone; the two
/// enumerating reads beside it carried none, and returned the same empty listing whether the
/// key held nothing or the enumeration was refused (REV-11). A denial laid on a <c>Run</c>
/// key therefore produced « aucun démarrage automatique », one laid on
/// <c>HKCU\Software\Classes\CLSID</c> « aucun détournement COM », and both read exactly like
/// a clean machine — on the two surfaces a persistence uses first.
/// </para>
///
/// <para>
/// <b>The status replaces the bare collection rather than sitting beside it in an
/// overload.</b> An overload leaves the statusless call as the shorter one, so the next
/// collector written takes it and the silence comes back — the hand-kept coverage the review
/// of 2026-07-29 is about. Changing the return type makes the compiler enumerate the call
/// sites once, and no later caller can reach the values without the status in hand. What it
/// cannot force is a caller <em>acting</em> on a refusal: that stays a judgement, because
/// only the caller knows whether zero is an answer on its surface — five autostart keys where
/// four are legitimately empty, against a hive nobody may be refused.
/// </para>
///
/// <para>
/// Status without diagnostic, like <see cref="RegistryRead"/> next door and for its reason:
/// the caller names the key it is reading, so « refusé » is the whole message. Nothing else
/// is folded in either — the provider catches the two denial exceptions and lets every other
/// failure through, so there is no failure here that a diagnostic would have to keep from
/// being mistaken for a denial.
/// </para>
/// </summary>
public sealed record RegistryValueList(
    ReadStatus Status,
    IReadOnlyDictionary<string, RegistryValue> Values)
{
    private static readonly IReadOnlyDictionary<string, RegistryValue> Nothing =
        new Dictionary<string, RegistryValue>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The key is not there. An answer, not a silence: the scan walks a fixed list of
    /// locations and most machines are missing several of them.
    /// </summary>
    public static readonly RegistryValueList NotFound = new(ReadStatus.NotFound, Nothing);

    /// <summary>The enumeration was refused. The only one that speaks.</summary>
    public static readonly RegistryValueList AccessDenied =
        new(ReadStatus.AccessDenied, Nothing);

    /// <summary>
    /// The key was enumerated. <b>An empty listing here is an answer</b> — four of the five
    /// <c>Run</c> keys hold nothing on an ordinary machine, and reporting that would put a
    /// finding on every scan. Same asymmetry as <see cref="DirectoryRead.Found"/>.
    /// </summary>
    public static RegistryValueList Found(IReadOnlyDictionary<string, RegistryValue> values) =>
        new(ReadStatus.Found, values);
}

/// <summary>
/// The subkeys of one key, and whether they could be enumerated. Same three states and same
/// reasoning as <see cref="RegistryValueList"/>; kept a separate type because the two reads
/// are asked separately and a key can legitimately refuse one and answer the other.
/// </summary>
public sealed record RegistrySubKeyList(ReadStatus Status, IReadOnlyList<string> Names)
{
    public static readonly RegistrySubKeyList NotFound = new(ReadStatus.NotFound, []);

    public static readonly RegistrySubKeyList AccessDenied = new(ReadStatus.AccessDenied, []);

    public static RegistrySubKeyList Found(IReadOnlyList<string> names) =>
        new(ReadStatus.Found, names);
}

/// <summary>
/// Registry access. No collector calls Windows directly (ADR-001, D5): this is what
/// allows replaying a scan offline from a snapshot.
/// </summary>
public interface IRegistryProvider
{
    /// <param name="keyPath">Full path, e.g. <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</c>.</param>
    RegistryRead ReadValue(string keyPath, string valueName);

    /// <summary>Whether a key exists — useful when presence alone is the signal.</summary>
    ReadStatus KeyExists(string keyPath);

    /// <summary>
    /// All values of a key, by name, and whether they could be enumerated.
    ///
    /// Rules query a value they already know; autostart enumeration instead discovers
    /// what is there. Entries whose names are unknown cannot be looked up by name — which
    /// is also why the refusal has to be carried rather than inferred: a caller that never
    /// named anything has nothing to compare an empty listing against.
    /// </summary>
    RegistryValueList ListValues(string keyPath);

    /// <summary>
    /// The names of a key's subkeys, and whether they could be enumerated. Used to discover
    /// a tree whose entries are not known in advance — for example CLSIDs registered by a
    /// user, whose identifiers are unpredictable.
    /// </summary>
    RegistrySubKeyList ListSubKeys(string keyPath);
}
