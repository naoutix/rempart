using System.Runtime.InteropServices;
using System.Security.Principal;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Why one surface of the policy read established nothing: the sentence a report prints,
/// and whether the operating system actually said « refusé ».
///
/// <para>
/// The two are separate because they are separately wrong to guess. The sentence is what
/// reaches a verdict, and it prints the code as itself so that a broken <c>netapi32</c>
/// reads as a broken <c>netapi32</c>; the flag decides whether the read as a whole may call
/// itself a denial, and only <c>ERROR_ACCESS_DENIED</c> sets it. Every other code is a
/// failure, and « relancer en administrateur » is the one piece of advice that cannot help
/// with one — the invariant CONTRIBUTING records, which cost this project two milestones of
/// a mute WMI that read as missing privileges.
/// </para>
/// </summary>
internal readonly record struct PolicyGap(string Reason, bool Refused)
{
    /// <summary><c>ERROR_ACCESS_DENIED</c>, from <c>winerror.h</c>.</summary>
    private const int ErrorAccessDenied = 5;

    /// <summary>Names the call that stopped, and prints its code as itself.</summary>
    internal static PolicyGap Of(string call, int status) =>
        status == ErrorAccessDenied
            ? new PolicyGap($"{call} : accès refusé (5)", Refused: true)
            : new PolicyGap($"{call} : échec {status}", Refused: false);
}

/// <summary>
/// Local account policy, via <c>netapi32</c>.
///
/// Same API family as <c>NetGetJoinInformation</c>, already proven: the WMI/AOT
/// question open since M0 is still unresolved, but it does not block this batch either.
///
/// Any memory returned by these calls must be freed with <c>NetApiBufferFree</c>,
/// otherwise the leak would become visible under repeated scans.
/// </summary>
public sealed partial class LiveSecurityPolicyProvider : ISecurityPolicyProvider
{
    private const int MaxPreferredLength = -1;
    private const int FilterNormalAccount = 0x0002;

    /// <summary><c>NERR_Success</c>, from <c>lmerr.h</c>: the enumeration is complete.</summary>
    private const int NerrSuccess = 0;

    /// <summary>
    /// <c>ERROR_MORE_DATA</c> (234). Not a failure: netapi32 allocated the buffer, filled
    /// part of it, and expects to be called again with the resume handle it wrote back.
    /// </summary>
    private const int ErrorMoreData = 234;

    /// <summary>
    /// How many times one enumeration may be resumed. The local SAM holds a handful of
    /// accounts and <c>MAX_PREFERRED_LENGTH</c> lets netapi32 size the buffer itself, so a
    /// second batch is already unusual; the ceiling is not a limit on the machine, it is the
    /// exit from a resumption that stops making progress.
    /// </summary>
    private const int MaxBatches = 64;

    private const int UfAccountDisable = 0x0002;
    private const int UfPasswordNotRequired = 0x0020;
    private const int UfDontExpirePassword = 0x10000;

    private const uint TimeqForever = 0xFFFFFFFF;

    // The resume handles are `ref` and not `out`: netapi32 reads them back on the next call,
    // which is how an enumeration that answered in part is continued. Declared with the
    // widths lmaccess.h gives them — a DWORD here, a DWORD_PTR for the group members — since
    // a handle is opaque and truncating one is not something the compiler would notice.

    [LibraryImport("netapi32.dll", EntryPoint = "NetUserEnum")]
    private static partial int NetUserEnum(
        [MarshalAs(UnmanagedType.LPWStr)] string? server, int level, int filter,
        out IntPtr buffer, int prefMaxLen, out int read, out int total, ref int resume);

    [LibraryImport("netapi32.dll", EntryPoint = "NetUserModalsGet")]
    private static partial int NetUserModalsGet(
        [MarshalAs(UnmanagedType.LPWStr)] string? server, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll", EntryPoint = "NetLocalGroupGetMembers")]
    private static partial int NetLocalGroupGetMembers(
        [MarshalAs(UnmanagedType.LPWStr)] string? server,
        [MarshalAs(UnmanagedType.LPWStr)] string group, int level,
        out IntPtr buffer, int prefMaxLen, out int read, out int total, ref nint resume);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    // Native structs are declared rather than walked with hand-computed offsets. The
    // first version did that and got it wrong: USER_INFO_1 is 56 bytes, not 64, its
    // "flags" field is at offset 40, not 28, and the password policy starts at offset
    // 0. The reader crashed. Here the compiler computes sizes and offsets -- without
    // reflection, so compatible with Native AOT.

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        public IntPtr Name;
        public IntPtr Password;
        public uint PasswordAge;
        public uint Privilege;
        public IntPtr HomeDirectory;
        public IntPtr Comment;
        public uint Flags;
        public IntPtr ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserModalsInfo0
    {
        public uint MinPasswordLength;
        public uint MaxPasswordAge;
        public uint MinPasswordAge;
        public uint ForceLogoff;
        public uint PasswordHistoryLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserModalsInfo3
    {
        public uint LockoutDuration;
        public uint LockoutObservationWindow;
        public uint LockoutThreshold;
    }

    /// <summary>
    /// The layout the compiler produced for <c>USER_INFO_1</c>, so that a test can hold it
    /// against the one <c>netapi32</c> documents: 56 bytes, <c>Flags</c> at offset 40.
    ///
    /// <para>
    /// Those two numbers are the bug this file was born with — 64 and 28, which crashed the
    /// reader. Declaring the struct fixed it without making anything check it. Reordering a
    /// field compiles, runs, and reads a slice of a pointer as an account flag: measured on
    /// this machine, that turns « compte invité désactivé » into « compte invité actif » and
    /// moves two counts, all of them plausible numbers no band would reject.
    /// </para>
    ///
    /// <para>
    /// <c>sizeof</c> and pointer arithmetic, never <c>Marshal.SizeOf</c> or
    /// <c>Marshal.OffsetOf</c>: those read field metadata at run time, which is exactly the
    /// reflection Native AOT does not have (ADR-001). Both expressions here are resolved at
    /// compile time.
    /// </para>
    /// </summary>
    public static unsafe (int Size, int FlagsOffset) UserInfo1Layout()
    {
        UserInfo1 probe = default;
        return (sizeof(UserInfo1), (int)((byte*)&probe.Flags - (byte*)&probe));
    }

    /// <summary>
    /// One surface of the read: it fills in the facts it can establish and answers with what
    /// stopped it, or <see langword="null"/> when nothing did.
    /// </summary>
    internal delegate PolicyGap? PolicySurface(Dictionary<string, string> facts);

    /// <summary>
    /// The four surfaces of this read, each declaring what it establishes.
    ///
    /// <para>
    /// A table rather than four calls in a row, and that is the correction rather than its
    /// decoration: the composition below — not the surface — records what a missing fact is
    /// missing for, so a fifth surface added here inherits the channel instead of having to
    /// remember it, and one added anywhere else does not run at all. Exactly the argument
    /// <see cref="Enumerate"/> was written on one issue earlier: a discipline every call site
    /// has to repeat is a discipline the next call site drops.
    /// </para>
    /// </summary>
    private static readonly (string[] Facts, PolicySurface Read)[] Surfaces =
    [
        ([
            PolicyFactNames.PasswordMinLength,
            PolicyFactNames.PasswordHistoryLength,
            PolicyFactNames.PasswordMaxAgeDays,
        ], ReadPasswordPolicy),

        ([
            PolicyFactNames.LockoutThreshold,
            PolicyFactNames.LockoutDurationMinutes,
        ], ReadLockoutPolicy),

        ([
            PolicyFactNames.AccountsWithoutPassword,
            PolicyFactNames.AccountsPasswordNeverExpires,
            PolicyFactNames.GuestEnabled,
        ], ReadAccounts),

        ([PolicyFactNames.LocalAdminCount], ReadAdminGroup),
    ];

    /// <summary>
    /// What each surface claims, kept in the table's own grouping.
    ///
    /// <para>
    /// The grouping is the part a test cannot invent: three of the four surfaces owe more
    /// than one fact — eight of the nine shipped — and one <c>NetUserModalsGet</c> answers
    /// for all of a group or for none of it. A composition that named only the first fact of
    /// a failed surface would be exactly the silence this file exists to close, and it is
    /// invisible to any test built from one-fact surfaces of its own making.
    /// </para>
    /// </summary>
    internal static IReadOnlyList<IReadOnlyList<string>> SurfaceFacts() =>
        [.. Surfaces.Select(surface => (IReadOnlyList<string>)surface.Facts)];

    /// <summary>
    /// Every fact name a surface claims, so a test can hold the table against
    /// <see cref="PolicyFactNames"/>: a fact declared there and claimed by nobody has no
    /// surface, therefore no gap, therefore no way of saying why it is missing.
    /// </summary>
    internal static IReadOnlyList<string> DeclaredFacts() =>
        [.. SurfaceFacts().SelectMany(facts => facts)];

    public PolicyFacts Read() => Compose(Surfaces);

    /// <summary>
    /// What a surface that answered without failing and without establishing its fact has to
    /// say. There is no code to print and none is borrowed: the alternative is to attribute
    /// the silence to the last call made, which may not be the one that gave up.
    /// </summary>
    private const string Unestablished =
        "Lecture terminée sans code d'erreur, et le fait n'a pas été établi.";

    /// <summary>
    /// Runs every surface into one dictionary and records, beside it, why each fact that is
    /// missing is missing.
    ///
    /// <para>
    /// The line this replaces was <c>facts.Count == 0 ? PolicyFacts.AccessDenied : new
    /// PolicyFacts(facts)</c>, and it was wrong twice over. A denial was deduced from a count
    /// and never from a code, so an unreachable <c>netapi32</c> reported missing privileges —
    /// the invariant CONTRIBUTING records. And a partial read was indistinguishable from a
    /// complete one: one surface answering made the count non-zero, and the surfaces that had
    /// refused left no trace at all.
    /// </para>
    /// </summary>
    internal static PolicyFacts Compose(
        IReadOnlyList<(string[] Facts, PolicySurface Read)> surfaces)
    {
        var facts = new Dictionary<string, string>(StringComparer.Ordinal);
        var gaps = new Dictionary<string, string>(StringComparer.Ordinal);
        var failed = 0;
        var refused = 0;

        foreach (var (names, read) in surfaces)
        {
            var gap = read(facts);

            if (gap is { } failure)
            {
                failed++;
                refused += failure.Refused ? 1 : 0;
            }

            // Driven by what is absent once the surface is done, rather than by what it
            // returned. A surface that answers « no error » and establishes nothing all the
            // same is then named too — the shape ReadAdminGroup has whenever the group name
            // does not resolve, which it had been taking in silence.
            foreach (var name in names)
            {
                if (!facts.ContainsKey(name))
                {
                    gaps[name] = gap?.Reason ?? Unestablished;
                }
            }
        }

        // A refusal is claimed only where the operating system said so, and only where
        // nothing at all was read: one surface refusing out of four leaves the three that
        // answered perfectly usable, and calling the whole read refused would throw them away
        // to describe the fourth.
        var denied = facts.Count == 0 && failed > 0 && refused == failed;

        // Null and not an empty map when nothing is missing, so that a capture of a machine
        // that answered everything is what such a capture has always been.
        return new PolicyFacts(facts, denied, gaps.Count == 0 ? null : gaps);
    }

    /// <summary>
    /// What a netapi32 call that established nothing has to say for itself: its code, or the
    /// absence of a buffer under a code that claimed success — which is not a code at all,
    /// and saying « échec 0 » of it would be nonsense.
    /// </summary>
    private static PolicyGap Missing(string call, int status, IntPtr buffer) =>
        status == NerrSuccess && buffer == IntPtr.Zero
            ? new PolicyGap($"{call} : aucun tampon rendu", Refused: false)
            : PolicyGap.Of(call, status);

    private const string PasswordPolicyCall = "NetUserModalsGet(niveau 0)";

    /// <summary>
    /// The password policy — and, with its pair below, a buffer released on every path out.
    ///
    /// <para>
    /// The release is tied to the <em>allocation</em> and not to the status code, which is the
    /// shape <see cref="Enumerate"/> already had and the accessory half of #173. Both reads
    /// used to return through <c>Missing(…)</c> before entering the <c>try</c>, so the
    /// path « netapi32 failed <em>and</em> handed back a buffer » left it unfreed. That path is
    /// unreachable by contract — <c>NetUserModalsGet</c> does not allocate on failure, so
    /// <c>buffer</c> is <c>IntPtr.Zero</c> there and the guard below never fires — which is why
    /// this is a defensive free and not a measured leak. It is written down because the
    /// alternative is rediscovering it as a finding every time someone reads the file, which is
    /// what the issue asked for; and because a contract nobody re-checks is exactly what the
    /// rest of #173 was about. The file's own docstring promises the buffers are freed, and
    /// « freed unless netapi32 does something it says it will not do » is a weaker promise than
    /// the one written at the top.
    /// </para>
    /// </summary>
    private static unsafe PolicyGap? ReadPasswordPolicy(Dictionary<string, string> facts)
    {
        var status = NetUserModalsGet(null, 0, out var buffer);

        try
        {
            if (status != NerrSuccess || buffer == IntPtr.Zero)
            {
                return Missing(PasswordPolicyCall, status, buffer);
            }

            var info = *(UserModalsInfo0*)buffer;

            facts[PolicyFactNames.PasswordMinLength] = info.MinPasswordLength.ToString();
            facts[PolicyFactNames.PasswordHistoryLength] = info.PasswordHistoryLength.ToString();

            // TIMEQ_FOREVER means "never expires". Rendering it as 0 days would be
            // ambiguous: the rule distinguishes "no expiration" from a threshold that
            // is too long.
            facts[PolicyFactNames.PasswordMaxAgeDays] = info.MaxPasswordAge == TimeqForever
                ? "never"
                : (info.MaxPasswordAge / 86400).ToString();
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NetApiBufferFree(buffer);
            }
        }

        return null;
    }

    private const string LockoutPolicyCall = "NetUserModalsGet(niveau 3)";

    /// <summary>The pair of <see cref="ReadPasswordPolicy"/>, and the same release shape.</summary>
    private static unsafe PolicyGap? ReadLockoutPolicy(Dictionary<string, string> facts)
    {
        var status = NetUserModalsGet(null, 3, out var buffer);

        try
        {
            if (status != NerrSuccess || buffer == IntPtr.Zero)
            {
                return Missing(LockoutPolicyCall, status, buffer);
            }

            var info = *(UserModalsInfo3*)buffer;

            facts[PolicyFactNames.LockoutThreshold] = info.LockoutThreshold.ToString();
            facts[PolicyFactNames.LockoutDurationMinutes] = (info.LockoutDuration / 60).ToString();
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NetApiBufferFree(buffer);
            }
        }

        return null;
    }

    /// <summary>
    /// One call of a netapi32 enumeration, with the resume handle it carries between calls.
    /// </summary>
    internal delegate int NetEnumeration(ref nint resume, out IntPtr buffer, out int read);

    /// <summary>
    /// Runs a netapi32 enumeration to its end, handing every batch to
    /// <paramref name="consume"/> and freeing what the API allocated on every path out.
    ///
    /// <para>
    /// <b>Why the walk is here and not at each call site.</b> Both callers had the same two
    /// bugs, because both had written the same three lines: <c>if (status != 0) return;</c>
    /// before the <c>try</c>. On <c>ERROR_MORE_DATA</c> netapi32 <em>has</em> allocated the
    /// buffer and filled part of it, so that early return leaked it — the leak the docstring
    /// at the top of this file promises to avoid — and threw away a batch of real accounts,
    /// leaving three facts unestablished. A truncated read presenting itself as a missing
    /// one. Written once, the buffer's release is tied to its allocation rather than to the
    /// status code, and a third enumeration added later inherits both.
    /// </para>
    ///
    /// <para>
    /// <b>The resume handle is the point of <c>ERROR_MORE_DATA</c>.</b> It does not mean
    /// « failed », it means « here is part of the answer, ask again with this ». Both call
    /// sites were discarding it into <c>out _</c>, so the continuation the API offers was
    /// not merely unused, it was unreachable.
    /// </para>
    /// </summary>
    /// <returns>
    /// <see langword="null"/> when the enumeration completed, otherwise what stopped it. A
    /// caller that gets a gap has seen only part of the machine and must establish nothing: a
    /// count drawn from a truncated walk is a plausible number that is wrong, which is worse
    /// than an absent fact.
    ///
    /// <para>
    /// The reason and not a bare « non ». This walk is the only place that sees the status
    /// netapi32 stopped on, so a boolean return threw the code away before any caller could
    /// name it — and an unnamed failure is what the empty dictionary above then reported as a
    /// denial (#160).
    /// </para>
    /// </returns>
    internal static PolicyGap? Enumerate(
        string call, NetEnumeration step, Action<IntPtr, int> consume, Action<IntPtr> free)
    {
        nint resume = 0;

        for (var batch = 0; batch < MaxBatches; batch++)
        {
            var status = step(ref resume, out var buffer, out var read);

            try
            {
                // Nothing allocated is nothing to walk and nothing to release, whatever the
                // status says. Kept ahead of the codes so that a netapi32 that answers
                // ERROR_MORE_DATA without a buffer cannot spin here.
                if (buffer == IntPtr.Zero
                    || (status != NerrSuccess && status != ErrorMoreData))
                {
                    return Missing(call, status, buffer);
                }

                consume(buffer, read);

                if (status == NerrSuccess)
                {
                    return null;
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    free(buffer);
                }
            }
        }

        // Still asking after MaxBatches: the enumeration is not converging, and the caller
        // gets nothing rather than a partial count. A resumption without a ceiling is the
        // netapi32 spelling of an enumeration that never gives the scan back.
        //
        // Not a refusal, and there is no code to print: netapi32 never failed, it simply
        // never finished. Elevation does nothing about that, so the sentence says what
        // happened instead of borrowing a word that would send someone to try.
        return new PolicyGap(
            $"{call} : {MaxBatches} appels sans fin d'énumération", Refused: false);
    }

    /// <summary>The same walk, freeing through netapi32 rather than through a test double.</summary>
    private static PolicyGap? Enumerate(
        string call, NetEnumeration step, Action<IntPtr, int> consume) =>
        Enumerate(call, step, consume, buffer => NetApiBufferFree(buffer));

    private static unsafe PolicyGap? ReadAccounts(Dictionary<string, string> facts)
    {
        var withoutPassword = 0;
        var neverExpires = 0;
        var guestEnabled = false;

        if (Enumerate("NetUserEnum", Batch, Count) is { } gap)
        {
            return gap;
        }

        facts[PolicyFactNames.AccountsWithoutPassword] = withoutPassword.ToString();
        facts[PolicyFactNames.AccountsPasswordNeverExpires] = neverExpires.ToString();
        facts[PolicyFactNames.GuestEnabled] = guestEnabled ? "true" : "false";

        return null;

        // Level 1: name and flags in a single pass.
        static int Batch(ref nint resume, out IntPtr buffer, out int read)
        {
            var handle = (int)resume;

            var status = NetUserEnum(null, 1, FilterNormalAccount, out buffer,
                MaxPreferredLength, out read, out _, ref handle);

            resume = handle;

            return status;
        }

        void Count(IntPtr buffer, int read)
        {
            var entries = (UserInfo1*)buffer;

            for (var i = 0; i < read; i++)
            {
                var entry = entries[i];
                var name = Marshal.PtrToStringUni(entry.Name) ?? string.Empty;

                // A disabled account poses no risk: counting it would inflate the
                // findings without adding anything.
                if ((entry.Flags & UfAccountDisable) != 0)
                {
                    continue;
                }

                if ((entry.Flags & UfPasswordNotRequired) != 0)
                {
                    withoutPassword++;
                }

                if ((entry.Flags & UfDontExpirePassword) != 0)
                {
                    neverExpires++;
                }

                // The guest account has RID 501, but its name varies with the
                // language. Name comparison covers the common cases; a deliberate
                // rename escapes it, which is a known and documented limitation.
                if (name.Equals("Guest", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Invité", StringComparison.OrdinalIgnoreCase))
                {
                    guestEnabled = true;
                }
            }
        }
    }

    /// <summary>
    /// Members of the Administrators group. The group name depends on the Windows
    /// language: it is resolved from its well-known SID so the rule also holds on a
    /// French-language machine.
    /// </summary>
    private static PolicyGap? ReadAdminGroup(Dictionary<string, string> facts)
    {
        var groupName = ResolveAdministratorsGroupName();
        if (groupName is null)
        {
            // No netapi32 code to print: the call was never made. The step that failed is
            // named rather than the enumeration's, which would be a lie, and the group is
            // not — the machine's own word for it is the one string here that would need
            // scrubbing out of a capture, and it buys nothing.
            return new PolicyGap(
                "SecurityIdentifier.Translate : le nom du groupe Administrateurs n'a pas été "
                + "résolu depuis son SID bien connu",
                Refused: false);
        }

        var members = 0;

        if (Enumerate("NetLocalGroupGetMembers", Batch, (_, read) => members += read) is { } gap)
        {
            return gap;
        }

        facts[PolicyFactNames.LocalAdminCount] = members.ToString();

        return null;

        int Batch(ref nint resume, out IntPtr buffer, out int read) =>
            NetLocalGroupGetMembers(null, groupName, 0, out buffer,
                MaxPreferredLength, out read, out _, ref resume);
    }

    /// <summary>
    /// The Administrators group name depends on the Windows language — "Administrateurs"
    /// in French. It is resolved from its well-known SID so the rule holds on any
    /// installation.
    ///
    /// Uses the managed API rather than LookupAccountSid: the P/Invoke source generator
    /// does not support marshalling character buffers, and SecurityIdentifier does the
    /// same job without native code to maintain.
    /// </summary>
    private static string? ResolveAdministratorsGroupName()
    {
        try
        {
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var account = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;

            // "BUILTIN\Administrateurs" -> "Administrateurs".
            var separator = account.LastIndexOf('\\');
            return separator >= 0 ? account[(separator + 1)..] : account;
        }
        catch (Exception)
        {
            // Without a resolved group name the fact is not produced: the
            // corresponding rule will report "not verifiable", never a failure.
            return null;
        }
    }
}
