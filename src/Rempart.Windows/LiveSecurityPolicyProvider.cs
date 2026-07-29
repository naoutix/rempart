using System.Runtime.InteropServices;
using System.Security.Principal;
using Rempart.Core.Providers;

namespace Rempart.Windows;

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

    public PolicyFacts Read()
    {
        var facts = new Dictionary<string, string>(StringComparer.Ordinal);

        ReadPasswordPolicy(facts);
        ReadLockoutPolicy(facts);
        ReadAccounts(facts);
        ReadAdminGroup(facts);

        // No fact established: the API denied everything. Reporting this prevents a
        // rule from drawing conclusions from an empty dictionary.
        return facts.Count == 0 ? PolicyFacts.AccessDenied : new PolicyFacts(facts);
    }

    private static unsafe void ReadPasswordPolicy(Dictionary<string, string> facts)
    {
        if (NetUserModalsGet(null, 0, out var buffer) != 0 || buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
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
            NetApiBufferFree(buffer);
        }
    }

    private static unsafe void ReadLockoutPolicy(Dictionary<string, string> facts)
    {
        if (NetUserModalsGet(null, 3, out var buffer) != 0 || buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var info = *(UserModalsInfo3*)buffer;

            facts[PolicyFactNames.LockoutThreshold] = info.LockoutThreshold.ToString();
            facts[PolicyFactNames.LockoutDurationMinutes] = (info.LockoutDuration / 60).ToString();
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
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
    /// Whether the enumeration completed. A caller that gets <see langword="false"/> has
    /// seen only part of the machine and must establish nothing: a count drawn from a
    /// truncated walk is a plausible number that is wrong, which is worse than an absent
    /// fact.
    /// </returns>
    internal static bool Enumerate(
        NetEnumeration step, Action<IntPtr, int> consume, Action<IntPtr> free)
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
                    return false;
                }

                consume(buffer, read);

                if (status == NerrSuccess)
                {
                    return true;
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
        return false;
    }

    /// <summary>The same walk, freeing through netapi32 rather than through a test double.</summary>
    private static bool Enumerate(NetEnumeration step, Action<IntPtr, int> consume) =>
        Enumerate(step, consume, buffer => NetApiBufferFree(buffer));

    private static unsafe void ReadAccounts(Dictionary<string, string> facts)
    {
        var withoutPassword = 0;
        var neverExpires = 0;
        var guestEnabled = false;

        if (!Enumerate(Batch, Count))
        {
            return;
        }

        facts[PolicyFactNames.AccountsWithoutPassword] = withoutPassword.ToString();
        facts[PolicyFactNames.AccountsPasswordNeverExpires] = neverExpires.ToString();
        facts[PolicyFactNames.GuestEnabled] = guestEnabled ? "true" : "false";

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
    private static void ReadAdminGroup(Dictionary<string, string> facts)
    {
        var groupName = ResolveAdministratorsGroupName();
        if (groupName is null)
        {
            return;
        }

        var members = 0;

        if (!Enumerate(Batch, (_, read) => members += read))
        {
            return;
        }

        facts[PolicyFactNames.LocalAdminCount] = members.ToString();

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
