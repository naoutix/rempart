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

    private const int UfAccountDisable = 0x0002;
    private const int UfPasswordNotRequired = 0x0020;
    private const int UfDontExpirePassword = 0x10000;

    private const uint TimeqForever = 0xFFFFFFFF;

    [LibraryImport("netapi32.dll", EntryPoint = "NetUserEnum")]
    private static partial int NetUserEnum(
        [MarshalAs(UnmanagedType.LPWStr)] string? server, int level, int filter,
        out IntPtr buffer, int prefMaxLen, out int read, out int total, out int resume);

    [LibraryImport("netapi32.dll", EntryPoint = "NetUserModalsGet")]
    private static partial int NetUserModalsGet(
        [MarshalAs(UnmanagedType.LPWStr)] string? server, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll", EntryPoint = "NetLocalGroupGetMembers")]
    private static partial int NetLocalGroupGetMembers(
        [MarshalAs(UnmanagedType.LPWStr)] string? server,
        [MarshalAs(UnmanagedType.LPWStr)] string group, int level,
        out IntPtr buffer, int prefMaxLen, out int read, out int total, out IntPtr resume);

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

    private static unsafe void ReadAccounts(Dictionary<string, string> facts)
    {
        // Level 1: name and flags in a single pass.
        if (NetUserEnum(null, 1, FilterNormalAccount, out var buffer,
                MaxPreferredLength, out var read, out _, out _) != 0 || buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var entries = (UserInfo1*)buffer;
            var withoutPassword = 0;
            var neverExpires = 0;
            var guestEnabled = false;

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

            facts[PolicyFactNames.AccountsWithoutPassword] = withoutPassword.ToString();
            facts[PolicyFactNames.AccountsPasswordNeverExpires] = neverExpires.ToString();
            facts[PolicyFactNames.GuestEnabled] = guestEnabled ? "true" : "false";
        }
        finally
        {
            NetApiBufferFree(buffer);
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

        if (NetLocalGroupGetMembers(null, groupName, 0, out var buffer,
                MaxPreferredLength, out var read, out _, out _) != 0 || buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            facts[PolicyFactNames.LocalAdminCount] = read.ToString();
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
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
