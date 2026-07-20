using System.Runtime.InteropServices;
using System.Security.Principal;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Politique de comptes locaux, par <c>netapi32</c>.
///
/// Même famille d'API que <c>NetGetJoinInformation</c>, déjà éprouvée : la question
/// WMI/AOT ouverte depuis M0 reste entière, mais elle ne bloque pas ce lot non plus.
///
/// Toute mémoire rendue par ces appels doit être libérée par <c>NetApiBufferFree</c>,
/// sous peine d'une fuite qu'un scan répété rendrait visible.
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

    // Structures natives declarees plutot que parcourues a coups de decalages calcules
    // a la main. La premiere version le faisait, et se trompait : USER_INFO_1 fait
    // 56 octets et non 64, son champ « flags » est au decalage 40 et non 28, et la
    // politique de mot de passe commence au decalage 0. Le lecteur plantait. Ici c'est
    // le compilateur qui calcule taille et decalages -- sans reflexion, donc compatible
    // Native AOT.

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

        // Aucun fait établi : l'API a refusé partout. Le signaler évite qu'une règle
        // conclue sur un dictionnaire vide.
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

            // TIMEQ_FOREVER signifie « n'expire jamais ». Le rendre en 0 jour serait
            // ambigu : la regle distingue « pas d'expiration » d'un seuil trop long.
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
        // Niveau 1 : nom et drapeaux en une seule passe.
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

                // Un compte desactive ne represente aucun risque : le compter
                // gonflerait les constats sans rien apporter.
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

                // Le compte invite porte le RID 501, mais son nom varie selon la
                // langue. La comparaison par nom couvre les cas courants ; un
                // renommage delibere y echappe, ce qui est assume et documente.
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
    /// Membres du groupe Administrateurs. Le nom du groupe dépend de la langue de
    /// Windows : il est résolu depuis son SID connu, pour que la règle vaille aussi
    /// sur une machine en français.
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
    /// Le nom du groupe Administrateurs dépend de la langue de Windows — « Administrateurs »
    /// en français. Il est résolu depuis son SID connu, pour que la règle vaille sur
    /// n'importe quelle installation.
    ///
    /// Passe par l'API managée plutôt que par LookupAccountSid : le générateur de
    /// P/Invoke ne prend pas en charge le marshalling de tampons de caractères, et
    /// SecurityIdentifier fait le même travail sans code natif à maintenir.
    /// </summary>
    private static string? ResolveAdministratorsGroupName()
    {
        try
        {
            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var account = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;

            // « BUILTIN\Administrateurs » -> « Administrateurs ».
            var separator = account.LastIndexOf('\\');
            return separator >= 0 ? account[(separator + 1)..] : account;
        }
        catch (Exception)
        {
            // Sans nom de groupe résolu, le fait n'est pas produit : la règle
            // correspondante rendra « non vérifiable », jamais un échec.
            return null;
        }
    }
}
