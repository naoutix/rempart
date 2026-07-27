using System.Diagnostics;
using System.Globalization;
using Rempart.Core.Providers;
using Rempart.Windows;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// The account policy read, against the real <c>netapi32</c>.
///
/// <para>
/// Seventy lines of unsafe struct walking, and — until this file — nought of them covered.
/// The coverage figure named it beside <c>LiveScheduledTaskProvider</c> as the least measured
/// code in the layer, and six shipped controls read nothing but its output, one of them
/// <c>critical</c>: <c>WIN-ACC-002</c> passes when <c>accounts.withoutPassword</c> is
/// <b>zero</b>. That is the shape this repository keeps calling the dangerous one — a value
/// that is plausible and wrong looks exactly like a machine in good order, and here the good
/// answer is the same one a failed read would produce.
/// </para>
///
/// <para>
/// The offsets are not hypothetical either. The first version of this provider walked the
/// buffers with hand-computed offsets, put <c>Flags</c> at 28 instead of 40 and sized
/// <c>USER_INFO_1</c> at 64 bytes instead of 56; the comment recording that is still in the
/// file. Declared structs made the compiler responsible for the arithmetic — they did not
/// make anything check the result.
/// </para>
///
/// <para>
/// So the password and lockout facts are held against <c>net accounts</c>, which reaches the
/// same policy through a different implementation shipped by Microsoft. Comparing the read
/// with itself would prove nothing; comparing it with the machine's own answer is what makes
/// a wrong offset show up as a disagreement instead of as a plausible number.
/// </para>
/// </summary>
public sealed class LiveSecurityPolicyProviderTests(ITestOutputHelper output)
{
    private readonly PolicyFacts facts = new LiveSecurityPolicyProvider().Read();

    /// <summary>
    /// The test that refuses to go quiet. <c>NetUserModalsGet</c> and <c>NetUserEnum</c> read
    /// the local SAM and need no elevation, so a machine that establishes no fact at all has a
    /// broken read rather than a locked-down configuration — and a class whose every test
    /// stood down on a denied read would report green while proving nothing.
    ///
    /// <para>
    /// Every name is required, not a subset: each missing one is a shipped control that turns
    /// « non vérifiable » without anything saying why, and the four sub-reads fail
    /// independently — the group membership through a different API from the password policy.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_fact_the_controls_read_is_established()
    {
        Assert.False(facts.Denied,
            "Aucun fait de politique établi sur cette machine. Ces lectures n'exigent pas "
            + "l'élévation : six contrôles livrés deviennent « non vérifiables » d'un coup, "
            + "et c'est la lecture qui est en cause, pas la machine.");

        var expected = new[]
        {
            PolicyFactNames.PasswordMinLength,
            PolicyFactNames.PasswordMaxAgeDays,
            PolicyFactNames.PasswordHistoryLength,
            PolicyFactNames.LockoutThreshold,
            PolicyFactNames.LockoutDurationMinutes,
            PolicyFactNames.LocalAdminCount,
            PolicyFactNames.GuestEnabled,
            PolicyFactNames.AccountsWithoutPassword,
            PolicyFactNames.AccountsPasswordNeverExpires,
        };

        var missing = expected.Where(name => facts.Find(name) is null).ToList();

        Assert.True(missing.Count == 0,
            $"Fait(s) de politique non établi(s) : {string.Join(", ", missing)}. Chacun rend "
            + "un contrôle livré non vérifiable, en silence.");
    }

    /// <summary>
    /// The independent half: the same policy, read by <c>net.exe</c>.
    ///
    /// <para>
    /// Matched by row and never by label. <c>net accounts</c> prints its table in the system
    /// language — on the machine this was written on, « Longueur minimale du mot de passe » —
    /// and the rows come out in a fixed order whatever that language is. The same reasoning
    /// as the dynamic port range, and the opposite of DISM, which offers <c>/English</c> and
    /// is pinned on its labels because of it.
    /// </para>
    ///
    /// <para>
    /// Only the rows that are numbers on both sides are compared: « Jamais » and « Aucune »
    /// are how this output spells the special values that the provider renders as
    /// <c>never</c> and as <c>0</c>, and forcing a mapping between two localised words and
    /// two sentinels would be inventing a second parser to check the first. The count of
    /// comparisons is asserted so that the test cannot pass by having compared nothing.
    /// </para>
    /// </summary>
    [Fact]
    public void The_password_and_lockout_facts_agree_with_what_net_accounts_reports()
    {
        var rows = NetAccounts();

        if (rows.Count == 0)
        {
            output.WriteLine(
                "net accounts n'a rien rendu sur cette machine : la confrontation n'a pas "
                + "eu lieu. Contrôle non exécuté.");
            return;
        }

        Assert.True(rows.Count >= 8,
            $"net accounts a rendu {rows.Count} ligne(s) au lieu des neuf attendues : la "
            + "table a changé de forme, et les indices ci-dessous ne désignent plus les mêmes "
            + $"valeurs. Reçu : {string.Join(" | ", rows)}");

        // Row order, fixed across languages: forced logoff, minimum password age, maximum
        // password age, minimum length, history length, lockout threshold, lockout duration,
        // observation window, computer role.
        var pairs = new (int Row, string Fact)[]
        {
            (2, PolicyFactNames.PasswordMaxAgeDays),
            (3, PolicyFactNames.PasswordMinLength),
            (4, PolicyFactNames.PasswordHistoryLength),
            (5, PolicyFactNames.LockoutThreshold),
            (6, PolicyFactNames.LockoutDurationMinutes),
        };

        var compared = 0;
        var disagreements = new List<string>();

        foreach (var (row, fact) in pairs)
        {
            if (!int.TryParse(rows[row], NumberStyles.None, CultureInfo.InvariantCulture,
                    out var reported)
                || !int.TryParse(facts.Find(fact), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var read))
            {
                continue;
            }

            compared++;

            if (reported != read)
            {
                disagreements.Add($"{fact} : netapi32 dit {read}, net accounts dit {reported}");
            }
        }

        Assert.True(compared >= 3,
            $"{compared} valeur(s) comparée(s) seulement : les deux sources ne se recoupent "
            + "presque plus, donc ce test ne confronte plus rien. "
            + $"net accounts : {string.Join(" | ", rows)}");

        Assert.True(disagreements.Count == 0,
            $"Les deux lectures de la même politique divergent : {string.Join(" ; ", disagreements)}. "
            + "Une valeur plausible et fausse est la panne dont cette couche est capable : "
            + "un décalage d'offset ne fait rien échouer, il rend un autre nombre.");
    }

    /// <summary>
    /// Zero cannot be true. A Windows machine always has at least one local administrator —
    /// the built-in account exists even when it is disabled, and the group is never empty —
    /// so a count of zero means the group name was not resolved or the members were not read.
    ///
    /// <para>
    /// That resolution is the one place in this provider that leaves native code: the group
    /// is looked up from its well-known SID through <c>SecurityIdentifier.Translate</c>,
    /// because it is called « Administrateurs » on this machine. It fails inside a
    /// <c>catch</c> that returns null, so the fact simply disappears and <c>WIN-ACC-004</c>
    /// goes unverifiable without a word.
    /// </para>
    /// </summary>
    [Fact]
    public void At_least_one_local_administrator_is_counted()
    {
        var counted = facts.Find(PolicyFactNames.LocalAdminCount);

        Assert.True(int.TryParse(counted, NumberStyles.None, CultureInfo.InvariantCulture,
                out var admins),
            $"Nombre d'administrateurs locaux illisible : « {counted ?? "absent"} ».");

        Assert.True(admins >= 1,
            "Zéro administrateur local compté. Aucune machine Windows n'est dans cet état : "
            + "soit le nom du groupe n'a pas été résolu depuis son SID, soit l'énumération de "
            + "ses membres a échoué — dans les deux cas en silence, et WIN-ACC-004 devient "
            + "non vérifiable.");
    }

    /// <summary>
    /// The three facts <c>net accounts</c> cannot corroborate — they come from the account
    /// enumeration rather than from the policy modals, and no shipped tool prints them as a
    /// number. What is checked is the band: a wrong offset into <c>USER_INFO_1</c> reads part
    /// of a pointer and yields counts that are not small integers.
    ///
    /// <para>
    /// Said plainly, because it is the weak one, and it was measured rather than guessed:
    /// moving <c>Flags</c> to another offset left every assertion below green. What it
    /// actually produced on this machine was <c>guestEnabled</c> flipping to <c>true</c> and
    /// two counts moving — all plausible numbers, none of them out of band. The test that
    /// catches that is the layout one below; this one holds the shapes the rules parse.
    /// </para>
    /// </summary>
    [Fact]
    public void The_account_counts_are_small_integers_and_the_guest_flag_is_a_boolean()
    {
        foreach (var name in new[]
                 {
                     PolicyFactNames.AccountsWithoutPassword,
                     PolicyFactNames.AccountsPasswordNeverExpires,
                     PolicyFactNames.LocalAdminCount,
                 })
        {
            var value = facts.Find(name);

            Assert.True(
                int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var count)
                && count <= 1000,
                $"{name} = « {value ?? "absent"} » : ce n'est pas un nombre de comptes. Un "
                + "décalage dans USER_INFO_1 lit un morceau de pointeur et rend exactement "
                + "cela.");
        }

        var guest = facts.Find(PolicyFactNames.GuestEnabled);
        Assert.True(guest is "true" or "false",
            $"accounts.guestEnabled = « {guest ?? "absent"} », attendu true ou false : "
            + "WIN-ACC-003 compare cette chaîne à « false » et ne reconnaîtrait rien d'autre.");
    }

    /// <summary>
    /// The struct the account enumeration is decoded through, held against the ABI
    /// <c>netapi32</c> publishes: <c>USER_INFO_1</c> is 56 bytes on x64 and its <c>Flags</c>
    /// field sits at offset 40.
    ///
    /// <para>
    /// These are not two numbers copied out of the code they check. They are the layout the
    /// documented structure has — pointer, pointer, two DWORDs, pointer, pointer, DWORD,
    /// pointer — and they are the exact pair the first version of this provider got wrong: 64
    /// and 28, which crashed the reader. Declaring the struct made the compiler compute them;
    /// nothing made anything verify the result, and a field reordered by a later edit
    /// recomputes them silently.
    /// </para>
    ///
    /// <para>
    /// This is the guard the three tests above cannot be: the flags decide whether an account
    /// is disabled, has no password, or never expires, and no tool available without
    /// elevation prints those as numbers to compare against. Measured on this machine, a
    /// <c>Flags</c> read at the wrong offset turns « compte invité désactivé » into « compte
    /// invité actif » — a <c>high</c> finding invented out of a struct field — and leaves
    /// every band and every parse above satisfied.
    /// </para>
    /// </summary>
    [Fact]
    public void The_account_structure_has_the_layout_netapi32_defines()
    {
        var (size, flagsOffset) = LiveSecurityPolicyProvider.UserInfo1Layout();

        Assert.True(size == 56,
            $"USER_INFO_1 fait {size} octets au lieu de 56 : l'énumération avance d'un pas "
            + "qui n'est pas celui du tableau rendu par netapi32, et lit un compte sur deux "
            + "à côté. La première version de ce fichier disait 64, et le lecteur plantait.");

        Assert.True(flagsOffset == 40,
            $"USER_INFO_1.Flags est à l'offset {flagsOffset} au lieu de 40 : ce qui est lu "
            + "comme des drapeaux de compte est un morceau de pointeur. Rien n'échoue, les "
            + "nombres restent plausibles, et « compte invité désactivé » peut devenir "
            + "« compte invité actif ». La première version disait 28.");
    }

    /// <summary>
    /// The values of <c>net accounts</c>, one per row, in the order the tool prints them. The
    /// value is everything after the last colon — the labels are never looked at, and the
    /// separator survives the non-breaking space French Windows puts in front of it.
    /// </summary>
    private static List<string> NetAccounts()
    {
        var startInfo = new ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "net.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        startInfo.ArgumentList.Add("accounts");

        try
        {
            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return [];
            }

            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(30_000))
            {
                return [];
            }

            return process.ExitCode != 0
                ? []
                : [.. output.GetAwaiter().GetResult()
                    .Split('\n')
                    .Where(line => line.Contains(':', StringComparison.Ordinal))
                    .Select(line => line[(line.LastIndexOf(':') + 1)..].Trim())];
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            return [];
        }
    }
}
