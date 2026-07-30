using System.Diagnostics;
using System.Globalization;
using System.Reflection;
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

        // The reason is quoted rather than left to be guessed: it is what the read records
        // beside each fact it could not establish, and reporting the name alone was the
        // silence #160 closed.
        var missing = expected
            .Where(name => facts.Find(name) is null)
            .Select(name => $"{name} ({facts.WhyMissing(name) ?? "sans raison enregistrée"})")
            .ToList();

        Assert.True(missing.Count == 0,
            $"Fait(s) de politique non établi(s) : {string.Join(", ", missing)}. Chacun rend "
            + "un contrôle livré non vérifiable.");
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

    // ---------------------------------------------------------------------------------
    // What the read says when it did not read. Driven through Compose rather than through
    // the machine: netapi32 answers on this workstation, and the failures below are the
    // ones that cannot be provoked from outside.
    // ---------------------------------------------------------------------------------

    private const int ErrorRpcUnavailable = 1722;   // le serveur RPC n'est pas disponible

    /// <summary>One surface of the read, as the composition takes them.</summary>
    private static (string[] Facts, LiveSecurityPolicyProvider.PolicySurface Read) Surface(
        string[] facts, LiveSecurityPolicyProvider.PolicySurface read) => (facts, read);

    /// <summary>A surface that establishes one fact and reports nothing missing.</summary>
    private static (string[] Facts, LiveSecurityPolicyProvider.PolicySurface Read) Establishes(
        string fact, string value) =>
        Surface([fact], facts =>
        {
            facts[fact] = value;
            return null;
        });

    /// <summary>
    /// The defect this whole channel exists for: an empty dictionary used to be reported as a
    /// denial, and nothing had established one.
    ///
    /// <para>
    /// The old line read <c>facts.Count == 0 ? PolicyFacts.AccessDenied : …</c>, so a
    /// <c>netapi32</c> that could not be reached at all — <c>RPC_S_SERVER_UNAVAILABLE</c>
    /// here, and every other code alike — came back as « accès refusé », which sends an
    /// operator to re-run elevated against a failure elevation cannot touch. That is the
    /// invariant CONTRIBUTING records, and the one #129 and #154 restored on the two
    /// interfaces beside this one.
    /// </para>
    /// </summary>
    [Fact]
    public void A_read_that_established_nothing_reports_the_code_instead_of_a_refusal()
    {
        var facts = LiveSecurityPolicyProvider.Compose(
        [
            Surface([PolicyFactNames.PasswordMinLength],
                _ => PolicyGap.Of("NetUserModalsGet(niveau 0)", ErrorRpcUnavailable)),
            Surface([PolicyFactNames.LocalAdminCount],
                _ => PolicyGap.Of("NetLocalGroupGetMembers", ErrorRpcUnavailable)),
        ]);

        Assert.False(facts.Denied,
            "Zéro fait établi rendu comme un refus alors que netapi32 a rendu 1722 : "
            + "l'opérateur est envoyé relancer en administrateur contre une panne que "
            + "l'élévation ne répare pas.");

        Assert.Equal("NetUserModalsGet(niveau 0) : échec 1722",
            facts.WhyMissing(PolicyFactNames.PasswordMinLength));
        Assert.Equal("NetLocalGroupGetMembers : échec 1722",
            facts.WhyMissing(PolicyFactNames.LocalAdminCount));
    }

    /// <summary>
    /// The other side of the same test, without which the one above is satisfied by a read
    /// that never says « refusé » at all: <c>ERROR_ACCESS_DENIED</c> is a refusal, is called
    /// one, and is the only code that is.
    /// </summary>
    [Fact]
    public void A_read_every_surface_refused_is_the_only_one_called_a_refusal()
    {
        var facts = LiveSecurityPolicyProvider.Compose(
        [
            Surface([PolicyFactNames.PasswordMinLength],
                _ => PolicyGap.Of("NetUserModalsGet(niveau 0)", ErrorAccessDenied)),
            Surface([PolicyFactNames.LocalAdminCount],
                _ => PolicyGap.Of("NetLocalGroupGetMembers", ErrorAccessDenied)),
        ]);

        Assert.True(facts.Denied,
            "Toutes les surfaces ont rendu ERROR_ACCESS_DENIED et la lecture ne se dit pas "
            + "refusée : « relancer en administrateur » est ici le bon conseil, et il est perdu.");

        Assert.Equal("NetUserModalsGet(niveau 0) : accès refusé (5)",
            facts.WhyMissing(PolicyFactNames.PasswordMinLength));
    }

    /// <summary>
    /// The worse half of #160: a partial read was indistinguishable from a complete one. One
    /// surface answering was enough to make <c>facts.Count != 0</c>, and the three that had
    /// refused disappeared without trace — six shipped controls turning « non vérifiable »
    /// with nothing said, on a report that otherwise looked whole.
    ///
    /// <para>
    /// What was read stays read, which is the half that is not negotiable either:
    /// <c>ScheduledTaskRead.Partial</c> and <c>WmiRead.Partial</c> both keep their inventory
    /// and name the gap beside it, and dropping the password policy because the group
    /// enumeration refused would trade one silence for another.
    /// </para>
    /// </summary>
    [Fact]
    public void A_partial_read_keeps_what_it_read_and_names_what_it_did_not()
    {
        var facts = LiveSecurityPolicyProvider.Compose(
        [
            Establishes(PolicyFactNames.PasswordMinLength, "14"),
            Surface([PolicyFactNames.LocalAdminCount],
                _ => PolicyGap.Of("NetLocalGroupGetMembers", ErrorAccessDenied)),
        ]);

        Assert.Equal("14", facts.Find(PolicyFactNames.PasswordMinLength));
        Assert.Null(facts.WhyMissing(PolicyFactNames.PasswordMinLength));

        Assert.Equal("NetLocalGroupGetMembers : accès refusé (5)",
            facts.WhyMissing(PolicyFactNames.LocalAdminCount));

        Assert.False(facts.Denied,
            "Une surface refusée sur deux rend la lecture entière « refusée » : les faits "
            + "réellement établis deviennent non vérifiables avec elle.");
    }

    /// <summary>
    /// A surface owes several facts, and a failed one owes a reason for every single one.
    ///
    /// <para>
    /// Run on the real table's own grouping rather than on surfaces made up here, because the
    /// grouping is the whole of what is being checked: <c>ReadPasswordPolicy</c> owes three
    /// facts, <c>ReadLockoutPolicy</c> two, <c>ReadAccounts</c> three — eight of the nine
    /// facts — and one <c>NetUserModalsGet</c> answers for a whole group or for none of it.
    /// Written with one-fact surfaces, every assertion of this section passed while the loop
    /// that names the rest of a group was never once executed: under <c>names.Take(1)</c> a
    /// refused level-0 modals read named <c>password.minLength</c> and left
    /// <c>password.historyLength</c> and <c>password.maxAgeDays</c> in exactly the silence
    /// #160 closes — five of the nine facts losing their reason, and with them two of the six
    /// shipped <c>type: policy</c> rules, <c>WIN-ACC-005</c> and <c>WIN-ACC-003</c>, coming
    /// back <c>Observed: null</c> (second review of #160).
    /// </para>
    /// </summary>
    [Fact]
    public void Every_fact_a_failed_surface_owed_is_named_and_not_just_its_first()
    {
        var grouping = LiveSecurityPolicyProvider.SurfaceFacts();

        // The premise, asserted rather than assumed: split the table into nine one-fact
        // surfaces and this test compares nothing again.
        Assert.Contains(grouping, group => group.Count > 1);

        var facts = LiveSecurityPolicyProvider.Compose(
            [.. grouping.Select(group => Surface([.. group],
                _ => PolicyGap.Of("NetUserModalsGet(niveau 0)", ErrorRpcUnavailable)))]);

        var silent = LiveSecurityPolicyProvider.DeclaredFacts()
            .Where(name => facts.WhyMissing(name) is null)
            .ToList();

        Assert.True(silent.Count == 0,
            $"Fait(s) dû(s) par une surface en échec et laissé(s) sans raison : "
            + $"{string.Join(", ", silent)}. La règle qui les lit redevient « non vérifiable » "
            + "sans un mot, ce que #160 ferme.");

        Assert.Equal("NetUserModalsGet(niveau 0) : échec 1722",
            facts.WhyMissing(PolicyFactNames.PasswordHistoryLength));
    }

    /// <summary>
    /// A read refused in part and broken in part is not a refusal.
    ///
    /// <para>
    /// The discriminating case for the third conjunct, and the only one that separates
    /// « toutes les surfaces en échec ont rendu <c>ERROR_ACCESS_DENIED</c> » from « une l'a
    /// rendu » : nothing established, one surface refused, one stopped by
    /// <c>RPC_S_SERVER_UNAVAILABLE</c>. Written as <c>refused &gt; 0</c> the read calls itself
    /// refused and sends an operator to re-run elevated against a netapi32 that is not there —
    /// and every other test of this section is caught by the <c>facts.Count == 0</c> conjunct
    /// beside it, so none of them noticed (second review of #160).
    /// </para>
    /// </summary>
    [Fact]
    public void A_read_refused_in_part_and_broken_in_part_is_not_called_a_refusal()
    {
        var facts = LiveSecurityPolicyProvider.Compose(
        [
            Surface([PolicyFactNames.PasswordMinLength],
                _ => PolicyGap.Of("NetUserModalsGet(niveau 0)", ErrorAccessDenied)),
            Surface([PolicyFactNames.LocalAdminCount],
                _ => PolicyGap.Of("NetLocalGroupGetMembers", ErrorRpcUnavailable)),
        ]);

        Assert.False(facts.Denied,
            "Une surface refusée et une cassée, et la lecture entière se dit « refusée » : "
            + "« relancer en administrateur » ne peut rien pour la seconde, et c'est "
            + "l'invariant que cette correction rétablit.");

        // Each half keeps its own word, which is the point of keying by fact rather than
        // writing one sentence for the read.
        Assert.Equal("NetUserModalsGet(niveau 0) : accès refusé (5)",
            facts.WhyMissing(PolicyFactNames.PasswordMinLength));
        Assert.Equal("NetLocalGroupGetMembers : échec 1722",
            facts.WhyMissing(PolicyFactNames.LocalAdminCount));
    }

    /// <summary>
    /// The gap is derived from what is absent at the end, not from what a surface returned —
    /// so a surface that reports no failure and establishes nothing all the same is named too.
    ///
    /// <para>
    /// That is not a hypothetical shape: <c>ReadAdminGroup</c> gives up before making any
    /// netapi32 call whenever the Administrators group name does not resolve from its
    /// well-known SID, and it did so in silence. There is no code to print in that case, and
    /// « aucun code » is what gets printed rather than a borrowed one.
    /// </para>
    ///
    /// <para>
    /// On the sentence and not merely on « quelque chose » : a reason nobody reads is the
    /// defect one layer up, and <c>Assert.NotNull</c> stays green on the empty string, which
    /// is a fact named without being explained.
    /// </para>
    /// </summary>
    [Fact]
    public void A_surface_that_failed_without_a_code_still_names_the_fact_it_owed()
    {
        var facts = LiveSecurityPolicyProvider.Compose(
            [Surface([PolicyFactNames.LocalAdminCount], _ => null)]);

        Assert.False(facts.Denied);
        Assert.Equal("Lecture terminée sans code d'erreur, et le fait n'a pas été établi.",
            facts.WhyMissing(PolicyFactNames.LocalAdminCount));
    }

    /// <summary>
    /// And a read that established everything records no gap at all — <see langword="null"/>,
    /// not an empty map. It is what makes a capture of a healthy machine identical to one
    /// written before this channel existed, which is the compatibility the unit suite holds
    /// against a versioned fixture.
    /// </summary>
    [Fact]
    public void A_complete_read_records_no_gap_at_all()
    {
        var facts = LiveSecurityPolicyProvider.Compose(
            [Establishes(PolicyFactNames.PasswordMinLength, "14")]);

        Assert.Null(facts.Gaps);
        Assert.False(facts.Denied);
    }

    /// <summary>
    /// The coverage, by construction rather than by a list that was true the day it was
    /// written.
    ///
    /// <para>
    /// A surface declares the facts it establishes, and the composition — not the surface —
    /// records a gap for each one that is missing when it is done. That closes the loop for
    /// the four surfaces of today; what it cannot do on its own is notice a
    /// <em>tenth</em> fact added to <see cref="PolicyFactNames"/> and read by a new rule, with
    /// no surface claiming it: no surface means no gap, means the silence this issue is about,
    /// re-opened one constant at a time.
    /// </para>
    ///
    /// <para>
    /// Equality in both directions, and both matter: a name declared by no surface is an
    /// unestablishable fact, and a name declared by a surface but absent from
    /// <see cref="PolicyFactNames"/> is a free-form string in the one place the project keeps
    /// them out of.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_fact_name_a_rule_can_read_is_claimed_by_exactly_one_surface()
    {
        var declared = LiveSecurityPolicyProvider.DeclaredFacts();

        var named = typeof(PolicyFactNames)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field is { IsLiteral: true, FieldType: { } type } && type == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToList();

        var unclaimed = named.Except(declared, StringComparer.Ordinal).ToList();
        Assert.True(unclaimed.Count == 0,
            $"Fait(s) déclaré(s) dans PolicyFactNames qu'aucune surface n'établit : "
            + $"{string.Join(", ", unclaimed)}. Sans surface, pas de manque nommé : la règle "
            + "qui les lit redevient « non vérifiable » sans un mot.");

        var stray = declared.Except(named, StringComparer.Ordinal).ToList();
        Assert.True(stray.Count == 0,
            $"Nom(s) de fait annoncé(s) par une surface hors de PolicyFactNames : "
            + $"{string.Join(", ", stray)}. Une règle ne peut pas les désigner.");

        // A comparison of two lists is satisfied by two empty lists, and this file has
        // already recorded what an assertion that compared nothing costs.
        Assert.Equal(declared.Count, named.Count);
        Assert.NotEmpty(declared);
    }

    /// <summary>
    /// The third list of the same nine names, and the one nothing else holds:
    /// <see cref="PolicyFacts.Unread"/> answers for every fact at once — a scan wired without
    /// a policy provider, a capture carrying no policy block — and it names them from a
    /// hand-written table, because reading the fields at run time is the reflection Native
    /// AOT does not have (ADR-001).
    ///
    /// <para>
    /// A hand-written list drifts, and a fact missing from it comes back « non vérifiable »
    /// with nothing said, which is the silence this issue closes, re-opened one constant at a
    /// time.
    /// </para>
    ///
    /// <para>
    /// Held against the surfaces rather than against <see cref="PolicyFactNames"/> directly,
    /// which is the stronger of the two things it could say: the guard above already pins the
    /// surfaces to the constants, so this one closes the chain — every name a rule can read is
    /// established by some surface, and every one of those has a reason waiting when no
    /// surface ran at all.
    /// </para>
    /// </summary>
    [Fact]
    public void The_table_that_answers_for_every_fact_at_once_holds_every_fact()
    {
        var established = LiveSecurityPolicyProvider.DeclaredFacts();

        var unanswered = established.Except(PolicyFactNames.All, StringComparer.Ordinal).ToList();
        Assert.True(unanswered.Count == 0,
            $"Fait(s) qu'une surface établit et que PolicyFactNames.All ignore : "
            + $"{string.Join(", ", unanswered)}. Une lecture qui n'a pas eu lieu les laisse "
            + "sans raison, et la règle qui les lit redevient « non vérifiable » sans un mot.");

        var stray = PolicyFactNames.All.Except(established, StringComparer.Ordinal).ToList();
        Assert.True(stray.Count == 0,
            $"Nom(s) dans PolicyFactNames.All qu'aucune surface n'établit : "
            + $"{string.Join(", ", stray)}.");

        Assert.Equal(established.Count, PolicyFactNames.All.Count);
        Assert.NotEmpty(established);
    }

    /// <summary>
    /// A scripted netapi32 enumeration: it hands back the status codes it was given, one per
    /// call, and records what was freed.
    ///
    /// <para>
    /// <c>ERROR_MORE_DATA</c> is not reachable on this machine — a local SAM holds a few
    /// accounts and <c>MAX_PREFERRED_LENGTH</c> asks netapi32 to size the buffer itself — and
    /// the two consequences of mishandling it are both invisible from outside: a leaked
    /// allocation, and three facts silently not established. Neither shows up in the read the
    /// tests above examine, which is why the walk is exercised through a double rather than
    /// through the machine.
    /// </para>
    ///
    /// <para>
    /// The pointers are fabricated and never dereferenced. <c>NetApiBufferFree</c> is a
    /// parameter of the walk for exactly this reason: handing a made-up pointer to the real
    /// one would corrupt the heap instead of failing a test.
    /// </para>
    /// </summary>
    private sealed class Netapi(params int[] statuses)
    {
        public List<IntPtr> Freed { get; } = [];

        public List<int> ResumeHandles { get; } = [];

        public List<int> Batches { get; } = [];

        public int Calls { get; private set; }

        public int Step(ref nint resume, out IntPtr buffer, out int read)
        {
            ResumeHandles.Add((int)resume);

            var status = statuses[Math.Min(Calls, statuses.Length - 1)];

            // A distinct allocation per call, so that a buffer freed twice — or the wrong
            // one freed — is visible rather than plausible.
            buffer = new IntPtr(1000 + Calls);
            read = 2;

            Calls++;
            resume = Calls;

            return status;
        }

        public void Consume(IntPtr buffer, int read) => Batches.Add(read);

        public void Free(IntPtr buffer) => Freed.Add(buffer);
    }

    private const int NerrSuccess = 0;
    private const int ErrorMoreData = 234;      // netapi32 allocated, and there is more
    private const int ErrorAccessDenied = 5;

    /// <summary>
    /// The leak. On <c>ERROR_MORE_DATA</c> netapi32 <b>has</b> allocated the buffer, and the
    /// early return that treated « status is not zero » as « nothing happened » walked past
    /// the only <c>NetApiBufferFree</c> in the method — the very leak this file's own
    /// docstring promises to avoid, on a read that runs once per scan.
    /// </summary>
    [Fact]
    public void A_partially_answered_enumeration_still_frees_what_netapi32_allocated()
    {
        var netapi = new Netapi(ErrorMoreData, NerrSuccess);

        LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", netapi.Step, netapi.Consume, netapi.Free);

        Assert.Equal(netapi.Calls, netapi.Freed.Count);
        Assert.Equal(netapi.Freed.Distinct().Count(), netapi.Freed.Count);
    }

    /// <summary>
    /// The silence beside the leak. <c>ERROR_MORE_DATA</c> means « here is part of the
    /// answer, ask again with this handle » — the resume handle exists for nothing else, and
    /// it was being discarded into <c>out _</c>. Dropping the batch made
    /// <c>accounts.withoutPassword</c>, <c>accounts.passwordNeverExpires</c> and
    /// <c>accounts.guestEnabled</c> vanish at once, so six shipped controls turned « non
    /// vérifiable » with nothing said about why.
    /// </summary>
    [Fact]
    public void A_partially_answered_enumeration_is_resumed_rather_than_dropped()
    {
        var netapi = new Netapi(ErrorMoreData, ErrorMoreData, NerrSuccess);

        Assert.Null(LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", netapi.Step, netapi.Consume, netapi.Free));

        // Every batch counted, not just the last: the accounts of the first call are as real
        // as the ones of the third.
        Assert.Equal([2, 2, 2], netapi.Batches);

        // And the handle netapi32 wrote back was handed to the next call. Starting each call
        // from zero would re-read the first batch for ever.
        Assert.Equal([0, 1, 2], netapi.ResumeHandles);
    }

    /// <summary>
    /// The other half: a walk that could not be completed must establish nothing. A count
    /// taken from a truncated enumeration is a small plausible integer that no band would
    /// reject — the failure shape this provider's tests keep naming — whereas an absent fact
    /// reads as « non vérifiable », which is true.
    ///
    /// <para>
    /// And it now hands the code back rather than a bare « non ». The walk is the only place
    /// that sees the status netapi32 stopped on, so a boolean return threw it away before any
    /// caller could name it (#160).
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_enumeration_frees_its_buffer_and_names_the_refusal()
    {
        var netapi = new Netapi(ErrorAccessDenied);

        var gap = LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", netapi.Step, netapi.Consume, netapi.Free);

        Assert.Equal(new PolicyGap("NetUserEnum : accès refusé (5)", Refused: true), gap);
        Assert.Empty(netapi.Batches);
        Assert.Single(netapi.Freed);
    }

    /// <summary>
    /// The same walk stopped by a code that is not a refusal. Both halves of the invariant in
    /// one place: the code is printed as itself, and the walk does not call it « refusé » —
    /// which is exactly what the old return, a bare <c>false</c> read as an empty dictionary
    /// read as <c>AccessDenied</c>, ended up doing to it.
    /// </summary>
    [Fact]
    public void An_enumeration_broken_by_another_code_prints_it_rather_than_a_refusal()
    {
        var netapi = new Netapi(ErrorRpcUnavailable);

        var gap = LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", netapi.Step, netapi.Consume, netapi.Free);

        Assert.Equal(new PolicyGap("NetUserEnum : échec 1722", Refused: false), gap);
        Assert.Empty(netapi.Batches);
    }

    /// <summary>
    /// A resumption that never converges ends anyway. Reading <c>ERROR_MORE_DATA</c> as
    /// « call again » is only safe if « again » is bounded: the enumeration that never
    /// completes is the same defect as the WMI enumeration that never returns, and the scan
    /// must come back either way.
    /// </summary>
    [Fact]
    public void An_enumeration_that_never_completes_stops_without_hanging_the_scan()
    {
        var netapi = new Netapi(ErrorMoreData);

        var gap = LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", netapi.Step, netapi.Consume, netapi.Free);

        // Named, and not as a refusal: an enumeration that will not converge is a fault of
        // the API or of the machine, and elevation does nothing about it.
        Assert.NotNull(gap);
        Assert.False(gap.Value.Refused);
        Assert.Contains("NetUserEnum", gap.Value.Reason, StringComparison.Ordinal);

        Assert.InRange(netapi.Calls, 1, 1000);
        Assert.Equal(netapi.Calls, netapi.Freed.Count);
    }

    /// <summary>
    /// A netapi32 that claims success and hands back nothing. There is no code to print —
    /// zero <em>is</em> the success code — so « échec 0 » would be a sentence naming a failure
    /// that the API says did not happen, printed at the operator who has to act on it.
    ///
    /// <para>
    /// The branch was written with a docstring saying exactly that and covered by nothing:
    /// the scripted enumeration above always allocates, and the two modals reads reach this
    /// same helper only through the machine, which does answer. Collapsing it to
    /// <c>PolicyGap.Of(call, status)</c> left all of 954 + 140 green (second review of #160).
    /// </para>
    /// </summary>
    [Fact]
    public void An_enumeration_that_succeeded_without_a_buffer_says_so_rather_than_echec_zero()
    {
        var freed = new List<IntPtr>();

        var gap = LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", NoBuffer, (_, _) => Assert.Fail(
                "Un tampon nul a été parcouru : le lecteur déréférence IntPtr.Zero."),
            freed.Add);

        Assert.Equal(new PolicyGap("NetUserEnum : aucun tampon rendu", Refused: false), gap);

        // Nothing was allocated, so nothing is handed to NetApiBufferFree either.
        Assert.Empty(freed);
    }

    /// <summary>Success, and no buffer with it — the shape the test above needs.</summary>
    private static int NoBuffer(ref nint resume, out IntPtr buffer, out int read)
    {
        buffer = IntPtr.Zero;
        read = 0;
        return NerrSuccess;
    }

    /// <summary>
    /// The ordinary path, unchanged: one call, one batch, one buffer freed. Without this the
    /// walk could be « always resume » or « always refuse » and the three tests above would
    /// still pass.
    /// </summary>
    [Fact]
    public void A_complete_enumeration_reads_one_batch_and_frees_it()
    {
        var netapi = new Netapi(NerrSuccess);

        Assert.Null(LiveSecurityPolicyProvider.Enumerate(
            "NetUserEnum", netapi.Step, netapi.Consume, netapi.Free));

        Assert.Equal(1, netapi.Calls);
        Assert.Equal([2], netapi.Batches);
        Assert.Single(netapi.Freed);
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
