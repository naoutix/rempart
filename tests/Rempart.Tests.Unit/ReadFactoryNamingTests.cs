using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// The link between what a read factory is called and the state it hands out.
///
/// <para>
/// Four rounds of review went past factories named <c>Failed</c> or <c>Partial</c> that built
/// <see cref="ReadStatus.AccessDenied"/>, and they were only ever found by reading them one at
/// a time — the fourth round listed eight, this test found twelve on its first run, plus a
/// thirteenth call site that inherited one of them. Nothing tied the name to the field, so the
/// two could drift apart in silence, and a reader of the code — or of the interface summary
/// written above it — had no way to know which was lying. #173 split <c>DirectoryRead</c> and
/// <c>HostsFileRead</c> by hand and left the rest; this is the part that stops the next one
/// being written the same way.
/// </para>
///
/// <para>
/// Discovered rather than listed, which is the whole difference between this and the table in
/// <see cref="ProviderStatusChannelTests"/>: a factory added tomorrow is judged without anyone
/// remembering that this file exists. The reproach the audit of 2026-07-29 keeps making is
/// coverage by enumeration, and a hand-kept list of factories would be one more of them.
/// </para>
///
/// <para>
/// <b>Its first version was discovered and still did not bite, and how is worth keeping.</b> It
/// built each factory once, on stand-in arguments that were empty for every list, and read the
/// status off the one value that came back. So it saw a factory's answer on the input that never
/// occurs and never on the input that does — and the defect of #177 could be put back, on a
/// channel #177 itself lists, in the exact shape this batch adopted for the scheduler:
/// <c>BrowserExtensionRead.Partial</c> returning <see cref="ReadStatus.AccessDenied"/> when its
/// <c>unreadable</c> list was non-empty, which is the only way the live provider ever calls it.
/// The whole suite stayed green. Reaching more than one shape of argument, and refusing the
/// factories whose answer moves between them unless they declare it, is what this file is now.
/// </para>
///
/// <para>
/// <b>And three shapes are still three points of an infinite space, which is why the constancy
/// of a factory is no longer decided by sampling at all.</b> Building on shapes answers « what
/// status is this, and does the name agree » — a question about a value, which only running the
/// factory can settle. It cannot answer « does this status move », because that is a question
/// about every input, and no finite set of inputs settles it: four factories named
/// <c>…Failed</c> handing out <see cref="ReadStatus.AccessDenied"/> — on a count above two, on
/// the text of a path, on a numeric threshold, on an absent diagnostic — were planted in
/// <c>Rempart.Core</c> and the whole suite came back green. The two questions are split
/// accordingly: <c>Rule.ArgumentDependent</c> walks the compiled body, the shapes hold the value
/// at three points.
/// </para>
///
/// <para>
/// <b>And the first version of that fourth rule was escaped four more times, by the review that
/// read it.</b> It refused a conditional branch in the factory's own frame and a call whose
/// return type was literally <see cref="ReadStatus"/>, and called that « settled before the
/// arguments are looked at ». It is not: the same instructions compute different values from
/// different operands. A helper returning the record, the same helper returning an <c>int</c>, a
/// lookup in a <c>ReadStatus[]</c> and arithmetic on <c>lost.Count</c> each carried
/// <see cref="ReadStatus.AccessDenied"/> out of a factory named <c>…Failed</c>, in
/// <c>Rempart.Core</c>, under a green suite — and the message the rule printed told whoever it
/// reddened to move the branch out of the factory, which is the first of the four. What the rule
/// decides now is one sentence and it is the sentence it can defend: the status handed to the
/// record's constructor is an integer constant of the program text.
/// </para>
/// </summary>
public sealed class ReadFactoryNamingTests
{
    /// <summary>
    /// The words a factory name may use to state a cause, and what each one commits to.
    ///
    /// <para>
    /// Longest first, because the words nest: <c>NotFound</c> contains <c>Found</c> and
    /// <c>AccessDenied</c> contains <c>Denied</c>, and a shortest-match reading would classify
    /// <c>ScheduledTaskRead.NotFound</c> as a successful read. Matched as a substring rather
    /// than as the whole name so that a qualifier may be carried in front of it —
    /// <c>PartiallyRefused</c> is a refusal, and its name says so.
    /// </para>
    /// </summary>
    private static readonly (string Word, ReadStatus Status)[] Vocabulary =
    [
        ("NotInstalled", ReadStatus.NotFound),
        ("AccessDenied", ReadStatus.AccessDenied),
        ("NotFound", ReadStatus.NotFound),
        ("Refused", ReadStatus.AccessDenied),
        ("Denied", ReadStatus.AccessDenied),
        ("Absent", ReadStatus.NotFound),
        ("Failed", ReadStatus.Failed),
        ("Found", ReadStatus.Found),
    ];

    /// <summary>
    /// Every member carrying <see cref="StatusFoldAttribute"/>, and the tests that hold its
    /// branches — written out, and the only written-out list in this file.
    ///
    /// <para>
    /// A discovered rule with a declared exception is not the enumeration this repository keeps
    /// refusing; a discovered rule with a <em>silent</em> exception is worse than the enumeration,
    /// which is what the previous version shipped. Growing this list is the two-place, visible act
    /// that granting an exemption has to be: an attribute at the definition site, where a reader
    /// of the provider sees it, and a line here, where a reader of the guard sees the guard shrink.
    /// </para>
    ///
    /// <para>
    /// The names are checked to exist, so a covering test renamed or deleted lands here rather
    /// than leaving a fold with nothing behind its declaration.
    /// </para>
    /// </summary>
    private static readonly (string Factory, string[] Branches)[] Folds =
    [
        ("DynamicPortRangeRead.Combine",
        [
            "DynamicPortRangeTests.Tables_that_agree_produce_one_band_and_no_diagnostic",
            "DynamicPortRangeTests.No_table_answering_is_a_failed_read_and_not_a_default",
        ]),
        ("ScheduledTaskRead.Partially",
        [
            "ScheduledTasksTests.A_partly_refused_walk_keeps_its_tasks_and_names_the_folder_it_lost",
            "ScheduledTasksTests.A_walk_that_lost_a_folder_without_being_refused_does_not_advise_elevation",
        ]),
    ];

    /// <summary>
    /// The shapes of argument every factory is built on.
    ///
    /// <para>
    /// Two polarities and their mixture, which between them exercise both sides of every
    /// emptiness test and every flag a factory in this layer reads off its payload:
    /// <see cref="ScheduledTaskRead.Partially"/> answers a refusal on <see cref="Populated"/> and
    /// a failure on <see cref="Empty"/>, and <see cref="Mixed"/> is the walk that met a denial
    /// <em>and</em> a plain failure — the shape a real non-elevated walk of the scheduler takes.
    /// </para>
    ///
    /// <para>
    /// <b>What they do not reach, measured rather than asserted — and the previous statement of
    /// it was itself wrong.</b> It read « a factory branching on a count above one […] answers
    /// the same on all three ». It does not: <see cref="Mixed"/> builds <em>two</em> elements per
    /// list, so <c>lost.Count > 1</c> is false on <see cref="Empty"/> and <see cref="Populated"/>
    /// and true on <see cref="Mixed"/>. Planted in <c>Rempart.Core</c>, such a factory was caught
    /// on the spot — « construit AccessDenied sur des arguments Mixed ». The sentence describing
    /// the guard's limit had never been run any more than the guard it described, which is the
    /// reproach of this repository turned on its own prose one level further in.
    /// </para>
    ///
    /// <para>
    /// What is genuinely out of reach of three shapes: a threshold above <em>two</em>, the text
    /// inside a string — <see cref="Sample"/> hands every string the same « … » — any number,
    /// which is always its default here, an entry of a table a count indexes, arithmetic on that
    /// count. Every one of them was planted and every one of them passed. They are refused now,
    /// but not by adding shapes: a fourth shape moves the frontier by one and leaves the fifth
    /// outside, which is the enumeration this repository keeps refusing. They are refused by
    /// <see cref="Rule.ArgumentDependent"/>, which asks the compiled body where the status came
    /// from rather than asking three inputs whether it moved.
    /// </para>
    /// </summary>
    private enum Shape
    {
        /// <summary>Lists empty, nullables absent, flags false.</summary>
        Empty,

        /// <summary>One element per list, built the same way down; nullables present, flags true.</summary>
        Populated,

        /// <summary>Two elements per list: an <see cref="Empty"/> one beside a <see cref="Populated"/> one.</summary>
        Mixed,
    }

    /// <summary>
    /// The cause a member name states, or null when it states none — <c>Partial</c> says how
    /// much came back, not why the rest did not, and <c>Combine</c> names no state at all.
    /// </summary>
    private static ReadStatus? Named(string member)
    {
        foreach (var (word, status) in Vocabulary)
        {
            if (member.Contains(word, StringComparison.Ordinal))
            {
                return status;
            }
        }

        return null;
    }

    /// <summary>
    /// The four rules of the contract, and they are not symmetric.
    ///
    /// <para>
    /// <b>A name that states a cause must carry it, on every shape.</b> That is the defect
    /// itself: seven factories called <c>Failed</c> answered <c>AccessDenied</c> and an eighth
    /// answered <c>NotFound</c>, and every interface summary above them described the state the
    /// name promised rather than the one the field held.
    /// </para>
    ///
    /// <para>
    /// <b>And <see cref="ReadStatus.AccessDenied"/> may only be reached through a name that
    /// says so</b> — the half that keeps the first from being escaped by silence, since a
    /// factory called <c>Partial</c> or <c>Broken</c> states no cause and would otherwise be
    /// free to hand out a refusal — four <c>Partial</c> factories did. It is stated for that
    /// one value and not for the other three on purpose: <c>AccessDenied</c> is the only status
    /// the report turns into an instruction to the reader — « relancer en administrateur » — so
    /// it is the only one that may not be produced by a name that does not name it.
    /// <c>Partial</c> carrying <see cref="ReadStatus.Failed"/> stays legal, and says something
    /// its name does not: that is a summary's job, and the summary is what a reader has instead
    /// of a guarantee.
    /// </para>
    ///
    /// <para>
    /// <b>And a name states one cause, so a factory that answers two must say it is a fold.</b>
    /// This is the rule that was missing, and its absence is what let the first two be read on an
    /// input no caller ever passes. There is no name for a member that refuses on one argument
    /// and fails on another; <see cref="StatusFoldAttribute"/> is how that member says so, and
    /// <see cref="A_declared_fold_really_folds_and_its_branches_are_covered"/> is what stops the
    /// attribute from being a way out of the first two.
    /// </para>
    ///
    /// <para>
    /// <b>And the fourth is the third one proved instead of sampled.</b> Rule three catches a
    /// factory whose answer moved between the shapes; <see cref="Rule.ArgumentDependent"/>
    /// catches one whose status it cannot trace to a constant of the program text, whether or not
    /// three inputs happened to show it moving. It is the only rule here that says something
    /// about every argument the factory will ever be handed — and it says it for the reads that
    /// hold their status in a field a constructor fills, which is all of them but the one
    /// <see cref="A_read_whose_status_is_computed_is_named_rather_than_passed_in_silence"/> names.
    /// </para>
    ///
    /// <para>
    /// It is read on methods only. A <c>static readonly</c> state takes no argument, so there is
    /// nothing for its status to depend on and nothing for this rule to say; the first two hold
    /// it, and they are the ones that can.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(Factories))]
    public void Every_read_factory_carries_the_state_its_name_names(string factory)
    {
        var verdict = Verdict(Member(factory));

        Assert.True(verdict.Count == 0,
            string.Join("\n\n", verdict.Select(broken => broken.Complaint)));
    }

    /// <summary>
    /// The ways a factory can break the contract, named so that
    /// <see cref="The_guard_refuses_each_way_a_factory_can_be_written_wrong"/> can pin which one
    /// fires on which specimen. A guard whose verdict is only ever « nothing to report » is a
    /// guard nobody has watched work, and that is how the first two versions of this file shipped.
    /// </summary>
    private enum Rule
    {
        /// <summary>Its name states one cause and the field it builds holds another.</summary>
        NameContradicted,

        /// <summary>It builds a refusal under a name that does not say « refused ».</summary>
        UnnamedDenial,

        /// <summary>Its answer moved between the shapes without a <c>[StatusFold]</c>.</summary>
        UndeclaredMove,

        /// <summary>Its status could not be traced to a constant of the program text.</summary>
        ArgumentDependent,
    }

    /// <summary>
    /// Everything the contract holds against one factory, or nothing — the whole judgement in a
    /// single function, so that it can be run over the corpus <em>and</em> over
    /// <see cref="Specimen"/>, which is written to fail it.
    /// </summary>
    private static IReadOnlyList<(Rule Broken, string Complaint)> Verdict(MemberInfo member)
    {
        var factory = $"{member.DeclaringType!.Name}.{member.Name}";
        var carried = Carried(member);
        var named = Named(member.Name);
        var fold = IsFold(member);
        var verdict = new List<(Rule, string)>();

        foreach (var (shape, status) in carried)
        {
            if (named is { } stated && stated != status)
            {
                verdict.Add((Rule.NameContradicted,
                    $"La fabrique « {factory} » s'appelle d'après « {stated} » et construit "
                    + $"« {status} » sur des arguments {shape}. Le nom et le champ ne peuvent pas "
                    + "dire deux choses : c'est le nom que lit celui qui écrit l'appel, et le "
                    + "champ que lit le collecteur qui décide s'il faut conseiller une élévation."));
            }

            if (!fold && status == ReadStatus.AccessDenied && named != ReadStatus.AccessDenied)
            {
                verdict.Add((Rule.UnnamedDenial,
                    $"La fabrique « {factory} » construit un refus sur des arguments {shape} sans "
                    + "le dire dans son nom. AccessDenied est le seul statut que le rapport "
                    + "traduit en consigne — « relancer en administrateur » — donc il ne s'atteint "
                    + "que par un nom qui l'annonce (Refused, Denied, ou un qualificatif suivi de "
                    + "l'un des deux), ou par un [StatusFold] qui délègue à l'un d'eux."));
            }
        }

        var reached = carried.Select(answer => answer.Status).Distinct().Order().ToList();

        if (!fold && reached.Count > 1)
        {
            verdict.Add((Rule.UndeclaredMove,
                $"La fabrique « {factory} » répond « {string.Join(" / ", reached)} » selon ses "
                + "arguments et n'est pas déclarée [StatusFold]. Un nom énonce une cause et une "
                + "seule : ou bien elle en choisit une parmi les fabriques qui la nomment, et le "
                + "déclare, ou bien c'est le défaut de #177 — un nom qui promet un état et un "
                + "champ qui en porte un autre sur l'entrée qui, elle, se produit vraiment."));
        }

        if (!fold && !StatusIsComputed(member.DeclaringType!) && member is MethodInfo method
            && Movable(method) is { Count: > 0 } reasons)
        {
            verdict.Add((Rule.ArgumentDependent,
                $"La fabrique « {factory} » n'est pas déclarée [StatusFold] et la garde n'a pas "
                + $"pu ramener son statut à une constante du texte : elle y a lu "
                + $"{string.Join(", ", reasons)}. Trois formes ne lisent que trois points de "
                + "l'espace des arguments, donc ce qui n'est pas une constante n'est tenu par "
                + "rien. Ou bien elle rend le même statut quoi qu'on lui passe, et ce statut "
                + "s'écrit littéralement dans la fabrique — le déplacer dans une aide privée ne "
                + "change rien, la garde suit les appels qui portent un statut. Ou bien elle plie "
                + "vraiment, et le déclare [StatusFold]."));
        }

        return verdict;
    }

    /// <summary>
    /// What a declaration costs, so that it is not simply the way out of the two rules above.
    ///
    /// <para>
    /// Three obligations, and the point of each: the set is pinned, so an exemption cannot be
    /// granted in one file without the guard's own diff showing it; a declared fold must really
    /// answer more than one status, so the attribute cannot be sprinkled pre-emptively on
    /// factories it would silence later; and its name must state no cause, because a fold called
    /// <c>Failed</c> would be lying in the one place the first rule cannot look.
    /// </para>
    ///
    /// <para>
    /// Then the branches. A fold's whole defence is that it delegates to named factories, and
    /// what makes that checkable is not reflection but a test per branch — named here, and
    /// resolved against the assembly, so that renaming one lands here instead of quietly leaving
    /// a fold with nothing behind it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_declared_fold_really_folds_and_its_branches_are_covered()
    {
        var declared = FactoryNames().Where(IsFold).ToArray();

        Assert.Equal(
            Folds.Select(fold => fold.Factory).OrderBy(name => name, StringComparer.Ordinal),
            declared);

        foreach (var (factory, branches) in Folds)
        {
            var reached = Carried(factory).Select(answer => answer.Status).Distinct().ToList();

            Assert.True(reached.Count > 1,
                $"« {factory} » est déclarée [StatusFold] et répond « {reached[0]} » quels que "
                + "soient ses arguments. Une déclaration qui ne recouvre rien retire une fabrique "
                + "des deux règles sans contrepartie : ou elle plie vraiment, ou l'attribut part.");

            Assert.True(Named(MemberName(factory)) is null,
                $"« {factory} » est déclarée [StatusFold] et son nom énonce pourtant une cause. "
                + "Un repli choisit parmi plusieurs états : le nommer d'après l'un des deux le "
                + "fait mentir sur l'autre, à l'endroit exact où la première règle ne regarde plus.");

            Assert.All(branches, branch => Assert.True(TestExists(branch),
                $"« {factory} » désigne « {branch} » comme la couverture d'une de ses branches, "
                + "et ce test n'existe pas. C'est la seule contrepartie de la déclaration ; sans "
                + "elle le repli n'est plus couvert par rien."));
        }
    }

    /// <summary>
    /// The reads the structural rule cannot decide, named here rather than passed by it in
    /// silence — the one place this file admits a hole, and it admits it by listing what falls in.
    ///
    /// <para>
    /// <see cref="Movable"/> reads the <see cref="ReadStatus"/> that reaches a constructor. A
    /// record that <em>computes</em> its status from other fields hands no such value to any
    /// constructor, so the walk finds nothing to pin and would return « nothing to report » on a
    /// factory it has not looked at — vacuous green, which is the exact failure of the two earlier
    /// versions of this file. <c>FirewallState</c> is one: its status is
    /// <c>Readable ? Found : Denied ? AccessDenied : Diagnostic is null ? NotFound : Failed</c>,
    /// and the last of those four is an argument. So it is refused from the rule instead, and the
    /// shapes are what hold it — which they do: its three factories answer one status each across
    /// all three, and their names agree.
    /// </para>
    ///
    /// <para>
    /// Pinned both ways, like <see cref="Folds"/>. A read that starts computing its status lands
    /// here, where the diff shows the guard shrinking; a read that stops does too, so the list
    /// cannot outlive its reason.
    /// </para>
    /// </summary>
    [Fact]
    public void A_read_whose_status_is_computed_is_named_rather_than_passed_in_silence()
    {
        Assert.Equal(
            ["FirewallState"],
            ReadTypes().Where(StatusIsComputed).Select(type => type.Name));

        Assert.All(FactoryNames().Where(factory => StatusIsComputed(Member(factory).DeclaringType!)),
            factory => Assert.Single(
                Carried(factory).Select(answer => answer.Status).Distinct()));
    }

    /// <summary>
    /// The counterweight, without which the theory above could go green on nothing: a read
    /// type whose factories were all renamed out of the vocabulary would simply stop being
    /// asserted about, and the discovery returning zero rows is the shape a guard fails
    /// silently in.
    /// </summary>
    [Fact]
    public void Every_read_that_carries_a_status_states_at_least_one_cause_by_name()
    {
        var types = ReadTypes().ToList();

        Assert.NotEmpty(types);

        Assert.All(types, type => Assert.True(
            FactoriesOf(type).Any(member => Named(member.Name) is not null),
            $"« {type.Name} » porte un ReadStatus et aucune de ses fabriques ne nomme l'état "
            + "qu'elle construit. Le type sort donc entièrement de la garde ci-dessus, sans "
            + "que rien ne rougisse."));
    }

    /// <summary>
    /// The second counterweight, and it watches the argument shapes rather than the discovery:
    /// a <see cref="Sample"/> that stopped populating lists would put every fold back to
    /// answering one status, which is the state this file was rewritten out of — and it would
    /// do it silently, because a constant factory is exactly what the rules want.
    /// </summary>
    [Fact]
    public void The_shapes_really_differ_where_a_factory_can_read_them()
    {
        Assert.Equal(
            [ReadStatus.Failed, ReadStatus.AccessDenied, ReadStatus.AccessDenied],
            Carried("ScheduledTaskRead.Partially").Select(answer => answer.Status));

        var gaps = (IReadOnlyList<TaskFolderGap>)Sample(
            typeof(IReadOnlyList<TaskFolderGap>), Shape.Mixed)!;

        Assert.Equal([false, true], gaps.Select(gap => gap.Denied));
    }

    /// <summary>
    /// The reading the contract rests on, pinned word by word — the same reason
    /// <c>ProviderStatusChannelTests.Every_combination_of_channels_a_read_can_carry_is_named</c>
    /// pins its classifier: a classifier nothing checks is a classifier that can be wrong in
    /// the direction that makes everything pass.
    /// </summary>
    [Fact]
    public void The_vocabulary_reads_each_name_as_the_cause_it_states()
    {
        Assert.Equal(ReadStatus.Found, Named("Found"));
        Assert.Equal(ReadStatus.NotFound, Named("NotFound"));
        Assert.Equal(ReadStatus.NotFound, Named("Absent"));
        Assert.Equal(ReadStatus.NotFound, Named("NotInstalled"));
        Assert.Equal(ReadStatus.AccessDenied, Named("AccessDenied"));
        Assert.Equal(ReadStatus.AccessDenied, Named("Refused"));
        Assert.Equal(ReadStatus.AccessDenied, Named("Denied"));
        Assert.Equal(ReadStatus.Failed, Named("Failed"));

        // A qualifier in front is carried, which is what makes PartiallyRefused expressible
        // without a second vocabulary.
        Assert.Equal(ReadStatus.AccessDenied, Named("PartiallyRefused"));
        Assert.Equal(ReadStatus.Failed, Named("PartiallyFailed"));

        // And the names that state no cause stay unclassified rather than falling on one:
        // « Partial » is a quantity and « Combine » is a fold.
        Assert.Null(Named("Partial"));
        Assert.Null(Named("Combine"));
    }

    /// <summary>
    /// The guard read on the input it exists for: factories written to be wrong, one per way of
    /// being wrong, and the exact set of rules each must break.
    ///
    /// <para>
    /// <b>Why this test and not a clean corpus.</b> Every rule above is asserted over
    /// <c>Rempart.Core</c>, where nothing violates any of them — so the whole file passes whether
    /// its rules bite or not, which is precisely how its first two versions shipped and precisely
    /// what four rounds of adverse review kept finding. Confronting the corpus proves the corpus
    /// is clean; only a factory that must be refused proves the guard refuses.
    /// </para>
    ///
    /// <para>
    /// <b>Equality both ways, not « at least one complaint ».</b> The expected set is pinned
    /// exactly, so a rule that starts firing on everything — the shape a guard fails in while
    /// looking stricter — reddens here as loudly as one that stops firing. That is why the two
    /// legal specimens are in the table with an empty set rather than left out.
    /// </para>
    ///
    /// <para>
    /// <b>And nine rows carry the finding, not one.</b> Each is refused by
    /// <see cref="Rule.ArgumentDependent"/> and by nothing else — the three sampled rules have
    /// nothing to say about any of them, and saying so here is what keeps the split between
    /// proving and sampling from quietly collapsing back into sampling. Delete the structural
    /// rule and those nine rows, alone, go green. Four of them are the four factories that were
    /// planted in <c>Rempart.Core</c> against the first version of that rule and left the whole
    /// suite green: the decision one frame down behind a helper typed as the record, the same
    /// behind one typed as an <c>int</c>, a table an argument indexes, arithmetic on a count.
    /// </para>
    /// </summary>
    [Fact]
    public void The_guard_refuses_each_way_a_factory_can_be_written_wrong()
    {
        (string Factory, Rule[] Broken)[] expected =
        [
            // Legal: the name states the cause the field holds, and nothing branches.
            ("Failed", []),
            ("Refused", []),

            // Legal too, and the exemption is what makes it so: it branches, it answers two
            // statuses, and it says it does.
            ("Between", []),

            // Legal, and it delegates: the origin of a constant argument travels into the
            // callee, so the rule reads « the status moves » and not « the factory calls ».
            ("RefusedByABuilder", []),

            // A refusal under a name that states no cause — the four « Partial » factories
            // of #177, in one line.
            ("Partial", [Rule.UnnamedDenial]),

            // Caught by everything, including the shapes: Mixed builds two elements, so the
            // count crosses one. This is the row that shows the old note on Shape was wrong.
            ("FailedOnTwo",
            [
                Rule.NameContradicted,
                Rule.UnnamedDenial,
                Rule.UndeclaredMove,
                Rule.ArgumentDependent,
            ]),

            // The three the shapes cannot see, each answering « Failed » at all three points
            // and « AccessDenied » just outside them.
            ("FailedBeyondTheShapes", [Rule.ArgumentDependent]),
            ("FailedOnTheTextOfAPath", [Rule.ArgumentDependent]),
            ("FailedAboveAThreshold", [Rule.ArgumentDependent]),

            // And the five that a rule reading « no branch here, no call typed ReadStatus »
            // passed — four of them planted in Rempart.Core under a whole green suite, which is
            // the finding this version answers. Each derives its status without branching in its
            // own frame and without any callee whose signature says « status ».
            ("FailedByDelegation", [Rule.ArgumentDependent]),
            ("FailedByAHelperTypedAsTheRead", [Rule.ArgumentDependent]),
            ("FailedByAHelperTypedAsANumber", [Rule.ArgumentDependent]),
            ("FailedByATableLookup", [Rule.ArgumentDependent]),
            ("FailedByArithmeticOnACount", [Rule.ArgumentDependent]),
            ("FailedByANumberFromAnotherAssembly", [Rule.ArgumentDependent]),
        ];

        var members = FactoriesOf(typeof(Specimen)).ToList();

        Assert.Equal(
            expected.Select(row => row.Factory).OrderBy(name => name, StringComparer.Ordinal),
            members.Select(member => member.Name).OrderBy(name => name, StringComparer.Ordinal));

        Assert.Equal(
            expected.Select(row => $"{row.Factory} → {string.Join(", ", row.Broken)}"),
            expected.Select(row =>
            {
                var member = members.Single(candidate => candidate.Name == row.Factory);
                var broken = Verdict(member).Select(complaint => complaint.Broken)
                    .Distinct().Order();

                return $"{row.Factory} → {string.Join(", ", broken)}";
            }));
    }

    /// <summary>
    /// Factories written to fail the contract, kept here and nowhere near
    /// <c>Rempart.Core</c> — a demonstration of the defect does not get to ship inside the
    /// thing it demonstrates against.
    ///
    /// <para>
    /// They are invisible to <see cref="ReadTypes"/>, which discovers over the assembly holding
    /// <see cref="ReadStatus"/>; nothing reaches them but
    /// <see cref="The_guard_refuses_each_way_a_factory_can_be_written_wrong"/>, which names each
    /// one. The record carries <c>Status</c> and a list because that is all the rules read, and
    /// the shape a read of this layer has.
    /// </para>
    /// </summary>
    private sealed record Specimen(ReadStatus Status, IReadOnlyList<string> Lost)
    {
        public static Specimen Failed(IReadOnlyList<string> lost) => new(ReadStatus.Failed, lost);

        public static Specimen Refused(IReadOnlyList<string> lost) =>
            new(ReadStatus.AccessDenied, lost);

        /// <summary>States no cause and hands out the one status that becomes an instruction.</summary>
        public static Specimen Partial(IReadOnlyList<string> lost) =>
            new(ReadStatus.AccessDenied, lost);

        /// <summary>Crosses its threshold on <see cref="Shape.Mixed"/>, so the shapes see it.</summary>
        public static Specimen FailedOnTwo(IReadOnlyList<string> lost) =>
            new(lost.Count > 1 ? ReadStatus.AccessDenied : ReadStatus.Failed, lost);

        /// <summary>Crosses it one element past the widest shape, so they do not.</summary>
        public static Specimen FailedBeyondTheShapes(IReadOnlyList<string> lost) =>
            new(lost.Count > 2 ? ReadStatus.AccessDenied : ReadStatus.Failed, lost);

        /// <summary>Reads the text of a string, which is « … » on all three shapes.</summary>
        public static Specimen FailedOnTheTextOfAPath(string path) =>
            new(path.Contains("System32", StringComparison.Ordinal)
                ? ReadStatus.AccessDenied
                : ReadStatus.Failed, [path]);

        /// <summary>Reads a number, which is its default on all three shapes.</summary>
        public static Specimen FailedAboveAThreshold(int errors) =>
            new(errors > 10 ? ReadStatus.AccessDenied : ReadStatus.Failed, []);

        /// <summary>Branches nowhere itself, and lets the callee choose.</summary>
        public static Specimen FailedByDelegation(IReadOnlyList<string> lost) =>
            new(Decide(lost), lost);

        /// <summary>
        /// The same delegation with the helper's return type changed, which is all it took to
        /// walk past a rule that recognised a callee by its signature.
        /// </summary>
        public static Specimen FailedByAHelperTypedAsTheRead(IReadOnlyList<string> lost) =>
            Choose(lost);

        /// <summary>And the same again through an <c>int</c>, since the enum is one.</summary>
        public static Specimen FailedByAHelperTypedAsANumber(IReadOnlyList<string> lost) =>
            new((ReadStatus)Rank(lost), lost);

        /// <summary>No branch anywhere: the status is a table entry an argument indexes.</summary>
        public static Specimen FailedByATableLookup(IReadOnlyList<string> lost) =>
            new(Table[lost.Count], lost);

        /// <summary>Arithmetic, and no numeric parameter needed — a list carries a count.</summary>
        public static Specimen FailedByArithmeticOnACount(IReadOnlyList<string> lost) =>
            new((ReadStatus)(3 - (lost.Count / 3)), lost);

        /// <summary>
        /// And the number arriving from a method this guard cannot open — outside the assembly,
        /// so there is no body to walk. It answers <c>Failed</c> at all three shapes and, past
        /// them, a value that is not a status at all.
        /// </summary>
        public static Specimen FailedByANumberFromAnotherAssembly(IReadOnlyList<string> lost) =>
            new((ReadStatus)Math.Max(3, lost.Count), lost);

        /// <summary>
        /// Legal, and the counterweight to the six above: it delegates too, and hands the
        /// builder a constant. What the rule refuses is a status that moves, not a factory that
        /// calls something — a rule obeyed by never delegating would be obeyed by writing worse
        /// code.
        /// </summary>
        public static Specimen RefusedByABuilder(IReadOnlyList<string> lost) =>
            Build(ReadStatus.AccessDenied, lost);

        /// <summary>Really folds, and says so — the shape the exemption is for.</summary>
        [StatusFold]
        public static Specimen Between(IReadOnlyList<string> lost) =>
            lost.Count > 1 ? Refused(lost) : Failed(lost);

        private static Specimen Build(ReadStatus status, IReadOnlyList<string> lost) =>
            new(status, lost);

        private static readonly ReadStatus[] Table =
        [
            ReadStatus.Failed, ReadStatus.Failed, ReadStatus.Failed,
            ReadStatus.AccessDenied, ReadStatus.AccessDenied, ReadStatus.AccessDenied,
        ];

        private static ReadStatus Decide(IReadOnlyList<string> lost) =>
            lost.Count > 2 ? ReadStatus.AccessDenied : ReadStatus.Failed;

        private static Specimen Choose(IReadOnlyList<string> lost) =>
            lost.Count > 2 ? new(ReadStatus.AccessDenied, lost) : new(ReadStatus.Failed, lost);

        private static int Rank(IReadOnlyList<string> lost) => lost.Count > 2 ? 2 : 3;
    }

    /// <summary>Every factory the provider layer offers, as « Type.Member ».</summary>
    public static TheoryData<string> Factories() => [.. FactoryNames()];

    private static IEnumerable<string> FactoryNames() =>
        ReadTypes()
            .SelectMany(type => FactoriesOf(type).Select(member => $"{type.Name}.{member.Name}"))
            .OrderBy(name => name, StringComparer.Ordinal);

    /// <summary>
    /// Every read record that carries a <see cref="ReadStatus"/>, wherever it lives.
    ///
    /// <para>
    /// Selected on the field rather than on a namespace or a name: the guard is about types
    /// that can produce a refusal, and that is exactly what carrying this enum means. So it is
    /// narrower than « every factory in the provider layer », which is what one summary claimed
    /// and is not true — <c>FileSignature</c> has a <c>Status</c> of another type and is not one
    /// of them; <c>PolicyFacts.Unread</c> invented a bespoke boolean instead and is not either,
    /// which <see cref="ProviderStatusChannelTests"/> is the guard for.
    /// </para>
    ///
    /// <para>
    /// Selecting on the field is also what let <c>FirewallState</c> sit outside until #179 —
    /// and the day it took a <see cref="ReadStatus"/>, the three factories below it were judged
    /// without a line being added here. That is the property worth having, and it cuts both
    /// ways: a type that gave the field up would leave just as quietly, which is why the
    /// channel each provider read carries is pinned by name in
    /// <see cref="ProviderStatusChannelTests"/> rather than left to this discovery alone.
    /// </para>
    ///
    /// <para>
    /// Interfaces are out: <see cref="IStatusCarryingRead{TSelf,TItem}"/> declares the property
    /// without ever building a value, so it has no factory to judge and would only ever fail
    /// the counterweight below.
    /// </para>
    /// </summary>
    private static IEnumerable<Type> ReadTypes() =>
        typeof(ReadStatus).Assembly.GetTypes()
            .Where(type => type is { IsPublic: true, IsInterface: false }
                && type.GetProperty("Status")?.PropertyType == typeof(ReadStatus))
            .OrderBy(type => type.Name, StringComparer.Ordinal);

    /// <summary>
    /// The public static members of a read that hand back one of it: the <c>static readonly</c>
    /// states and the methods that build one. Operators are excluded by their return type, and
    /// the explicit <c>IStatusCarryingRead.Compose</c> implementations by not being public.
    /// </summary>
    private static IEnumerable<MemberInfo> FactoriesOf(Type type)
    {
        const BindingFlags Public = BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly;

        return type.GetFields(Public).Where(field => field.FieldType == type).Cast<MemberInfo>()
            .Concat(type.GetMethods(Public).Where(method => method.ReturnType == type));
    }

    private static string MemberName(string factory) =>
        factory[(factory.IndexOf('.', StringComparison.Ordinal) + 1)..];

    private static MemberInfo Member(string factory)
    {
        var type = ReadTypes().Single(candidate =>
            candidate.Name == factory[..factory.IndexOf('.', StringComparison.Ordinal)]);

        return FactoriesOf(type).Single(candidate => candidate.Name == MemberName(factory));
    }

    private static bool IsFold(string factory) => IsFold(Member(factory));

    private static bool IsFold(MemberInfo member) =>
        member.GetCustomAttribute<StatusFoldAttribute>() is not null;

    /// <summary>
    /// Where a slot of the evaluation stack got its value, as coarsely as the question needs.
    /// </summary>
    private enum Origin
    {
        /// <summary>
        /// Anything this walk did not pin to a constant: an argument, a field, an array element,
        /// the result of arithmetic, the return of a method whose body it did not read. The
        /// default answer, so a form nobody foresaw lands here rather than in the two below.
        /// </summary>
        Unknown,

        /// <summary>An integer constant the body itself loads — the <c>ldc.i4</c> family.</summary>
        Literal,

        /// <summary>
        /// A read built in this closure, every <see cref="ReadStatus"/> of which was
        /// <see cref="Literal"/>.
        /// </summary>
        Settled,
    }

    /// <summary>
    /// Why a factory's status <em>could</em> move, read off the compiled body — empty when this
    /// walk pinned it to a constant the body itself writes.
    ///
    /// <para>
    /// <b>What it decides, stated as what it decides and not as more.</b> It walks the
    /// instructions of the body in order, carrying an <see cref="Origin"/> per stack slot and per
    /// local, and it answers one question: is the <see cref="ReadStatus"/> that reaches the
    /// record's constructor an <c>ldc.i4</c> written in the closure. Everything else — an
    /// argument, a field, an array element, a subtraction, the return of a method whose body was
    /// not read — is <see cref="Origin.Unknown"/> and refused. So the guarantee is not « the body
    /// holds no branch » (which proves nothing: the same instructions compute different values
    /// from different operands, which is what <c>Table[lost.Count]</c> and
    /// <c>(ReadStatus)(3 - lost.Count / 3)</c> do) but « the status is a constant of the program
    /// text ». That does hold for every argument.
    /// </para>
    ///
    /// <para>
    /// <b>Three earlier statements of this rule were each escaped, and by what.</b> Refusing a
    /// conditional branch alone let the decision move one frame down — <c>new(Decide(paths), …)</c>.
    /// Adding « no call whose return type is <c>ReadStatus</c> » closed that one signature and
    /// nothing beside it: a helper returning the <em>record</em>, a helper returning
    /// <c>int</c>, a lookup in a <c>ReadStatus[]</c>, arithmetic on <c>lost.Count</c> — four
    /// factories named <c>…Failed</c> handing out <see cref="ReadStatus.AccessDenied"/> — were
    /// planted in <c>Rempart.Core</c> and the whole suite stayed green. Worse, the message the
    /// rule printed told a reddened developer to « sortir le branchement de la fabrique », which
    /// is the first of those four. Each is a row of
    /// <see cref="The_guard_refuses_each_way_a_factory_can_be_written_wrong"/> now, and the
    /// message says what it means.
    /// </para>
    ///
    /// <para>
    /// <b>Calls are followed, and only the ones that can carry a status.</b> A call whose return
    /// type is <see cref="ReadStatus"/> or a read is walked in turn, so a decision pushed into a
    /// private helper is read where it sits rather than believed. A call returning anything else
    /// is not followed and pushes <see cref="Origin.Unknown"/>: a helper that builds a diagnostic
    /// may branch all it likes, because its value cannot become the status. That is what makes
    /// the rule affordable, and measurably so — no factory in <c>Rempart.Core</c> that is not a
    /// declared fold calls anything that can carry a status, so the walk descends nowhere at all
    /// there today, and the only bodies it enters below the first are
    /// <see cref="Specimen"/>'s own.
    /// </para>
    ///
    /// <para>
    /// <b>Still sufficient rather than necessary.</b> A conditional branch is refused in any frame
    /// this walk enters, whatever it decides there, because a walk carrying one origin per slot
    /// cannot merge two paths — the moment it would have to, it stops and says so. It costs
    /// nothing today: the only two bodies in <c>Rempart.Core</c> that branch are exactly the two
    /// carrying <see cref="StatusFoldAttribute"/>, in Debug and in Release alike, which matters
    /// because CI runs Release and a workstation runs Debug. And a branch that decides a
    /// diagnostic is out of reach of the refusal rather than caught by it, since the call that
    /// builds one is not followed.
    /// </para>
    ///
    /// <para>
    /// <b>And what it does not reach at all is a whole class, not an example.</b> A read whose
    /// <c>Status</c> is <em>computed</em> from its other fields rather than held in one has no
    /// <see cref="ReadStatus"/> reaching any constructor, so this walk finds nothing to pin and
    /// would pass it vacuously. Those types are refused from the rule instead of passed by it,
    /// listed by <see cref="A_read_whose_status_is_computed_is_named_rather_than_passed_in_silence"/>,
    /// and held by the shapes alone.
    /// </para>
    /// </summary>
    private static IReadOnlyList<string> Movable(MethodInfo method)
    {
        var reasons = new List<string>();

        // Nothing is known about what a caller will hand the factory itself, which is the whole
        // question: every one of its own parameters starts Unknown.
        if (Walk(method, [], reasons, [], 0) is not Origin.Settled && reasons.Count == 0)
        {
            reasons.Add("un résultat qui n'est pas un enregistrement construit ici");
        }

        return reasons;
    }

    /// <summary>
    /// The walk itself: the <see cref="Origin"/> of the value <paramref name="method"/> returns
    /// when handed <paramref name="arguments"/>, with every reason it could not be pinned
    /// appended to <paramref name="reasons"/>.
    ///
    /// <para>
    /// The origins of the arguments travel into the callee, so a helper handed a constant is read
    /// as one — <c>Build(ReadStatus.AccessDenied, paths)</c> passes, and <c>Build(Decide(paths),
    /// paths)</c> does not. Without that, delegating to a private builder would be refused
    /// whatever it was handed, which is a rule that would be obeyed by not delegating rather than
    /// by not moving the status.
    /// </para>
    ///
    /// <para>
    /// Every way of losing track is loud. A stack that runs empty, an operand form the walk
    /// cannot size, a member it cannot resolve, a backward jump, a closure deeper than the cap
    /// below — each fails the test with its own sentence rather than returning « nothing to
    /// report », because a guard that stops reading its input and says nothing is the failure
    /// this whole file exists to stop repeating.
    /// </para>
    /// </summary>
    private static Origin Walk(MethodBase method, Origin[] arguments, List<string> reasons,
        HashSet<MethodBase> walking, int depth)
    {
        const int Depth = 6;
        var name = $"{method.DeclaringType?.Name}.{method.Name}";
        var here = depth == 0 ? string.Empty : $" dans « {name} », qu'elle appelle";

        Assert.True(depth <= Depth,
            $"La chaîne d'appels qui décide le statut passe {Depth} niveaux à « {name} ». La "
            + "garde s'arrête là plutôt que de descendre sans fin, et une fabrique qu'elle n'a "
            + "pas fini de lire ne se laisse pas passer en silence.");

        if (!walking.Add(method))
        {
            reasons.Add($"un cycle d'appels qui repasse par « {name} »");
            return Origin.Unknown;
        }

        try
        {
            var il = method.GetMethodBody()?.GetILAsByteArray();

            Assert.True(il is not null,
                $"« {name} » n'a pas de corps lisible. La règle qui tient la constance du statut "
                + "ne s'applique donc pas à elle, et une fabrique hors de la garde ne se saute "
                + "pas en silence.");

            var code = Instructions(il!).ToList();
            var at = code.Select((step, index) => (step.Offset, index))
                .ToDictionary(step => step.Offset, step => step.index);
            var returns = method is MethodInfo { ReturnType: var declared }
                && declared != typeof(void);
            var stack = new Stack<Origin>();
            var locals = new Dictionary<int, Origin>();
            var cursor = 0;

            while (cursor < code.Count)
            {
                var (offset, op, operand, next) = code[cursor++];

                Origin Pop()
                {
                    Assert.True(stack.Count > 0,
                        $"La pile simulée de « {name} » est vide à l'offset {offset}, devant "
                        + $"« {op.Name} » : le parcours a perdu le fil du corps et tout ce qu'il "
                        + "dira ensuite est faux. C'est un cas à traiter ici, pas à ignorer.");

                    return stack.Pop();
                }

                if (op.FlowControl is FlowControl.Cond_Branch)
                {
                    reasons.Add($"un branchement conditionnel « {op.Name} »{here}");
                    return Origin.Unknown;
                }

                if (op.FlowControl is FlowControl.Branch)
                {
                    var target = next + (op.OperandType is OperandType.ShortInlineBrTarget
                        ? (sbyte)il![operand]
                        : BitConverter.ToInt32(il!, operand));

                    Assert.True(target > offset && at.ContainsKey(target),
                        $"« {name} » saute de l'offset {offset} vers {target}, en arrière ou hors "
                        + "des instructions du corps. Le parcours est linéaire et ne sait pas "
                        + "suivre cela : il le dit au lieu de continuer de travers.");

                    cursor = at[target];
                    continue;
                }

                if (op.FlowControl is FlowControl.Return)
                {
                    return returns ? Pop() : Origin.Unknown;
                }

                if (op.FlowControl is FlowControl.Throw)
                {
                    reasons.Add($"une exception levée{here}, qui ne construit aucun statut");
                    return Origin.Unknown;
                }

                var opName = op.Name!;

                if (opName.StartsWith("ldc.i4", StringComparison.Ordinal))
                {
                    stack.Push(Origin.Literal);
                    continue;
                }

                if (opName is "dup")
                {
                    var duplicated = Pop();

                    stack.Push(duplicated);
                    stack.Push(duplicated);
                    continue;
                }

                // The two address forms first, because their names start with the two load
                // forms: whatever the slot held may be replaced through the pointer, so it stops
                // being known — a status put in a local before is one of the things that stops.
                if (Slot(op, il!, operand, "ldarga") is not null)
                {
                    stack.Push(Origin.Unknown);
                    continue;
                }

                if (Slot(op, il!, operand, "ldloca") is { } aliased)
                {
                    locals[aliased] = Origin.Unknown;
                    stack.Push(Origin.Unknown);
                    continue;
                }

                if (Slot(op, il!, operand, "ldarg") is { } read)
                {
                    stack.Push(read < arguments.Length ? arguments[read] : Origin.Unknown);
                    continue;
                }

                if (Slot(op, il!, operand, "stloc") is { } written)
                {
                    locals[written] = Pop();
                    continue;
                }

                if (Slot(op, il!, operand, "ldloc") is { } slot)
                {
                    stack.Push(locals.GetValueOrDefault(slot, Origin.Unknown));
                    continue;
                }

                if (op.OperandType is OperandType.InlineMethod)
                {
                    var target = Resolve(method, il!, operand, name);
                    var parameters = target.GetParameters();
                    var construct = opName is "newobj";
                    var arity = parameters.Length
                        + (construct || target.IsStatic ? 0 : 1);
                    var handed = new Origin[arity];

                    for (var slotIndex = arity - 1; slotIndex >= 0; slotIndex--)
                    {
                        handed[slotIndex] = Pop();
                    }

                    var first = arity - parameters.Length;
                    var pinned = true;

                    for (var index = 0; index < parameters.Length; index++)
                    {
                        if (parameters[index].ParameterType == typeof(ReadStatus)
                            && handed[first + index] is not Origin.Literal)
                        {
                            pinned = false;

                            reasons.Add($"un statut qui n'est pas une constante du texte, remis "
                                + $"à « {target.DeclaringType?.Name}.{target.Name} »{here}");
                        }
                    }

                    var returned = target is MethodInfo built
                        ? built.ReturnType
                        : construct ? target.DeclaringType! : typeof(void);

                    if (returned == typeof(void))
                    {
                        continue;
                    }

                    if (construct)
                    {
                        stack.Push(pinned && CarriesStatus(returned)
                            && parameters.Any(p => p.ParameterType == typeof(ReadStatus))
                            ? Origin.Settled
                            : Origin.Unknown);

                        continue;
                    }

                    if (returned != typeof(ReadStatus) && !CarriesStatus(returned))
                    {
                        // Its value cannot become the status, so what it does inside is none of
                        // this rule's business — a diagnostic may be built by anything at all.
                        stack.Push(Origin.Unknown);
                        continue;
                    }

                    if (target.Module.Assembly != method.Module.Assembly)
                    {
                        reasons.Add($"un appel à « {target.DeclaringType?.Name}.{target.Name} », "
                            + $"qui porte un statut et dont le corps est hors de cet assembly{here}");

                        stack.Push(Origin.Unknown);
                        continue;
                    }

                    stack.Push(Walk(target, handed, reasons, walking, depth + 1));
                    continue;
                }

                var pops = Slots(op.StackBehaviourPop, op, name, offset);

                for (var slotIndex = 0; slotIndex < pops; slotIndex++)
                {
                    Pop();
                }

                var pushes = Slots(op.StackBehaviourPush, op, name, offset);

                for (var slotIndex = 0; slotIndex < pushes; slotIndex++)
                {
                    stack.Push(Origin.Unknown);
                }
            }

            return Origin.Unknown;
        }
        finally
        {
            walking.Remove(method);
        }
    }

    /// <summary>
    /// How many slots a stack behaviour moves, read off the name the framework gives it rather
    /// than transcribed into a table: <c>Popref_popi_popi</c> is three, <c>Pop0</c> is none. The
    /// two variable forms belong to calls and to <c>ret</c>, which are handled before this, so
    /// meeting one here means the walk has met an instruction it cannot size — and it says so
    /// instead of guessing and reading everything after it out of step.
    /// </summary>
    private static int Slots(StackBehaviour behaviour, OpCode op, string name, int offset)
    {
        var written = behaviour.ToString();

        Assert.True(behaviour is not (StackBehaviour.Varpop or StackBehaviour.Varpush),
            $"« {op.Name} », à l'offset {offset} de « {name} », déplace un nombre variable de "
            + "valeurs et n'est pas un appel. La garde ne sait pas de combien : elle s'arrête "
            + "plutôt que de décaler la lecture de tout ce qui suit.");

        return written is "Pop0" or "Push0" ? 0 : written.Split('_').Length;
    }

    /// <summary>
    /// The argument or local slot an instruction of the given family names, or null when it is
    /// not of that family. The index rides in the operand for the long forms and in the last
    /// character of the name for the short ones — <c>ldloc.2</c>, <c>ldarg.0</c>.
    /// </summary>
    private static int? Slot(OpCode op, byte[] il, int operand, string family)
    {
        var name = op.Name!;

        if (!name.StartsWith(family, StringComparison.Ordinal)
            || (name.Length > family.Length && name[family.Length] is not '.'))
        {
            return null;
        }

        return op.OperandType switch
        {
            OperandType.ShortInlineVar => il[operand],
            OperandType.InlineVar => BitConverter.ToUInt16(il, operand),
            _ => name[^1] - '0',
        };
    }

    /// <summary>The member a call refers to, or a failed test — never a silent skip.</summary>
    private static MethodBase Resolve(MethodBase method, byte[] il, int operand, string name)
    {
        try
        {
            return method.Module.ResolveMethod(BitConverter.ToInt32(il, operand),
                method.DeclaringType!.GetGenericArguments(),
                method is MethodInfo generic ? generic.GetGenericArguments() : null)!;
        }
        catch (ArgumentException error)
        {
            Assert.Fail($"« {name} » appelle un membre que cette garde ne sait pas résoudre "
                + $"({error.Message}). Elle ne peut donc pas dire si le statut y est décidé : "
                + "c'est un cas à traiter ici, pas à ignorer.");

            throw;
        }
    }

    /// <summary>Whether a type holds a <see cref="ReadStatus"/> under the name the guard reads.</summary>
    private static bool CarriesStatus(Type type) =>
        type.GetProperty("Status")?.PropertyType == typeof(ReadStatus);

    /// <summary>
    /// Whether a read holds its status in a field the constructor fills, which is what
    /// <see cref="Movable"/> reads, or computes it from other fields, which
    /// <see cref="Movable"/> cannot see at all.
    /// </summary>
    private static bool StatusIsComputed(Type type) =>
        type.GetProperty("Status")!.GetMethod!
            .GetCustomAttribute<CompilerGeneratedAttribute>() is null;

    /// <summary>
    /// Every opcode by its encoded value, taken from the framework's own table rather than
    /// transcribed: a hand-copied opcode list is one typo away from walking the body out of step
    /// and reporting « no branch » on anything.
    /// </summary>
    private static readonly Dictionary<short, OpCode> Opcodes =
        typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(field => (OpCode)field.GetValue(null)!)
            .GroupBy(op => op.Value)
            .ToDictionary(group => group.Key, group => group.First());

    /// <summary>
    /// The instructions of a method body: where each starts, what it is, where its operand sits
    /// and where the next one begins — the last of which is what a branch target is measured from.
    ///
    /// <para>
    /// Walking rather than scanning: an operand may hold any byte, so a body containing the value
    /// of <c>brtrue</c> inside a metadata token would be read as branching by a search, and a
    /// body whose branch sits inside what a search skipped would be read as constant. The length
    /// of each operand comes from <see cref="OpCode.OperandType"/>, and <c>switch</c> — the one
    /// variable-length form, and a conditional branch — from the count it carries.
    /// </para>
    /// </summary>
    private static IEnumerable<(int Offset, OpCode Op, int Operand, int Next)> Instructions(
        byte[] il)
    {
        var index = 0;

        while (index < il.Length)
        {
            var offset = index;

            // 0xFE is the escape to the two-byte opcodes, and never an opcode itself.
            var escaped = il[index] is 0xFE;
            var key = escaped ? unchecked((short)((0xFE << 8) | il[index + 1])) : il[index];

            index += escaped ? 2 : 1;

            Assert.True(Opcodes.TryGetValue(key, out var op),
                $"Opcode inconnu 0x{key:X4} dans un corps de fabrique : le parcours est désormais "
                + "décalé et tout ce qui suit est lu de travers. Une garde qui ne sait plus lire "
                + "son entrée doit le dire.");

            var operand = index;

            index += op.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI
                    or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4 + (4 * BitConverter.ToInt32(il, index)),
                _ => 4,
            };

            yield return (offset, op, operand, index);
        }
    }

    /// <summary>Whether the test named « Class.Method » exists in this assembly.</summary>
    private static bool TestExists(string test)
    {
        var split = test.IndexOf('.', StringComparison.Ordinal);
        var type = typeof(ReadFactoryNamingTests).Assembly.GetType(
            $"Rempart.Tests.Unit.{test[..split]}");

        return type?.GetMethods().Any(method => method.Name == test[(split + 1)..]) is true;
    }

    /// <summary>
    /// The statuses a factory really builds, obtained by building it — once per
    /// <see cref="Shape"/>, because reading the source would have been reading prose again and
    /// building it once was reading a single point of an argument space the factory is free to
    /// branch on. Which is what the previous version did, and what let the defect of #177 be put
    /// back on <c>BrowserExtensionRead.Partial</c> under a green suite.
    /// </summary>
    private static IReadOnlyList<(Shape Shape, ReadStatus Status)> Carried(string factory) =>
        Carried(Member(factory));

    private static IReadOnlyList<(Shape Shape, ReadStatus Status)> Carried(MemberInfo member)
    {
        var type = member.DeclaringType!;

        return [.. Enum.GetValues<Shape>().Select(shape =>
        {
            var built = member switch
            {
                FieldInfo field => field.GetValue(null),
                MethodInfo method => method.Invoke(null,
                    [.. method.GetParameters().Select(p => Sample(p.ParameterType, shape))]),
                _ => null,
            };

            Assert.NotNull(built);
            return (shape, (ReadStatus)type.GetProperty("Status")!.GetValue(built)!);
        })];
    }

    /// <summary>
    /// A stand-in value of any type a factory takes, built without knowing which types those
    /// are — a factory added tomorrow with a payload nobody foresaw is built here or fails
    /// loudly, never skipped. Skipping is how a guard stops covering what it was written for.
    /// </summary>
    private static object? Sample(Type type, Shape shape, int depth = 0)
    {
        Assert.True(depth < 8,
            $"« {type} » se contient lui-même : la construction d'un argument témoin ne "
            + "termine pas. Ce n'est pas un cas à ignorer — la fabrique qui le prend sort "
            + "de la garde tant qu'il n'est pas traité ici.");

        if (type == typeof(string))
        {
            return "…";
        }

        if (Nullable.GetUnderlyingType(type) is { } underlying)
        {
            return shape is Shape.Empty ? null : Sample(underlying, shape, depth + 1);
        }

        if (type == typeof(bool))
        {
            return shape is not Shape.Empty;
        }

        if (type.IsEnum)
        {
            return Enum.GetValues(type).GetValue(0);
        }

        if (type.IsGenericType)
        {
            var definition = type.GetGenericTypeDefinition();
            var arguments = type.GetGenericArguments();

            if (definition == typeof(IReadOnlyList<>) || definition == typeof(IEnumerable<>)
                || definition == typeof(IList<>) || definition == typeof(List<>))
            {
                // Mixed is the shape a real refused walk takes: something lost to a denial
                // beside something lost to anything else, which is neither of the two pure
                // shapes and is the input ScheduledTasksTests holds a branch for.
                Shape[] elements = shape switch
                {
                    Shape.Empty => [],
                    Shape.Populated => [Shape.Populated],
                    _ => [Shape.Empty, Shape.Populated],
                };

                var array = Array.CreateInstance(arguments[0], elements.Length);

                for (var index = 0; index < elements.Length; index++)
                {
                    array.SetValue(Sample(arguments[0], elements[index], depth + 1), index);
                }

                return array;
            }

            if (definition == typeof(IReadOnlyDictionary<,>) || definition == typeof(IDictionary<,>)
                || definition == typeof(Dictionary<,>))
            {
                var map = (System.Collections.IDictionary)Activator.CreateInstance(
                    typeof(Dictionary<,>).MakeGenericType(arguments))!;

                if (shape is not Shape.Empty)
                {
                    map[Sample(arguments[0], shape, depth + 1)!] =
                        Sample(arguments[1], shape, depth + 1);
                }

                return map;
            }
        }

        // A value type with no public constructor has only its default, and that is the same
        // value on every shape. One that has constructors — a tuple, above all — is populated
        // like anything else, or DynamicPortRangeRead.Combine would see four empty tables on
        // every shape and read as constant.
        if (type.IsValueType && (shape is Shape.Empty || type.GetConstructors().Length == 0))
        {
            return Activator.CreateInstance(type);
        }

        var constructor = type.GetConstructors()
            .OrderBy(candidate => candidate.GetParameters().Length)
            .First();

        return constructor.Invoke(
            [.. constructor.GetParameters().Select(p => Sample(p.ParameterType, shape, depth + 1))]);
    }
}
