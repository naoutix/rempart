using System.Reflection;
using System.Reflection.Emit;
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
/// accordingly: <c>Rule.ArgumentDependent</c> reads the compiled body and holds for every input,
/// the shapes hold the value at three of them.
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
    /// inside a string — <see cref="Sample"/> hands every string the same « … » — and any number,
    /// which is always its default here. All three were planted and all three passed. They are
    /// refused now, but not by adding shapes: a fourth shape moves the frontier by one and leaves
    /// the fifth outside, which is the enumeration this repository keeps refusing. They are
    /// refused by <see cref="Rule.ArgumentDependent"/>, which asks the compiled body whether the
    /// answer <em>can</em> move rather than asking three inputs whether it did.
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
    /// catches one whose answer <em>can</em> move at all, whether or not three inputs happened to
    /// show it. It is the only rule here that says something about every argument the factory
    /// will ever be handed.
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

        /// <summary>Its compiled body lets the answer move, on any input at all.</summary>
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

        if (!fold && member is MethodInfo method && Movable(method) is { Count: > 0 } reasons)
        {
            verdict.Add((Rule.ArgumentDependent,
                $"La fabrique « {factory} » n'est pas déclarée [StatusFold] et son corps compilé "
                + $"porte {string.Join(", ", reasons)}. Son statut peut donc dépendre de ses "
                + "arguments, et trois formes ne lisent que trois points de l'espace où il en "
                + "dépendrait : un seuil au-delà de deux, le contenu d'une chaîne, un nombre y "
                + "passent verts — les trois ont été essayés. Ou bien elle rend le même statut "
                + "quoi qu'on lui passe, et le branchement porte sur autre chose : le sortir de "
                + "la fabrique. Ou bien elle plie vraiment, et le déclare."));
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
    /// <b>And the row that carries the finding is <c>FailedBeyondTheShapes</c>.</b> It is refused
    /// by <see cref="Rule.ArgumentDependent"/> and by nothing else — the three sampled rules have
    /// nothing to say about it, and saying so here is what keeps the split between proving and
    /// sampling from quietly collapsing back into sampling. Delete the structural rule and this
    /// row, alone, goes green.
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

            // And the choice delegated one frame down, where a body with no branch of its own
            // would otherwise read as constant.
            ("FailedByDelegation", [Rule.ArgumentDependent]),
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

        /// <summary>Really folds, and says so — the shape the exemption is for.</summary>
        [StatusFold]
        public static Specimen Between(IReadOnlyList<string> lost) =>
            lost.Count > 1 ? Refused(lost) : Failed(lost);

        private static ReadStatus Decide(IReadOnlyList<string> lost) =>
            lost.Count > 2 ? ReadStatus.AccessDenied : ReadStatus.Failed;
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
    /// Why a factory's status <em>could</em> move, read off the compiled body — empty when it
    /// provably cannot, whatever it is handed.
    ///
    /// <para>
    /// <b>The one thing here that is not a sample.</b> A body holding no conditional branch runs
    /// the same instructions on every input, so the <see cref="ReadStatus"/> it hands to the
    /// record is settled before the arguments are looked at; a body holding one is free to
    /// choose, and three shapes only say whether it happened to choose differently at three
    /// points. Both refusals are needed: without the second, a branch-free factory could delegate
    /// the choice — <c>new(Decide(paths), …)</c> — and the branch would sit one frame down where
    /// nothing looks.
    /// </para>
    ///
    /// <para>
    /// <b>Sufficient, deliberately not necessary.</b> A branch that decides something other than
    /// the status — a diagnostic, a default — is refused too, and that is the price: proving
    /// which branches reach the status field needs a dataflow pass over the stack, and a guard
    /// nobody can repair is worse than a guard that asks for one line to be moved. It costs
    /// nothing today. Every one of the factories in <c>Rempart.Core</c> is already branch-free,
    /// measured, and the only two bodies that branch are exactly the two carrying
    /// <see cref="StatusFoldAttribute"/> — in Debug and in Release alike, which matters because
    /// CI runs Release and a workstation runs Debug.
    /// </para>
    ///
    /// <para>
    /// <b>What still escapes, and it is now nameable in one sentence.</b> A status derived from
    /// an argument arithmetically — <c>(ReadStatus)errors</c> — branches nowhere and calls
    /// nothing, so it passes here, and it passes the shapes too whenever it lands on the same
    /// value at their three points. No factory in this layer takes a number at all, and this is
    /// written down rather than covered by « by construction », which is the sentence that had to
    /// be withdrawn from three files last round.
    /// </para>
    /// </summary>
    private static IReadOnlyList<string> Movable(MethodInfo method)
    {
        var il = method.GetMethodBody()?.GetILAsByteArray();

        Assert.True(il is not null,
            $"« {method.DeclaringType?.Name}.{method.Name} » n'a pas de corps lisible. La règle "
            + "qui tient la constance du statut ne s'applique donc pas à elle, et une fabrique "
            + "hors de la garde ne se saute pas en silence.");

        var reasons = new List<string>();

        foreach (var (op, operand) in Instructions(il!))
        {
            if (op.FlowControl is FlowControl.Cond_Branch)
            {
                reasons.Add($"un branchement conditionnel « {op.Name} »");
                continue;
            }

            if (op.OperandType is not OperandType.InlineMethod)
            {
                continue;
            }

            var token = BitConverter.ToInt32(il!, operand);
            MethodBase? called;

            try
            {
                called = method.Module.ResolveMethod(token,
                    method.DeclaringType!.GetGenericArguments(), method.GetGenericArguments());
            }
            catch (ArgumentException error)
            {
                called = null;

                Assert.Fail($"« {method.DeclaringType?.Name}.{method.Name} » appelle un membre "
                    + $"que cette garde ne sait pas résoudre ({error.Message}). Elle ne peut donc "
                    + "pas dire si le statut y est décidé : c'est un cas à traiter ici, pas à "
                    + "ignorer.");
            }

            if (called is MethodInfo { ReturnType: var returned } target
                && returned == typeof(ReadStatus))
            {
                reasons.Add($"un appel à « {target.DeclaringType?.Name}.{target.Name} », "
                    + "qui rend un ReadStatus");
            }
        }

        return reasons;
    }

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
    /// The instructions of a method body, with the offset of each operand.
    ///
    /// <para>
    /// Walking rather than scanning: an operand may hold any byte, so a body containing the value
    /// of <c>brtrue</c> inside a metadata token would be read as branching by a search, and a
    /// body whose branch sits inside what a search skipped would be read as constant. The length
    /// of each operand comes from <see cref="OpCode.OperandType"/>, and <c>switch</c> — the one
    /// variable-length form, and a conditional branch — from the count it carries.
    /// </para>
    /// </summary>
    private static IEnumerable<(OpCode Op, int Operand)> Instructions(byte[] il)
    {
        var index = 0;

        while (index < il.Length)
        {
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

            yield return (op, operand);
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
