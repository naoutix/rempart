using System.Reflection;
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
    /// <b>What they do not reach, stated rather than implied.</b> A factory branching on a count
    /// above one, on the text inside a string, or on a numeric threshold answers the same on all
    /// three and is read as constant. That hole is real; it is not the hole this file was
    /// rewritten over, which was that <em>every</em> argument-dependent factory was invisible —
    /// including the two that exist. Nothing here is true « by construction », and the summaries
    /// that said so have been corrected to say this instead.
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
    /// The three rules of the contract, and they are not symmetric.
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
    /// </summary>
    [Theory]
    [MemberData(nameof(Factories))]
    public void Every_read_factory_carries_the_state_its_name_names(string factory)
    {
        var carried = Carried(factory);
        var named = Named(MemberName(factory));
        var fold = IsFold(factory);

        foreach (var (shape, status) in carried)
        {
            if (named is { } stated)
            {
                Assert.True(stated == status,
                    $"La fabrique « {factory} » s'appelle d'après « {stated} » et construit "
                    + $"« {status} » sur des arguments {shape}. Le nom et le champ ne peuvent pas "
                    + "dire deux choses : c'est le nom que lit celui qui écrit l'appel, et le "
                    + "champ que lit le collecteur qui décide s'il faut conseiller une élévation.");
            }

            Assert.True(
                fold || status != ReadStatus.AccessDenied || named == ReadStatus.AccessDenied,
                $"La fabrique « {factory} » construit un refus sur des arguments {shape} sans le "
                + "dire dans son nom. AccessDenied est le seul statut que le rapport traduit en "
                + "consigne — « relancer en administrateur » — donc il ne s'atteint que par un nom "
                + "qui l'annonce (Refused, Denied, ou un qualificatif suivi de l'un des deux), ou "
                + "par un [StatusFold] qui délègue à l'un d'eux.");
        }

        var reached = carried.Select(answer => answer.Status).Distinct().Order().ToList();

        Assert.True(fold || reached.Count == 1,
            $"La fabrique « {factory} » répond « {string.Join(" / ", reached)} » selon ses "
            + "arguments et n'est pas déclarée [StatusFold]. Un nom énonce une cause et une "
            + "seule : ou bien elle en choisit une parmi les fabriques qui la nomment, et le "
            + "déclare, ou bien c'est le défaut de #177 — un nom qui promet un état et un champ "
            + "qui en porte un autre sur l'entrée qui, elle, se produit vraiment.");
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

    private static bool IsFold(string factory) =>
        Member(factory).GetCustomAttribute<StatusFoldAttribute>() is not null;

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
    private static IReadOnlyList<(Shape Shape, ReadStatus Status)> Carried(string factory)
    {
        var member = Member(factory);
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
