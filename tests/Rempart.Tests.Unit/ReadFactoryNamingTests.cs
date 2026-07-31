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
    /// The two halves of the contract, and they are not symmetric.
    ///
    /// <para>
    /// <b>A name that states a cause must carry it.</b> That is the defect itself: seven
    /// factories called <c>Failed</c> answered <c>AccessDenied</c> and an eighth answered
    /// <c>NotFound</c>, and every interface summary above them described the state the name
    /// promised rather than the one the field held.
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
    /// <b>What neither half reaches is a fold.</b> <c>DynamicPortRangeRead.Combine</c> and
    /// <c>ScheduledTaskRead.Partially</c> name no cause and choose among the factories that do,
    /// so all the guard sees is whichever branch its stand-in arguments land on — the first
    /// failed here on its first run, but only because the <c>Failed</c> it delegates to was
    /// itself wrong. A fold is covered by the factories it calls being covered, and by a unit
    /// test on each branch; <c>ScheduledTasksTests</c> holds the two branches of the second.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(Factories))]
    public void Every_read_factory_carries_the_state_its_name_names(string factory)
    {
        var carried = Carried(factory);
        var named = Named(MemberName(factory));

        if (named is { } stated)
        {
            Assert.True(stated == carried,
                $"La fabrique « {factory} » s'appelle d'après « {stated} » et construit "
                + $"« {carried} ». Le nom et le champ ne peuvent pas dire deux choses : c'est "
                + "le nom que lit celui qui écrit l'appel, et le champ que lit le collecteur "
                + "qui décide s'il faut conseiller une élévation.");
        }

        Assert.True(carried != ReadStatus.AccessDenied || named == ReadStatus.AccessDenied,
            $"La fabrique « {factory} » construit un refus sans le dire dans son nom. "
            + "AccessDenied est le seul statut que le rapport traduit en consigne — « relancer "
            + "en administrateur » — donc il ne s'atteint que par un nom qui l'annonce : "
            + "Refused, Denied, ou un qualificatif suivi de l'un des deux.");
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
    public static TheoryData<string> Factories() =>
    [
        .. ReadTypes()
            .SelectMany(type => FactoriesOf(type).Select(member => $"{type.Name}.{member.Name}"))
            .OrderBy(name => name, StringComparer.Ordinal),
    ];

    /// <summary>
    /// Every read record that carries a <see cref="ReadStatus"/>, wherever it lives.
    ///
    /// <para>
    /// Selected on the field rather than on a namespace or a name: the guard is about types
    /// that can produce a refusal, and that is exactly what carrying this enum means.
    /// <c>FileSignature</c> has a <c>Status</c> too and is not one of them; <c>PolicyFacts</c>
    /// and <c>FirewallState</c> invented bespoke booleans instead and are not either, which
    /// <see cref="ProviderStatusChannelTests"/> is the guard for.
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

    /// <summary>
    /// The status a factory really builds, obtained by building one. Reading the source would
    /// have been reading prose again; the arguments are stand-ins because none of them can
    /// reach the status — a factory whose answer depended on its payload would fail
    /// <see cref="Every_read_factory_carries_the_state_its_name_names"/> on the input it was
    /// handed, which is the right way round.
    /// </summary>
    private static ReadStatus Carried(string factory)
    {
        var type = ReadTypes().Single(candidate =>
            candidate.Name == factory[..factory.IndexOf('.', StringComparison.Ordinal)]);

        var member = FactoriesOf(type).Single(candidate => candidate.Name == MemberName(factory));

        var built = member switch
        {
            FieldInfo field => field.GetValue(null),
            MethodInfo method => method.Invoke(
                null, [.. method.GetParameters().Select(parameter => Sample(parameter.ParameterType))]),
            _ => null,
        };

        Assert.NotNull(built);
        return (ReadStatus)type.GetProperty("Status")!.GetValue(built)!;
    }

    /// <summary>
    /// A stand-in value of any type a factory takes, built without knowing which types those
    /// are — a factory added tomorrow with a payload nobody foresaw is built here or fails
    /// loudly, never skipped. Skipping is how a guard stops covering what it was written for.
    /// </summary>
    private static object? Sample(Type type)
    {
        if (type == typeof(string))
        {
            return "…";
        }

        if (Nullable.GetUnderlyingType(type) is { } underlying)
        {
            return Sample(underlying);
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
                return Array.CreateInstance(arguments[0], 0);
            }

            if (definition == typeof(IReadOnlyDictionary<,>) || definition == typeof(IDictionary<,>)
                || definition == typeof(Dictionary<,>))
            {
                return Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(arguments));
            }
        }

        if (type.IsValueType)
        {
            return Activator.CreateInstance(type);
        }

        var constructor = type.GetConstructors()
            .OrderBy(candidate => candidate.GetParameters().Length)
            .First();

        return constructor.Invoke(
            [.. constructor.GetParameters().Select(parameter => Sample(parameter.ParameterType))]);
    }
}
