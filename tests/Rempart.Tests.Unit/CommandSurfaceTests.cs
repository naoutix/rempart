using System.Text.RegularExpressions;
using Rempart.Core.Cli;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds <see cref="CommandSurface"/> against the commands it claims to describe.
///
/// <para>
/// The table is written by hand — ADR-001 forbids reflection and ADR-005 refuses a source
/// generator — so nothing in the compiler relates it to the code it describes. A command
/// that starts reading a new option, a command added to the dispatch table, an option
/// removed and left declared: all three compile, all three ship, and all three are silent.
/// That failure mode is not hypothetical here. This repository has already paid for it
/// three times — D2, D2b and the component store — each time a declaration and its use
/// drifted apart behind a green build.
/// </para>
///
/// <para>
/// The guards that need to inspect the CLI read its <em>source files</em> rather than its
/// types, because <c>Rempart.Cli</c> targets <c>net10.0-windows</c> and the Linux job does
/// not compile it: a test that referenced those classes would never run in CI. Same
/// technique as <c>CoverageSettingsTests</c> and the replay wiring guard.
/// <see cref="Path"/> is legitimate here — these are paths on the host running the test,
/// not Windows paths captured on one machine and replayed on another.
/// </para>
/// </summary>
public sealed class CommandSurfaceTests
{
    /// <summary>
    /// Every option any command reads, and the four readers it can read it with. Anchored
    /// on <c>args</c> so that a call built from a variable does not slip past unseen — the
    /// count below is what makes that visible.
    /// </summary>
    private static readonly Regex OptionRead = new(
        """(?:OptionValue|OptionalValue|OptionValues|HasFlag)\(args,\s*"(--[a-z0-9-]+)"\)""",
        RegexOptions.Compiled);

    /// <summary>The rows of the dispatch table: a quoted command word mapped to a class.</summary>
    private static readonly Regex TableRow = new(
        """"
        "([a-z][a-z0-9-]*)"\s*=>\s*(\w+)\.Run
        """",
        RegexOptions.Compiled);

    /// <summary>The command a call site asks <c>ValueTaking</c> about.</summary>
    private static readonly Regex ValueTakingCall = new(
        """ValueTaking\("([a-z][a-z0-9-]*)"\)""",
        RegexOptions.Compiled);

    /// <summary>
    /// The shape of a hand-written list of value-taking options, as <c>diff</c> and
    /// <c>index</c> used to open one.
    /// </summary>
    private const string HandWrittenValueList = "Positional(args, [\"";

    /// <summary>
    /// Options a command accepts and the help does not mention, as they stand today.
    ///
    /// <para>
    /// Frozen rather than fixed: filling these holes is a documentation change, and this
    /// pass moves code without changing a byte of behaviour or of output. What the constant
    /// buys is that the list can only get shorter by accident — adding a hole now means
    /// editing this array, which is a deliberate act somebody has to justify.
    /// </para>
    ///
    /// <para>
    /// All six are the same shape: an option a command inherits from a shared helper
    /// (<c>--rules</c>, <c>--store</c>) or a second destination nobody thought to document
    /// (<c>seal --out</c>), never an option that command's own paragraph was written for.
    /// </para>
    /// </summary>
    private static readonly string[] KnownUndocumented =
    [
        "capture --rules",
        "capture --store",
        "scan --store",
        "seal --out",
        "synthesise --rules",
        "update --rules",
    ];

    /// <summary>
    /// Both directions, because they fail differently. An option read but not declared
    /// means <see cref="CommandSurface.ValueTaking"/> hands <c>Positional</c> an incomplete
    /// list, and the option's value is then mistaken for a bare argument. An option
    /// declared but no longer read is a line of documentation that describes nothing.
    /// </summary>
    [Fact]
    public void Every_option_the_CLI_reads_is_declared_in_the_surface()
    {
        var reads = CliSources()
            .SelectMany(source => OptionRead.Matches(source).Select(m => m.Groups[1].Value))
            .ToList();

        // A call written as OptionValue(args, name) would match nothing and take this
        // guard down with it, silently. The count says out loud how much it is watching.
        Assert.Equal(43, reads.Count);

        var declared = CommandSurface.All
            .SelectMany(command => command.Options)
            .Select(option => option.Name)
            .ToHashSet(StringComparer.Ordinal);

        var read = reads.ToHashSet(StringComparer.Ordinal);

        Assert.True(read.SetEquals(declared),
            "La surface déclarée et les options réellement lues par le CLI ont divergé. "
            + $"Lues mais non déclarées : {Join(read.Except(declared))}. "
            + $"Déclarées mais plus lues : {Join(declared.Except(read))}.");
    }

    /// <summary>
    /// The table and the surface name the same commands. A command in the table and not in
    /// the surface accepts options nobody describes; the reverse is a command the dispatch
    /// cannot reach, which is exactly the omission this repository keeps producing.
    /// </summary>
    [Fact]
    public void Every_command_in_the_dispatch_table_is_declared_in_the_surface()
    {
        var dispatched = TableRow.Matches(Read("src/Rempart.Cli/CommandTable.cs"))
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(19, dispatched.Count);

        var declared = CommandSurface.All.Select(c => c.Name).ToHashSet(StringComparer.Ordinal);

        Assert.True(dispatched.SetEquals(declared),
            "La table de dispatch et la surface ne nomment plus les mêmes commandes. "
            + $"Dispatchées sans déclaration : {Join(dispatched.Except(declared))}. "
            + $"Déclarées sans entrée dans la table : {Join(declared.Except(dispatched))}.");
    }

    /// <summary>
    /// The guard ADR-005 asked for by name, and the one the other two cannot stand in for:
    /// the dispatch table against <em>the command classes that exist on disk</em>.
    ///
    /// <para>
    /// Comparing the table to <see cref="CommandSurface"/> compares two lists written by
    /// the same hand in the same sitting; neither knows whether a class was ever wired up.
    /// The case was not hypothetical, and is no longer future tense — ADR-005 action 6
    /// added <c>diagnose-drivers</c> and <c>diagnose-processes</c> on the model of
    /// <c>diagnose-wmi</c>, and neither reads a single option. Dropping such a file in and
    /// forgetting the table line leaves every other guard green and the command
    /// unreachable: D2, D2b and the component store, a fourth time. What actually caught
    /// the addition was the count above rather than this set comparison, because the two
    /// commands were wired everywhere at once — the count is what makes an addition
    /// impossible to make in silence, whichever place it lands in.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_command_class_on_disk_is_wired_into_the_dispatch_table()
    {
        var onDisk = Directory
            .EnumerateFiles(Path.Combine(RepositoryRoot, "src", "Rempart.Cli", "Commands"),
                "*Command.cs", SearchOption.TopDirectoryOnly)
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .ToHashSet(StringComparer.Ordinal);

        var wired = TableRow.Matches(Read("src/Rempart.Cli/CommandTable.cs"))
            .Select(m => m.Groups[2].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.NotEmpty(onDisk);
        Assert.True(onDisk.SetEquals(wired),
            "Des classes de commande et la table de dispatch ont divergé. "
            + $"Présentes sur le disque mais jamais câblées, donc injoignables : {Join(onDisk.Except(wired))}. "
            + $"Câblées mais sans fichier : {Join(wired.Except(onDisk))}.");
    }

    /// <summary>
    /// Attribution, not just presence. The global check above passes as long as an option
    /// is declared <em>somewhere</em>, so moving a read from one command to another slips
    /// through it — and that is precisely the move that breaks
    /// <see cref="CommandSurface.ValueTaking"/>: adding an <c>--out</c> read to
    /// <c>DiffCommand</c> without the matching entry leaves <c>ValueTaking("diff")</c>
    /// short, and <c>rempart diff --out D:\rapports a.json b.json</c> then takes the folder
    /// for the first report to compare and drops the second.
    ///
    /// <para>
    /// A subset, not an equality: options reached through a shared helper —
    /// <c>--rules</c>, <c>--store</c>, <c>--analyze-store</c> — are read in
    /// <c>CliHost</c>, not in the command file. The equality in the other direction is what
    /// the global guard is for.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_option_a_command_reads_directly_is_declared_for_that_command()
    {
        var byClass = TableRow.Matches(Read("src/Rempart.Cli/CommandTable.cs"))
            .ToDictionary(m => m.Groups[2].Value, m => m.Groups[1].Value, StringComparer.Ordinal);

        var misattributed = new List<string>();

        foreach (var path in Directory.EnumerateFiles(
                     Path.Combine(RepositoryRoot, "src", "Rempart.Cli", "Commands"),
                     "*Command.cs", SearchOption.TopDirectoryOnly))
        {
            if (!byClass.TryGetValue(Path.GetFileNameWithoutExtension(path), out var command))
            {
                continue;
            }

            var declared = (CommandSurface.Find(command)?.Options ?? [])
                .Select(option => option.Name)
                .ToHashSet(StringComparer.Ordinal);

            misattributed.AddRange(OptionRead.Matches(File.ReadAllText(path))
                .Select(m => m.Groups[1].Value)
                .Where(option => !declared.Contains(option))
                .Distinct(StringComparer.Ordinal)
                .Select(option => $"{command} lit {option}"));
        }

        Assert.True(misattributed.Count == 0,
            "Une commande lit une option qui n'est pas déclarée pour elle : "
            + $"{Join(misattributed)}. ValueTaking rendra donc une liste incomplète, et "
            + "Positional prendra la valeur de cette option pour un argument.");
    }

    /// <summary>
    /// The command name handed to <see cref="CommandSurface.ValueTaking"/> is a fourth
    /// place holding that name, after the table, the surface and the help. A typo there
    /// yields an empty list rather than an error — deliberately, since a lookup must not
    /// turn a typo into a crash on a user's machine — so the noise has to be made here
    /// instead, where it costs nothing.
    /// </summary>
    [Fact]
    public void Every_command_named_in_a_ValueTaking_call_exists()
    {
        var asked = CliSources()
            .SelectMany(source => ValueTakingCall.Matches(source)
                .Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);

        Assert.NotEmpty(asked);

        var unknown = asked.Where(command => CommandSurface.Find(command) is null);

        Assert.True(!unknown.Any(),
            $"ValueTaking est appelée avec un nom de commande inconnu : {Join(unknown)}. "
            + "La liste rendue est vide, donc la commande cesse silencieusement de "
            + "reconnaître ses propres options à valeur.");
    }

    /// <summary>
    /// An option documented for a command that does not read it is worse than an
    /// undocumented one: the reader types it, nothing happens, and nothing says so.
    /// </summary>
    [Fact]
    public void The_help_documents_only_options_that_exist()
    {
        foreach (var (command, documented) in HelpByCommand())
        {
            var spec = CommandSurface.Find(command);

            Assert.True(spec is not null,
                $"L'aide documente « rempart {command} », qui n'est pas une commande déclarée.");

            var declared = spec!.Options.Select(o => o.Name).ToHashSet(StringComparer.Ordinal);
            var invented = documented.Except(declared).ToList();

            Assert.True(invented.Count == 0,
                $"L'aide de « {command} » documente {Join(invented)}, que la commande ne lit pas.");
        }
    }

    /// <summary>
    /// The other direction, which does not hold today: six options exist and are not
    /// documented. Asserting equality rather than a ceiling means closing a hole also
    /// fails, and has to be recorded here — the list cannot rot in either direction.
    /// </summary>
    [Fact]
    public void The_help_leaves_exactly_the_known_options_undocumented()
    {
        var help = HelpByCommand();

        var undocumented = CommandSurface.All
            .SelectMany(command => command.Options
                .Select(option => option.Name)
                .Where(name => !help.GetValueOrDefault(command.Name, []).Contains(name))
                .Select(name => $"{command.Name} {name}"))
            .OrderBy(entry => entry, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(KnownUndocumented, undocumented);
    }

    /// <summary>
    /// The list of value-taking options was a third place to remember an option, next to
    /// the command that reads it and the help that describes it. It is now derived, and
    /// this refuses its return: a hand-written list would drift without failing anything,
    /// which is precisely how the option's value ends up read as a bare argument.
    /// </summary>
    [Fact]
    public void No_command_hand_writes_its_own_list_of_value_taking_options()
    {
        foreach (var source in CliSources())
        {
            Assert.DoesNotContain(HandWrittenValueList, source, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// What <see cref="CommandSurface.ValueTaking"/> must produce for the two commands whose
    /// hand-written lists it replaced. Composition is what matters, not order:
    /// <c>Positional</c> consults the list with <c>Contains</c>.
    /// </summary>
    [Fact]
    public void The_derived_value_taking_lists_match_the_ones_they_replaced()
    {
        Assert.Equal(
            new HashSet<string>(["--report", "--baseline"], StringComparer.Ordinal),
            CommandSurface.ValueTaking("diff").ToHashSet(StringComparer.Ordinal));

        Assert.Equal(
            new HashSet<string>(["--out"], StringComparer.Ordinal),
            CommandSurface.ValueTaking("index").ToHashSet(StringComparer.Ordinal));

        // A flag never takes the next token, so it must stay out: listing --json would make
        // "rempart diff --json a.json b.json" lose a report to compare.
        Assert.DoesNotContain("--json", CommandSurface.ValueTaking("scan"));

        // An unknown command is not a crash: the caller gets the empty list it would have
        // hand-written anyway.
        Assert.Empty(CommandSurface.ValueTaking("nonexistent"));
    }

    /// <summary>
    /// Shape, not meaning. A command listed twice would make <c>Find</c> answer for the
    /// first and ignore the second; an option listed twice inside a command would inflate
    /// the value-taking list without changing what it matches, which is the kind of
    /// duplicate that survives review because it does nothing.
    /// </summary>
    [Fact]
    public void Option_and_command_names_are_well_formed_and_unique()
    {
        Assert.Equal(
            CommandSurface.All.Select(c => c.Name).Distinct(StringComparer.Ordinal).Count(),
            CommandSurface.All.Count);

        foreach (var command in CommandSurface.All)
        {
            Assert.True(Regex.IsMatch(command.Name, "^[a-z][a-z0-9-]*$"),
                $"Nom de commande hors convention : « {command.Name} ».");

            Assert.True(command.Positionals >= 0,
                $"« {command.Name} » déclare un nombre négatif d'arguments positionnels.");

            foreach (var option in command.Options)
            {
                Assert.True(Regex.IsMatch(option.Name, "^--[a-z0-9]+(-[a-z0-9]+)*$"),
                    $"Option hors convention sur « {command.Name} » : « {option.Name} ». "
                    + "Attendu : minuscules, double tiret, mots séparés par un tiret.");
            }

            var names = command.Options.Select(o => o.Name).ToList();
            Assert.Equal(names.Distinct(StringComparer.Ordinal).Count(), names.Count);
        }
    }

    /// <summary>
    /// The options the help text documents, per command.
    ///
    /// <para>
    /// A block runs from a <c>rempart &lt;commande&gt;</c> line to the next one, prose
    /// included: the paragraph under <c>scan</c> is where <c>--probe-dns</c> is actually
    /// explained, and a parser that only read the usage line would call it undocumented.
    /// </para>
    /// </summary>
    private static Dictionary<string, HashSet<string>> HelpByCommand()
    {
        var source = Read("src/Rempart.Cli/Commands/HelpCommand.cs");

        // The raw string literal itself, so that a comment or an identifier in the
        // surrounding C# cannot pass for documentation.
        var text = source[(source.IndexOf("\"\"\"", StringComparison.Ordinal) + 3)
            ..source.LastIndexOf("\"\"\"", StringComparison.Ordinal)];

        var blocks = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        string? current = null;

        foreach (var line in text.Split('\n'))
        {
            if (Regex.Match(line, @"^\s*rempart ([a-z][a-z0-9-]*)") is { Success: true } header)
            {
                current = header.Groups[1].Value;
                blocks.TryAdd(current, new HashSet<string>(StringComparer.Ordinal));
            }

            if (current is not null)
            {
                blocks[current].UnionWith(
                    Regex.Matches(line, "--[a-z0-9-]+").Select(m => m.Value));
            }
        }

        return blocks;
    }

    private static string Join(IEnumerable<string> names)
    {
        var listed = names.OrderBy(n => n, StringComparer.Ordinal).ToList();
        return listed.Count == 0 ? "aucune" : string.Join(", ", listed);
    }

    /// <summary>
    /// Every hand-written source file of the CLI. <c>bin</c> and <c>obj</c> are left out:
    /// generated files would make the counted total depend on whether the project happens
    /// to have been built on the machine running the tests.
    /// </summary>
    private static IEnumerable<string> CliSources() =>
        Directory
            .EnumerateFiles(Path.Combine(RepositoryRoot, "src", "Rempart.Cli"), "*.cs",
                SearchOption.AllDirectories)
            .Where(path => !path.Split(Path.DirectorySeparatorChar).Any(
                segment => segment is "bin" or "obj"))
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(File.ReadAllText);

    private static string Read(string relativePath) =>
        File.ReadAllText(Path.Combine(RepositoryRoot,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));

    private static string RepositoryRoot { get; } = Locate();

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src", "Rempart.Cli")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Racine du dépôt introuvable.");
    }
}
