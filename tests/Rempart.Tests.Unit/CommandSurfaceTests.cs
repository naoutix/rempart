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
    /// count below is what makes that visible. The reader is captured too: which of the
    /// four is used is what the declared arity has to name, and reading it with the wrong
    /// one is DET-ARITE-REPORT.
    /// </summary>
    private static readonly Regex OptionRead = new(
        """(OptionValue|OptionalValue|OptionValues|HasFlag)\(args,\s*"(--[a-z0-9-]+)"\)""",
        RegexOptions.Compiled);

    /// <summary>
    /// A read at a fixed slot, and the slot. Only index 0 — the command word, which nothing
    /// can precede — is a fact rather than an assumption.
    /// </summary>
    private static readonly Regex WordAtCall = new(
        @"WordAt\(args,\s*(\d+)\)",
        RegexOptions.Compiled);

    /// <summary>The reader a command calls, and the arity that names it.</summary>
    private static readonly Dictionary<string, OptionArity> ArityOfReader =
        new(StringComparer.Ordinal)
        {
            ["HasFlag"] = OptionArity.Flag,
            ["OptionValue"] = OptionArity.Value,
            ["OptionalValue"] = OptionArity.OptionalValue,
            ["OptionValues"] = OptionArity.RepeatableValue,
        };

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
    /// The fallback arm of the dispatch table — the class an unrecognised word runs.
    /// </summary>
    private static readonly Regex FallbackRow = new(
        @"_\s*=>\s*(\w+)\.Run",
        RegexOptions.Compiled);

    /// <summary>
    /// A shared helper of <c>CliHost</c>, as a command calls it: name only, since
    /// <c>using static</c> is how the commands reach them.
    /// </summary>
    private static readonly Regex HostMember = new(
        @"^ {4}public static [^\n(]*?(\w+)\s*\(",
        RegexOptions.Compiled | RegexOptions.Multiline);

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
            .SelectMany(source => OptionRead.Matches(source).Select(m => m.Groups[2].Value))
            .ToList();

        // A call written as OptionValue(args, name) would match nothing and take this
        // guard down with it, silently. The count says out loud how much it is watching.
        Assert.Equal(45, reads.Count);

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

        Assert.Equal(20, dispatched.Count);

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
        var onDisk = CommandFiles()
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

        foreach (var path in CommandFiles())
        {
            if (!byClass.TryGetValue(Path.GetFileNameWithoutExtension(path), out var command))
            {
                continue;
            }

            var declared = (CommandSurface.Find(command)?.Options ?? [])
                .Select(option => option.Name)
                .ToHashSet(StringComparer.Ordinal);

            misattributed.AddRange(OptionRead.Matches(File.ReadAllText(path))
                .Select(m => m.Groups[2].Value)
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
    /// The options a command inherits from a shared helper are declared for that command too
    /// — the half of the attribution the guard above cannot see.
    ///
    /// <para>
    /// <c>--rules</c>, <c>--store</c> and <c>--analyze-store</c> are read inside
    /// <c>CliHost</c> and in no command file at all. The per-command guard above therefore
    /// walks straight past them, and the global one is satisfied by <em>any</em> command
    /// declaring them anywhere — so which commands actually inherit them was, until here,
    /// held by nothing.
    /// </para>
    ///
    /// <para>
    /// That gap used to cost a mis-parsed positional argument. Since unknown options are
    /// refused it costs a command line that works: let a command start calling
    /// <c>StoreDirectory(args)</c> without declaring <c>--store</c>, and
    /// <c>rempart &lt;commande&gt; --store D:\donnees</c> exits 6 on a line the command reads
    /// perfectly well. A refusal that turns on the tool's own users is worse than the silence
    /// it closed, which is why closing this belongs in the same change as the refusal and not
    /// after it.
    /// </para>
    ///
    /// <para>
    /// The helper-to-option map is read off <c>CliHost.cs</c> and closed over the calls the
    /// helpers make to each other, so <c>ResolveLiveCatalog</c> answers for the
    /// <c>--store</c> and <c>--rules</c> it reaches through two other helpers rather than
    /// appearing to read nothing. Comments come out first: a helper named in a doc comment is
    /// a mention and not a call, and counting one would attribute options to commands that
    /// never touch them.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_option_a_command_inherits_from_a_shared_helper_is_declared_for_that_command()
    {
        var optionsOfHelper = HelperOptions();

        // The premise, and it is the whole test: were CliHost to stop reading options — or
        // were this parser to stop seeing them — every command below would be compared
        // against nothing and the guard would pass by having found nothing to check.
        Assert.NotEmpty(optionsOfHelper);

        var byClass = TableRow.Matches(Read("src/Rempart.Cli/CommandTable.cs"))
            .ToDictionary(m => m.Groups[2].Value, m => m.Groups[1].Value, StringComparer.Ordinal);

        var undeclared = new List<string>();
        var inherited = 0;

        foreach (var path in CommandFiles())
        {
            if (!byClass.TryGetValue(Path.GetFileNameWithoutExtension(path), out var command))
            {
                continue;
            }

            var declared = (CommandSurface.Find(command)?.Options ?? [])
                .Select(option => option.Name)
                .ToHashSet(StringComparer.Ordinal);

            var body = WithoutComments(File.ReadAllText(path));

            foreach (var (helper, options) in optionsOfHelper)
            {
                if (!Regex.IsMatch(body, $@"\b{helper}\s*\("))
                {
                    continue;
                }

                inherited += options.Count;

                undeclared.AddRange(options
                    .Where(option => !declared.Contains(option))
                    .Select(option => $"{command} hérite {option} de {helper}"));
            }
        }

        Assert.True(inherited > 0,
            "Aucune commande n'appelle un helper de CliHost qui lit une option : soit le "
            + "partage a disparu, soit cette garde ne sait plus reconnaître un appel.");

        Assert.True(undeclared.Count == 0,
            "Une commande lit une option par un helper partagé sans la déclarer : "
            + $"{Join(undeclared.Distinct(StringComparer.Ordinal))}. Cette option sera "
            + "refusée par Usage.Check sur une ligne que la commande lit pourtant, et le "
            + "refus tombera sur l'utilisateur au lieu de tomber ici.");
    }

    /// <summary>
    /// The arity a command declares is the reader it actually calls — the guard the surface
    /// was missing, and the one DET-ARITE-REPORT was.
    ///
    /// <para>
    /// The global check above passes as long as an option is read by <em>one of</em> the
    /// four readers, so <c>diff</c> could declare <c>--report</c> a <c>Value</c> and read it
    /// with <c>OptionValue</c> while <c>scan</c> declared the same spelling an
    /// <c>OptionalValue</c>: both green, both accurate, and
    /// <c>rempart diff --report --baseline b.json a.json</c> wrote the comparison into a
    /// folder named <c>--baseline</c>. An arity is not documentation — it is the promise
    /// that <see cref="CommandLine.Positional"/> and the option's own reader draw the same
    /// line between a value and a bare argument, and only the reader can keep it.
    /// </para>
    ///
    /// <para>
    /// <c>HasFlag</c> beside a value reader is not a contradiction but the <c>--report</c>
    /// shape itself: presence decides whether to write anything, the value decides where.
    /// The value reader is the one the arity has to name; <c>HasFlag</c> on its own means a
    /// real flag. Two <em>different</em> value readers on one option is the ambiguity this
    /// guard exists for, and is reported as such.
    /// </para>
    /// </summary>
    /// <summary>
    /// One spelling, one arity, everywhere it is declared — the guard the previous one
    /// cannot stand in for.
    ///
    /// <para>
    /// DET-ARITE-REPORT was never a command disagreeing with its own declaration; it was
    /// two commands disagreeing with <em>each other</em> about the same word.
    /// <c>--report</c> was read with <c>OptionalValue</c> on <c>scan</c> and with
    /// <c>OptionValue</c> on <c>diff</c>, and both were internally consistent — so the
    /// per-command check goes green on the defect as long as the surface is reverted
    /// alongside the code. Proven: reverting <c>DiffCommand</c> and <c>CommandSurface</c>
    /// together left the whole suite passing with the defect back in place.
    /// </para>
    ///
    /// <para>
    /// A reader typing <c>--report</c> should not have to remember which command they are
    /// in to know whether the next token will be swallowed.
    /// </para>
    /// </summary>
    [Fact]
    public void An_option_spelled_the_same_way_carries_the_same_arity_everywhere()
    {
        var divergent = CommandSurface.All
            .SelectMany(command => command.Options,
                (command, option) => (Option: option.Name, option.Arity, Command: command.Name))
            .GroupBy(entry => entry.Option, StringComparer.Ordinal)
            .Where(spelling => spelling.Select(entry => entry.Arity).Distinct().Count() > 1)
            .Select(spelling => $"{spelling.Key} — "
                + Join(spelling.Select(entry => $"{entry.Command}:{entry.Arity}")))
            .ToList();

        Assert.True(divergent.Count == 0,
            "La même option porte des arités différentes selon la commande : "
            + $"{Join(divergent)}. Le token qui suit sera avalé ici et pas là, et personne "
            + "n'a à retenir dans quelle commande il se trouve pour savoir laquelle.");
    }

    [Fact]
    public void Every_option_a_command_reads_is_declared_with_the_reader_it_is_read_with()
    {
        var byClass = TableRow.Matches(Read("src/Rempart.Cli/CommandTable.cs"))
            .ToDictionary(m => m.Groups[2].Value, m => m.Groups[1].Value, StringComparer.Ordinal);

        var mismatched = new List<string>();

        foreach (var path in CommandFiles())
        {
            if (!byClass.TryGetValue(Path.GetFileNameWithoutExtension(path), out var command))
            {
                continue;
            }

            var declared = (CommandSurface.Find(command)?.Options ?? [])
                .ToDictionary(option => option.Name, option => option.Arity, StringComparer.Ordinal);

            foreach (var option in OptionRead.Matches(File.ReadAllText(path))
                         .GroupBy(m => m.Groups[2].Value, m => m.Groups[1].Value,
                             StringComparer.Ordinal))
            {
                // An option read here but declared elsewhere — or not at all — is the other
                // guard's finding, and reporting it twice would bury this one.
                if (!declared.TryGetValue(option.Key, out var arity))
                {
                    continue;
                }

                var readers = option.Distinct(StringComparer.Ordinal).ToList();
                var deciding = readers.Count > 1
                    ? [.. readers.Where(reader => reader != "HasFlag")]
                    : readers;

                if (deciding.Count != 1 || ArityOfReader[deciding[0]] != arity)
                {
                    mismatched.Add($"{command} {option.Key} — lue par {Join(readers)}, "
                        + $"déclarée {arity}");
                }
            }
        }

        Assert.True(mismatched.Count == 0,
            "Une option est déclarée avec une arité que sa commande ne lit pas : "
            + $"{Join(mismatched)}. L'arité nomme lequel des quatre lecteurs sert, et ces "
            + "lecteurs sont en désaccord par construction — celui qui refuse une valeur "
            + "commençant par un tiret et celui qui prend le jeton suivant quoi qu'il "
            + "arrive. Positional suit l'arité déclarée, la commande suit son lecteur : "
            + "quand les deux divergent, la valeur d'une option est comptée pour un "
            + "argument, ou l'option suivante est prise pour une valeur.");
    }

    /// <summary>
    /// <see cref="CommandLine.WordAt"/> is called once, on the command word.
    ///
    /// <para>
    /// Index 0 is the one slot where a fixed index is a fact: no option can precede the
    /// command word. Every other position is an assumption, and DET-EXPLAIN-POSITIONNEL was
    /// that assumption — <c>explain</c> read its identifier at index 1, so
    /// <c>rempart explain --rules ./mes-regles WIN-CRED-001</c> found <c>--rules</c> there
    /// and listed the whole catalog instead of explaining the rule. Nothing failed: listing
    /// is what an argument-less <c>explain</c> legitimately does, which is why the defect
    /// survived to be catalogued rather than reported.
    /// </para>
    ///
    /// <para>
    /// Equality rather than a ceiling, and on the whole list rather than a count: a second
    /// call at index 0 would be a second place deciding which command runs, and any call at
    /// a non-zero index is the defect coming back. Both have to be a decision taken here.
    /// </para>
    /// </summary>
    [Fact]
    public void Only_the_command_word_is_read_at_a_fixed_index()
    {
        var slots = CliSources()
            .SelectMany(source => WordAtCall.Matches(source).Select(m => m.Groups[1].Value))
            .ToList();

        Assert.True(slots is ["0"],
            $"WordAt est appelée sur les indices {Join(slots)}, attendu : le seul indice 0. "
            + "Un argument lu à un indice fixe au-delà du mot de commande n'est pas vu "
            + "quand une option le précède, et la commande se rabat en silence sur son "
            + "comportement sans argument. Tout ce qui suit le mot de commande passe par "
            + "Positional, qui sait qu'une option avale le jeton derrière elle.");
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
    /// The refusal of unknown options is wired into the entry point, and wired <em>before</em>
    /// the dispatch.
    ///
    /// <para>
    /// <see cref="Usage.Check"/> is a pure function in Core, so every test of it passes with
    /// the call missing from <c>Program.cs</c> — the check would be written, tested, and
    /// reach no command line. That is D2 one directory over, and this repository has shipped
    /// that omission three times. Reading the source is the only way to see it: the Linux job
    /// does not compile <c>Rempart.Cli</c>, so nothing here can call the entry point.
    /// </para>
    ///
    /// <para>
    /// Order is half the claim and the half that matters. Behind the dispatch, the check
    /// would print its refusal after <c>scan</c> had already read the machine and written a
    /// report — the exact harm, with a sentence added at the end. The single
    /// <c>Dispatch</c> call is asserted with it: a second one is a second way in, and it
    /// would not have to pass this door.
    /// </para>
    /// </summary>
    [Fact]
    public void The_usage_check_runs_before_the_dispatch()
    {
        var program = Read("src/Rempart.Cli/Program.cs");

        var checkedAt = program.IndexOf("Usage.Check(", StringComparison.Ordinal);
        var dispatchedAt = program.IndexOf("CommandTable.Dispatch(", StringComparison.Ordinal);

        Assert.True(checkedAt >= 0,
            "Program.cs n'appelle pas Usage.Check : le refus des options inconnues est écrit "
            + "et testé dans Core, et aucune ligne de commande ne le rencontre. « rempart "
            + "scan --replay capture.json » scanne de nouveau la machine locale en silence.");

        Assert.True(dispatchedAt >= 0,
            "Program.cs n'appelle plus CommandTable.Dispatch : cette garde ne sait plus dire "
            + "où passe la ligne de commande, et ne garde donc plus rien.");

        Assert.True(checkedAt < dispatchedAt,
            "Usage.Check est appelée après le dispatch. Une option inconnue serait alors "
            + "refusée une fois la machine lue et le rapport écrit : le défaut entier, plus "
            + "une phrase à la fin.");

        var ways = Regex.Matches(program, @"CommandTable\.Dispatch\(").Count;

        Assert.True(ways == 1,
            $"Program.cs appelle CommandTable.Dispatch {ways} fois, attendu une seule. Un "
            + "second appel est une seconde entrée vers les commandes, et rien n'oblige "
            + "celle-là à passer par la porte au-dessus.");
    }

    /// <summary>
    /// The one command the usage check exempts is the dispatch table's fallback, and the
    /// claim is confronted with the table on disk rather than believed.
    ///
    /// <para>
    /// The exemption exists because the help is where an unusable command line already lands,
    /// and because <c>rempart --help</c> carries no command word at all — refusing options
    /// there would make the tool answer an unreadable line with a second unreadable line.
    /// Every other command acts on what it was given, which is the whole harm.
    /// </para>
    ///
    /// <para>
    /// Written as a constant in Core and checked here, because Core cannot see the table:
    /// <c>Rempart.Cli</c> targets <c>net10.0-windows</c>. Should the fallback ever become
    /// another command, the exemption follows it or this fails — what must not happen is an
    /// exemption quietly covering a command that does something.
    /// </para>
    /// </summary>
    [Fact]
    public void The_command_the_usage_check_exempts_is_the_dispatch_fallback()
    {
        var table = Read("src/Rempart.Cli/CommandTable.cs");

        var fallbacks = FallbackRow.Matches(table).Select(m => m.Groups[1].Value).ToList();

        Assert.True(fallbacks.Count == 1,
            $"La table de dispatch a {fallbacks.Count} bras par défaut ({Join(fallbacks)}), "
            + "attendu un seul : cette garde ne sait plus lequel la vérification d'usage "
            + "exempte.");

        var byClass = TableRow.Matches(table)
            .ToDictionary(m => m.Groups[2].Value, m => m.Groups[1].Value, StringComparer.Ordinal);

        Assert.True(byClass.TryGetValue(fallbacks[0], out var fallbackCommand),
            $"Le bras par défaut lance {fallbacks[0]}, qui n'est nommée par aucune ligne de "
            + "la table : la commande de repli n'est joignable que par ce bras, ce que la "
            + "table dit elle-même refuser.");

        Assert.Equal(Usage.Fallback, fallbackCommand);
    }

    /// <summary>
    /// « Undocumented » and « inexistent » are two different things, and the refusal of
    /// unknown options must not merge them.
    ///
    /// <para>
    /// Six options exist that the help does not mention — <c>scan --store</c>,
    /// <c>capture --rules</c> and four more, all inherited from a shared helper. They are
    /// typed on real command lines. A refusal built on the help text rather than on the
    /// declared surface would reject every one of them, which is a worse failure than the
    /// silence being closed: it breaks lines that work today.
    /// </para>
    ///
    /// <para>
    /// Derived from the help parser above rather than from <see cref="KnownUndocumented"/>,
    /// so that it keeps speaking about whatever the gap actually is on the day it runs. The
    /// non-empty assertion is the premise: the day the help documents everything, this test
    /// stops proving anything and has to say so.
    /// </para>
    /// </summary>
    [Fact]
    public void An_option_the_help_omits_is_still_accepted_by_the_usage_check()
    {
        var help = HelpByCommand();

        var undocumented = CommandSurface.All
            .SelectMany(command => command.Options
                .Select(option => option.Name)
                .Where(name => !help.GetValueOrDefault(command.Name, []).Contains(name))
                .Select(name => (Command: command.Name, Option: name)))
            .ToList();

        Assert.NotEmpty(undocumented);

        var refused = undocumented
            .Where(entry => Usage.Check(entry.Command, [entry.Command, entry.Option, "valeur"])
                is not null)
            .Select(entry => $"{entry.Command} {entry.Option}");

        Assert.True(!refused.Any(),
            $"Des options existantes mais non documentées sont refusées : {Join(refused)}. "
            + "« Non documentée » et « inexistante » sont deux choses différentes : ces "
            + "options-là sont lues par la commande, tapées sur de vraies lignes, et les "
            + "refuser casse un usage réel.");
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

    /// <summary>
    /// Every option each <c>CliHost</c> helper reads: the ones it reads itself, plus the ones
    /// the helpers it calls read. Helpers reading none are dropped — they have nothing to say
    /// about a command's surface, and keeping them would only make an empty match look like a
    /// checked one.
    /// </summary>
    private static Dictionary<string, HashSet<string>> HelperOptions()
    {
        var source = WithoutComments(Read("src/Rempart.Cli/CliHost.cs"));
        var declarations = HostMember.Matches(source).ToList();

        var bodies = declarations.ToDictionary(
            declaration => declaration.Groups[1].Value,
            declaration => source[declaration.Index..End(declarations, declaration, source.Length)],
            StringComparer.Ordinal);

        var options = bodies.ToDictionary(
            entry => entry.Key,
            entry => OptionRead.Matches(entry.Value)
                .Select(m => m.Groups[2].Value)
                .ToHashSet(StringComparer.Ordinal),
            StringComparer.Ordinal);

        // Closed by repetition rather than by recursion: ResolveLiveCatalog reads no option
        // of its own and reaches two that do, and a helper chain three deep would need the
        // second pass. One pass per helper is more than any chain can be.
        for (var pass = 0; pass < bodies.Count; pass++)
        {
            foreach (var (name, body) in bodies)
            {
                foreach (var callee in bodies.Keys.Where(other =>
                    !string.Equals(other, name, StringComparison.Ordinal)
                    && Regex.IsMatch(body, $@"\b{other}\s*\(")))
                {
                    options[name].UnionWith(options[callee]);
                }
            }
        }

        return options
            .Where(entry => entry.Value.Count > 0)
            .ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.Ordinal);
    }

    /// <summary>Where a member's text stops: at the next declaration, or at the end.</summary>
    private static int End(List<Match> declarations, Match current, int end) =>
        declarations.FirstOrDefault(next => next.Index > current.Index)?.Index ?? end;

    /// <summary>
    /// The source with its comment lines removed. A helper or an option named in a doc
    /// comment is a mention, and reading it as a call attributes options to code that never
    /// touches them.
    /// </summary>
    private static string WithoutComments(string source) =>
        Regex.Replace(source, @"(?m)^[ \t]*//.*$", string.Empty);

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

    /// <summary>The one class per command, as ADR-005 laid them out.</summary>
    private static IEnumerable<string> CommandFiles() =>
        Directory.EnumerateFiles(
            Path.Combine(RepositoryRoot, "src", "Rempart.Cli", "Commands"),
            "*Command.cs", SearchOption.TopDirectoryOnly);

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
