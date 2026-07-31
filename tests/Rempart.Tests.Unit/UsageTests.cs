using Rempart.Core.Cli;

namespace Rempart.Tests.Unit;

/// <summary>
/// What the tool does with a word on its command line that nobody declared.
///
/// <para>
/// It used to do nothing at all. <c>rempart scan --replay capture.json</c> — the replay
/// option is <c>--from</c>, <c>--replay</c> does not exist — scanned the local machine and
/// printed a report nothing distinguishes from a replay but its header. That is the failure
/// this repository is built against, turned on its own command line: someone believes they
/// looked at one machine and looked at another. The report never lied; it was simply never
/// given the chance to say it had been asked for something else.
/// </para>
///
/// <para>
/// The refusal is by construction rather than by list. <see cref="CommandSurface"/> is the
/// declared surface, and <c>CommandSurfaceTests</c> holds it equal to the options the CLI
/// really reads — so an option added tomorrow is refused until it is declared there, which
/// is the direction the defect came from, reversed. Nothing here enumerates option names;
/// the test that walks the whole surface is what proves it.
/// </para>
/// </summary>
public sealed class UsageTests
{
    /// <summary>
    /// A token as the refusal names it. Every assertion below goes through this rather than
    /// looking for a bare <c>--rule</c>, which the printed list of accepted options contains
    /// as a substring of <c>--rules</c> — an assertion that would hold on a refusal naming
    /// the wrong token, or on no refusal at all.
    /// </summary>
    private static string Named(string token) => $"« {token} »";

    /// <summary>
    /// The refusal a line must have drawn, or a failure naming the line that drew none.
    ///
    /// <para>
    /// Dereferencing <c>Check</c>'s answer with <c>!</c> turns « rien n'a été refusé » into a
    /// <see cref="NullReferenceException"/> on the following line: whoever breaks the check
    /// reads a stack trace where the sentence should say what the tool went on to do instead.
    /// Measured — inverting one condition in <c>Split</c> reddened this file with nothing but
    /// null dereferences.
    /// </para>
    /// </summary>
    private static FailureExit Refused(string command, string[] args)
    {
        var refusal = Usage.Check(command, args);

        Assert.True(refusal is not null,
            $"« rempart {string.Join(' ', args)} » n'a pas été refusée, alors que "
            + $"« {command} » ne déclare pas tout ce qui est écrit là. La ligne part donc "
            + "s'exécuter telle quelle : c'est le défaut lui-même, une machine regardée pour "
            + "une autre.");

        return refusal!;
    }

    /// <summary>
    /// The case in the issue, kept whole: the command word, the typo, and a file name that
    /// makes the line look like a replay to whoever typed it.
    /// </summary>
    [Fact]
    public void The_replay_typo_that_scanned_the_local_machine_is_refused_by_name()
    {
        var refusal = Refused("scan", ["scan", "--replay", "capture.json"]);

        Assert.Contains(Named("--replay"), refusal.Message, StringComparison.Ordinal);
        Assert.Contains(Named("scan"), refusal.Message, StringComparison.Ordinal);

        // The option that was meant is named too: the accepted list is printed and --from is
        // in it. A refusal that only says « non » leaves the reader guessing the spelling,
        // which is how the typo happened.
        Assert.Contains("--from", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A usage error is not an execution failure, and the number says so. <c>1</c> means a
    /// run was attempted and broke; here nothing ran, and a scheduler retrying on <c>1</c>
    /// would retry a word that will never exist.
    /// </summary>
    [Fact]
    public void An_unknown_option_is_not_reported_as_a_run_that_failed()
    {
        var refusal = Refused("scan", ["scan", "--replay", "capture.json"]);

        Assert.Equal(ExitCode.Usage, refusal.Code);
        Assert.NotEqual(ExitCode.Failure, refusal.Code);
        Assert.Equal(6, (int)refusal.Code);
    }

    /// <summary>
    /// The quieter half of the defect: a typo on an option that carries a value drops the
    /// command back onto its default without a word. <c>--rule</c> for <c>--rules</c> runs
    /// the embedded catalog while the caller believes their own rules were loaded;
    /// <c>--form</c> for <c>--format</c> writes all three report formats.
    /// </summary>
    [Theory]
    [InlineData("scan", "--rule", "./mes-regles")]
    [InlineData("report", "--form", "json")]
    [InlineData("scan", "--virustotal-keys", "abc")]
    [InlineData("update", "--uri", "https://example.invalid")]
    public void A_typo_on_an_option_that_carries_a_value_is_refused_rather_than_ignored(
        string command, string typo, string value)
    {
        var refusal = Refused(command, [command, typo, value]);

        Assert.Contains(Named(typo), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The whole declared surface, accepted — the guard that says this refusal cannot break
    /// a line that works today. Walked rather than listed: an option added to
    /// <see cref="CommandSurface"/> tomorrow is covered without anyone remembering this file
    /// exists, which is the difference between a check by construction and a second list.
    ///
    /// <para>
    /// Both shapes, because the four readers disagree about them: the option followed by a
    /// value, and the option alone at the end of the line — which is what an
    /// <see cref="OptionArity.OptionalValue"/> is for, and what every reader tolerates.
    /// </para>
    ///
    /// <para>
    /// This is also where « undocumented » and « inexistent » are told apart on the value
    /// side. Six declared options are absent from the help — <c>scan --store</c> among them —
    /// and they go through here like the rest. The other side of that distinction is asserted
    /// against the help text itself, in <c>CommandSurfaceTests</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_option_every_command_declares_is_accepted()
    {
        var refused = new List<string>();

        foreach (var command in CommandSurface.All)
        {
            foreach (var option in command.Options)
            {
                if (Usage.Check(command.Name, [command.Name, option.Name, "valeur"]) is { } withValue)
                {
                    refused.Add($"{command.Name} {option.Name} <valeur> — {withValue.Message}");
                }

                if (Usage.Check(command.Name, [command.Name, option.Name]) is { } bare)
                {
                    refused.Add($"{command.Name} {option.Name} — {bare.Message}");
                }
            }
        }

        Assert.True(refused.Count == 0,
            "Une option que sa commande déclare a été refusée : "
            + $"{string.Join(" | ", refused)}. Le refus se lit sur la surface déclarée et sur "
            + "rien d'autre, sans quoi il casse des lignes de commande qui fonctionnent.");
    }

    /// <summary>
    /// Two options at once, in both orders, on the command carrying the most of them: a
    /// check that stopped at the first token would pass every case above.
    /// </summary>
    [Fact]
    public void Several_options_on_one_line_are_all_read()
    {
        Assert.Null(Usage.Check("scan", ["scan", "--json", "--probe-dns", "--fetch-pac"]));

        var last = Refused("scan", ["scan", "--json", "--replay"]);
        Assert.Contains(Named("--replay"), last.Message, StringComparison.Ordinal);

        var first = Refused("scan", ["scan", "--replay", "--json"]);
        Assert.Contains(Named("--replay"), first.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every unknown option on the line is named, not just the first: a caller who fixes one
    /// and re-runs to be told about the next is bisecting their own command line.
    /// </summary>
    [Fact]
    public void Every_unknown_option_on_the_line_is_named()
    {
        var refusal = Refused("scan", ["scan", "--replay", "--rejeu"]);

        Assert.Contains(Named("--replay"), refusal.Message, StringComparison.Ordinal);
        Assert.Contains(Named("--rejeu"), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The value of an option is not an option, and a bare argument is not one either. Both
    /// are what a check reading the raw tokens would get wrong — and getting them wrong means
    /// refusing a line that works, which is worse than the silence being closed.
    /// </summary>
    [Fact]
    public void A_value_and_a_bare_argument_are_not_taken_for_options()
    {
        Assert.Null(Usage.Check("scan", ["scan", "--from", "capture.json"]));
        Assert.Null(Usage.Check("synthesise",
            ["synthesise", "--deny", "fragment", "--deny", "autre"]));
        Assert.Null(Usage.Check("diff", ["diff", "avant.json", "apres.json"]));
        Assert.Null(Usage.Check("explain", ["explain", "WIN-CRED-001", "--rules", "d"]));
        Assert.Null(Usage.Check("explain", ["explain", "--rules", "d", "WIN-CRED-001"]));
        Assert.Null(Usage.Check("index", ["index", "reports", "--out", "parc.html"]));
    }

    /// <summary>
    /// Frozen rather than fixed, because the parser has no way of knowing: <c>--from</c>
    /// takes the next token whatever it looks like, so <c>--replay</c> is at once its value
    /// and something that reads as an option. Refusing is the answer an audit tool owes —
    /// the alternative is to go and scan whatever <c>--replay</c> turns out to name, and say
    /// nothing. It is also the line <c>Positional</c> already drew, which is why the two
    /// cannot disagree: they walk the arguments together.
    /// </summary>
    [Fact]
    public void A_value_that_reads_as_an_option_is_refused_rather_than_swallowed()
    {
        var refusal = Refused("scan", ["scan", "--from", "--replay"]);

        Assert.Contains(Named("--replay"), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A lone dash used to be dropped on the floor — <c>Positional</c> refuses it and no
    /// reader claims it, so the token reached nothing at all. It is a token nobody declared,
    /// and it is now said out loud rather than ignored.
    /// </summary>
    [Fact]
    public void A_lone_dash_is_a_token_nobody_declared()
    {
        var refusal = Refused("diff", ["diff", "-", "avant.json", "apres.json"]);

        Assert.Contains(Named("-"), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A word naming no command is not judged on its options: it already goes to the help,
    /// which is the answer to a line nobody can parse. Refusing here would print an option
    /// error about a command that does not exist, burying the thing actually wrong.
    /// </summary>
    [Fact]
    public void A_word_that_names_no_command_is_not_judged_on_its_options() =>
        Assert.Null(Usage.Check("scna", ["scna", "--replay", "capture.json"]));

    /// <summary>
    /// The help stays reachable from a line it could not parse — including
    /// <c>rempart --help</c>, which carries no command word at all and lands on the fallback.
    ///
    /// <para>
    /// The single exemption, and it is structural rather than a taste: the help is where an
    /// unusable command line already goes, and it acts on nothing. Every other command acts,
    /// which is the whole harm. That the exempted word really is the dispatch table's
    /// fallback is checked against the table on disk, in <c>CommandSurfaceTests</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void The_help_is_reachable_from_a_line_it_could_not_parse()
    {
        Assert.Null(Usage.Check(Usage.Fallback, ["--help"]));
        Assert.Null(Usage.Check(Usage.Fallback, ["help", "--replay"]));
        Assert.Null(Usage.Check(Usage.Fallback, []));
    }

    /// <summary>
    /// The refusal prints what the command does accept, derived from the surface rather than
    /// retyped — a message listing options by hand would rot exactly where the defect grew.
    /// </summary>
    [Fact]
    public void The_refusal_lists_what_the_command_accepts()
    {
        var refusal = Refused("update", ["update", "--replay"]);

        foreach (var option in CommandSurface.Find("update")!.Options)
        {
            Assert.Contains(option.Name, refusal.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A command with no option of its own says so, rather than printing an empty list and
    /// leaving the reader to wonder what got truncated.
    /// </summary>
    [Fact]
    public void A_command_that_accepts_no_option_says_so()
    {
        // The premise, asserted rather than assumed: this test proves nothing the day
        // « version » grows an option.
        Assert.Empty(CommandSurface.Find("version")!.Options);

        var refusal = Refused("version", ["version", "--json"]);

        Assert.Contains(Named("--json"), refusal.Message, StringComparison.Ordinal);
        Assert.Contains("aucune option", refusal.Message, StringComparison.Ordinal);
    }
}
