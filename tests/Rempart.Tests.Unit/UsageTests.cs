using Rempart.Core.Cli;

namespace Rempart.Tests.Unit;

/// <summary>
/// What the tool does with a command line naming something the command never declared.
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
/// Three spellings of that sentence, all tested here, because all three ended on the same
/// machine: the word nobody declares, the bare argument nobody reads
/// (<c>rempart scan capture.json</c> — the issue's own line, one keystroke away, exiting 5,
/// which all three CI gates accept), and the option left without the value it must carry
/// (<c>rempart scan --from --json</c>).
/// </para>
///
/// <para>
/// A fourth spelling sits one rank up and is the one the dispatch table used to answer on
/// purpose: the <em>command</em> word nobody declares. <c>rempart scna --replay capture.json</c>
/// printed the usage text and exited <c>0</c>, so a scheduler saw a run that had succeeded
/// while the tool had done something else entirely. It is refused on the same record as the
/// other three — the word is in <see cref="CommandSurface"/> or it is not — and the refusal is
/// walked over every command rather than sampled on the one the issue names.
/// </para>
///
/// <para>
/// The refusal is by construction rather than by list. <see cref="CommandSurface"/> is the
/// declared surface, and <c>CommandSurfaceTests</c> holds it equal to the options the CLI
/// really reads — so an option added tomorrow is refused until it is declared there, which
/// is the direction the defect came from, reversed. Nothing here enumerates option names;
/// the tests that walk the whole surface are what prove it, and they walk it on the refusal
/// side as well as on the acceptance side. That asymmetry was a hole: exempting a command
/// from the check outright used to leave the suite green.
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
            + $"« {command} » ne déclare pas tout ce qui est écrit là — ou n'est pas une "
            + "commande. La ligne part donc s'exécuter telle quelle : c'est le défaut "
            + "lui-même, une machine regardée pour une autre, ou l'aide imprimée avec un code "
            + "de réussite.");

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
    /// Each option written the way its declared arity says it is written: a flag alone, and
    /// anything that takes a value followed by one. That is the pairing under test — the
    /// arity is the promise that <c>Positional</c> and the option's own reader draw the same
    /// line — and giving a flag a trailing word would not be testing the option, it would be
    /// handing the command a bare argument it never declared.
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
                string[] line = option.Arity == OptionArity.Flag
                    ? [command.Name, option.Name]
                    : [command.Name, option.Name, "valeur"];

                if (Usage.Check(command.Name, line) is { } refusal)
                {
                    refused.Add($"{string.Join(' ', line)} — {refusal.Message}");
                }
            }
        }

        Assert.True(refused.Count == 0,
            "Une option que sa commande déclare a été refusée : "
            + $"{string.Join(" | ", refused)}. Le refus se lit sur la surface déclarée et sur "
            + "rien d'autre, sans quoi il casse des lignes de commande qui fonctionnent.");
    }

    /// <summary>
    /// An option that may be given bare is given bare, on every command that declares one.
    ///
    /// <para>
    /// <see cref="OptionArity.OptionalValue"/> is the whole of the distinction: <c>--report</c>
    /// alone writes the reports where they go by default, and <c>--report D:\audits</c> says
    /// where. Refusing the first would break the commoner of the two spellings, on the option
    /// most likely to be typed from memory.
    /// </para>
    /// </summary>
    [Fact]
    public void An_option_that_may_be_given_bare_is_accepted_bare()
    {
        var bare = CommandSurface.All
            .SelectMany(command => command.Options
                .Where(option => option.Arity is OptionArity.Flag or OptionArity.OptionalValue)
                .Select(option => (Command: command.Name, option.Name)))
            .ToList();

        // The premise: the day no command declares one of those two arities, this test stops
        // proving anything and has to say so.
        Assert.NotEmpty(bare);

        var refused = bare
            .Where(entry => Usage.Check(entry.Command, [entry.Command, entry.Name]) is not null)
            .Select(entry => $"{entry.Command} {entry.Name}");

        Assert.True(!refused.Any(),
            $"Une option qui peut être donnée nue a été refusée nue : {string.Join(", ", refused)}. "
            + "C'est l'arité déclarée qui dit laquelle des deux formes une option accepte, et un "
            + "refus qui ne la lit pas casse « rempart scan --report ».");
    }

    /// <summary>
    /// Every command but the exempted one refuses a word it does not declare — walked over
    /// <see cref="CommandSurface.All"/> rather than sampled.
    ///
    /// <para>
    /// The acceptance side has always been walked; the refusal side was six commands out of
    /// twenty, and the asymmetry was the hole. What <c>CommandSurfaceTests</c> confronts with
    /// the dispatch table is the <em>constant</em> <see cref="Usage.Fallback"/>; the set of
    /// commands <see cref="Usage.Check"/> actually lets through was held by nothing. Measured:
    /// adding <c>|| command == "capture"</c> to that condition — exempting a command that
    /// writes a snapshot to disk — left the whole suite green.
    /// </para>
    ///
    /// <para>
    /// The exempted command is asserted as the complement rather than assumed, so that an
    /// exemption removed is as visible as one added: the help must stay reachable from a line
    /// nobody can parse, which is what the exemption is for.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_command_but_the_exempted_one_refuses_a_word_it_does_not_declare()
    {
        const string Nobodys = "--replay";

        // The premise, and it is what makes the walk mean anything: the probe really is a word
        // no command declares. The day one does, this test would be asserting that a declared
        // option is refused.
        Assert.DoesNotContain(CommandSurface.All.SelectMany(command => command.Options),
            option => string.Equals(option.Name, Nobodys, StringComparison.Ordinal));

        var accepted = CommandSurface.All
            .Where(command =>
                Usage.Check(command.Name, [command.Name, Nobodys, "capture.json"]) is null)
            .Select(command => command.Name)
            .ToList();

        Assert.True(accepted is [Usage.Fallback],
            $"« {Nobodys} » passe sur : {string.Join(", ", accepted)}, attendu la seule "
            + $"« {Usage.Fallback} ». Une commande exemptée est une commande qui agit sur ce "
            + "qu'on lui a donné sans l'avoir lu — c'est le défaut entier — et l'exemption de "
            + "l'aide existe parce que l'aide, elle, n'agit sur rien : elle doit rester "
            + "joignable depuis une ligne que personne ne sait analyser.");
    }

    /// <summary>
    /// The issue's own sentence, one keystroke away: the caller types the path of the capture
    /// and forgets <c>--from</c>.
    ///
    /// <para>
    /// <c>rempart scan capture.json</c> scanned the local machine and returned a report nothing
    /// distinguishes from a replay — the same harm as <c>--replay</c>, with an exit code of 5
    /// that all three CI gates accept. The material to refuse it was in the record the check
    /// already reads: <c>scan</c> declares <c>Positionals: 0</c>, and the walk that answers
    /// « which tokens are options » answers « which are bare arguments » in the same pass.
    /// </para>
    ///
    /// <para>
    /// The refusal names <c>--from</c>, because that is what the caller was reaching for.
    /// </para>
    /// </summary>
    [Fact]
    public void The_capture_path_typed_without_its_option_is_refused_by_name()
    {
        var refusal = Refused("scan", ["scan", "capture.json"]);

        Assert.Contains(Named("capture.json"), refusal.Message, StringComparison.Ordinal);
        Assert.Contains("--from", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(ExitCode.Usage, refusal.Code);
    }

    /// <summary>
    /// The same, walked over the whole surface: one bare argument more than a command declares
    /// is refused, whichever command it is. Sampling <c>scan</c> would leave nineteen commands
    /// answering for themselves.
    /// </summary>
    [Fact]
    public void One_bare_argument_more_than_a_command_declares_is_refused_everywhere()
    {
        var accepted = new List<string>();

        foreach (var command in CommandSurface.All.Where(c => c.Name != Usage.Fallback))
        {
            string[] line =
            [
                command.Name,
                .. Enumerable.Range(0, command.Positionals + 1).Select(i => $"argument{i}"),
            ];

            if (Usage.Check(command.Name, line) is null)
            {
                accepted.Add(string.Join(' ', line));
            }
        }

        Assert.True(accepted.Count == 0,
            "Une commande accepte un argument nu de plus qu'elle n'en déclare : "
            + $"{string.Join(" | ", accepted)}. Elle le laissera tomber en silence et fera ce "
            + "qu'elle fait sans argument — « rempart scan capture.json » scannait ainsi la "
            + "machine locale et rendait un rapport que rien ne distinguait du rejeu demandé.");
    }

    /// <summary>
    /// The number a command declares is a ceiling, not a count: too few bare arguments is the
    /// command's own business, and answering it here would break the commands whose no-argument
    /// form is a feature — <c>rempart explain</c> alone lists the catalog, which is what
    /// DET-EXPLAIN-POSITIONNEL made it do by accident and what it legitimately does on purpose.
    /// </summary>
    [Fact]
    public void Fewer_bare_arguments_than_a_command_declares_is_the_command_s_own_business()
    {
        Assert.Null(Usage.Check("explain", ["explain"]));
        Assert.Null(Usage.Check("diff", ["diff", "avant.json"]));
        Assert.Null(Usage.Check("index", ["index"]));
    }

    /// <summary>
    /// The quietest half of the defect, and the one that leaves no trace: an option that must
    /// carry a value, given none, answers exactly as if it had never been typed.
    ///
    /// <para>
    /// <c>rempart scan --json --from</c> scanned the local machine having been asked for a
    /// replay in as many words — <see cref="CommandLine.OptionValue"/> found nothing after
    /// <c>--from</c> and returned <c>null</c>, which is what an absent option returns.
    /// <c>rempart scan --rules</c> runs the embedded catalog while the caller believes their
    /// own rules were loaded. Walked over the declared arities rather than sampled: which
    /// options must carry a value is the surface's answer, not this file's.
    /// </para>
    /// </summary>
    [Fact]
    public void An_option_that_must_carry_a_value_is_refused_without_one()
    {
        var mustCarry = CommandSurface.All
            .SelectMany(command => command.Options
                .Where(option => option.Arity
                    is OptionArity.Value or OptionArity.RepeatableValue)
                .Select(option => (Command: command.Name, option.Name)))
            .ToList();

        Assert.NotEmpty(mustCarry);

        var swallowed = mustCarry
            .Where(entry => Usage.Check(entry.Command, [entry.Command, entry.Name]) is null)
            .Select(entry => $"{entry.Command} {entry.Name}");

        Assert.True(!swallowed.Any(),
            $"Une option à valeur est acceptée sans valeur : {string.Join(", ", swallowed)}. "
            + "Son lecteur rend alors null, c'est-à-dire la même réponse que pour une option "
            + "absente : la commande retombe sur son défaut sans un mot.");
    }

    /// <summary>
    /// The same, on the shape it really takes on a command line: not at the end, but followed
    /// by the next option. <c>--from</c> then reads <c>--json</c> as the path to replay.
    /// </summary>
    [Fact]
    public void An_option_whose_value_is_the_next_option_is_refused()
    {
        var refusal = Refused("scan", ["scan", "--from", "--json"]);

        Assert.Contains(Named("--from"), refusal.Message, StringComparison.Ordinal);
        Assert.Equal(ExitCode.Usage, refusal.Code);
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
    /// The issue's own line: a command word misspelt, carrying an option that does not exist.
    ///
    /// <para>
    /// <c>rempart scna --replay capture.json</c> printed the usage text and exited <c>0</c>.
    /// The dispatch table sent every word it did not recognise to the help — a decision, and
    /// one it documented — so the tool did something other than what it was asked while the
    /// one channel a scheduler reads reported success. That is DET-OPTION-INCONNUE moved from
    /// the option to the command word, and closing it changes a contract rather than repairing
    /// an oversight.
    /// </para>
    ///
    /// <para>
    /// The word is named and the option is not, which is the « one refusal at a time » the
    /// unknown option already followed, applied one rank up: <c>--replay</c> is a judgement
    /// about the surface of <c>scna</c>, and <c>scna</c> has none. Told both, a caller would
    /// be sent to fix the spelling of an option belonging to a command that does not exist.
    /// </para>
    /// </summary>
    [Fact]
    public void The_command_typo_that_printed_the_help_and_returned_zero_is_refused_by_name()
    {
        var refusal = Refused("scna", ["scna", "--replay", "capture.json"]);

        Assert.Contains(Named("scna"), refusal.Message, StringComparison.Ordinal);
        Assert.Equal(ExitCode.Usage, refusal.Code);
        Assert.NotEqual(ExitCode.Success, refusal.Code);

        Assert.DoesNotContain("--replay", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A typo on <em>any</em> command word, walked over the whole surface rather than sampled
    /// on the one the issue happens to name.
    ///
    /// <para>
    /// The probes are derived, two per command, and neither family stands in for the other.
    /// One character short — <c>sca</c>, <c>hel</c>, <c>diagnose-wm</c> — is a word a command
    /// <em>starts with</em>, which is what a lookup written loosely would answer for. One
    /// character long — <c>scanx</c>, <c>helpx</c> — is a word that <em>starts with</em> a
    /// command, which is what a loose exemption lets in. Forty typos written out here would be
    /// a second list, and the command added tomorrow would be in neither.
    /// </para>
    ///
    /// <para>
    /// The second family is not symmetry for its own sake; it was measured. With the short one
    /// alone, loosening the exemption below to
    /// <c>command.StartsWith(Fallback, StringComparison.Ordinal)</c> — one token — left all
    /// 1 049 tests green while <c>rempart helpme --replay capture.json</c> printed the usage
    /// text and exited <c>0</c> again: the defect entire, on any word beginning with « help ».
    /// </para>
    ///
    /// <para>
    /// <c>help</c> is walked like the rest, deliberately: what <see cref="Usage.Check"/>
    /// exempts is that word and not anything resembling it. <c>hel</c> is not the help, and
    /// answering it with the help and a code of success is the defect.
    /// </para>
    ///
    /// <para>
    /// The line carries nothing but the word, which is the harshest shape: there is no option
    /// to complain about, so a refusal can only come from the word itself.
    /// </para>
    ///
    /// <para>
    /// « By construction » is on the alphabet that reaches this check, and that is narrower
    /// than it sounds: <c>-scan</c> and <c>--scan</c> are not in the two families and would
    /// fail if they were, because <see cref="CommandLine.WordAt"/> answers <c>null</c> as soon
    /// as the first token starts with a dash, so the line resolves to
    /// <see cref="Usage.Fallback"/> and never gets here. A misspelt command word wearing a dash
    /// still prints the help and exits <c>0</c> — measured on the binary,
    /// <c>rempart -scan --from t.json</c> → 0 — and that is the same open question as
    /// <c>rempart --json</c> rather than a hole this walk was meant to cover.
    /// </para>
    /// </summary>
    [Fact]
    public void A_typo_on_any_command_word_is_refused_rather_than_answered_with_the_help()
    {
        var declared = CommandSurface.All
            .Select(command => command.Name)
            .ToHashSet(StringComparer.Ordinal);

        var typos = declared
            .SelectMany(name => new[] { name[..^1], name + "x" })
            .ToList();

        // The premise, and it is what makes the walk mean anything: the probes really are
        // words no command goes by, there are two per command, and no two of them are the
        // same word. Were a probe a command, this test would be asserting that a declared
        // command is refused; were the two families to collapse into one, half the looseness
        // above would stop being watched.
        Assert.DoesNotContain(typos, declared.Contains);
        Assert.Equal(CommandSurface.All.Count * 2, typos.Count);
        Assert.Equal(typos.Count, typos.Distinct(StringComparer.Ordinal).Count());

        var swallowed = typos
            .Where(typo => Usage.Check(typo, [typo]) is null)
            .OrderBy(typo => typo, StringComparer.Ordinal)
            .ToList();

        Assert.True(swallowed.Count == 0,
            $"Des mots de commande que rien ne déclare passent : {string.Join(", ", swallowed)}. "
            + "Ils partent au bras par défaut du dispatch, qui imprime l'aide et rend 0 : "
            + "l'outil a fait autre chose que ce qu'on lui demandait, et le seul canal qu'une "
            + "machine lit dit que tout va bien.");
    }

    /// <summary>
    /// The lookup is exact. Case, an edge of whitespace and the empty word are three ways of
    /// not being a command, and each of them used to print the help and exit <c>0</c>.
    ///
    /// <para>
    /// <c>Help</c> is the one that matters: the exemption is a comparison against
    /// <see cref="Usage.Fallback"/> and it is ordinal, so a word that merely looks like the
    /// help does not inherit what the help is exempted for.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("Scan")]
    [InlineData("SCAN")]
    [InlineData("Help")]
    [InlineData("scan ")]
    [InlineData(" scan")]
    [InlineData("")]
    public void A_word_that_only_resembles_a_command_is_refused(string word) =>
        Assert.NotNull(Usage.Check(word, [word]));

    /// <summary>
    /// The refusal prints the commands that do exist, derived from <see cref="CommandSurface"/>
    /// rather than retyped — the same reason the option refusal prints the accepted options. A
    /// message that only says « non » leaves the reader guessing the spelling, which is how the
    /// typo happened; <c>scan</c> is in that list, and it is what whoever typed <c>scna</c> was
    /// reaching for.
    /// </summary>
    [Fact]
    public void The_refusal_of_an_unknown_command_names_the_commands_that_exist()
    {
        var refusal = Refused("scna", ["scna"]);

        foreach (var command in CommandSurface.All)
        {
            Assert.Contains(command.Name, refusal.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The help stays reachable from a line it could not parse — including
    /// <c>rempart --help</c> and bare <c>rempart</c>, which carry no command word at all.
    ///
    /// <para>
    /// The single exemption, and it is structural rather than a taste: the help is where a line
    /// nobody can parse already goes, and it acts on nothing. Every other command acts, which
    /// is the whole harm. That the exempted word really is the dispatch table's fallback is
    /// checked against the table on disk, in <c>CommandSurfaceTests</c>.
    /// </para>
    ///
    /// <para>
    /// The resolution written below is a <em>copy</em> of the one <c>Program.cs</c> performs,
    /// and saying otherwise would be the second list this repository forbids everywhere else:
    /// nothing in this project compiles <c>Rempart.Cli</c>, so this test cannot read that line
    /// and would stay green while it changed. It is written that way rather than with
    /// <see cref="Usage.Fallback"/> handed over outright because that is where the boundary of
    /// the command-word refusal sits — a check reading « this word names no command » and given
    /// the raw <c>args[0]</c> answers the two commonest lines of the tool, no word and
    /// <c>--help</c>, with an error and a code of 6 — but what holds the entry point to it is
    /// <c>BuildChainParityTests</c>, which requires the build chain to run the binary itself on
    /// <c>rempart --help</c> and demand a 0.
    /// </para>
    /// </summary>
    [Fact]
    public void The_help_is_reachable_from_a_line_it_could_not_parse()
    {
        string[][] lines = [[], ["--help"], ["help"], ["help", "--replay"]];

        foreach (var line in lines)
        {
            Assert.Null(Usage.Check(CommandLine.WordAt(line, 0) ?? Usage.Fallback, line));
        }
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
