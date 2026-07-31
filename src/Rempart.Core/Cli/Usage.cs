namespace Rempart.Core.Cli;

/// <summary>
/// Refuses a command line the tool cannot honour, before anything acts on it.
///
/// <para>
/// An unknown option used to be dropped in silence, and on an audit tool that is the defect
/// this whole repository is built against, turned on its own command line:
/// <c>rempart scan --replay capture.json</c> — the replay option is <c>--from</c> — scanned
/// the local machine and printed a report nothing distinguishes from a replay but its
/// header. The report never lied. It was never given the chance to say it had been asked for
/// something else.
/// </para>
///
/// <para>
/// Three spellings of that one sentence, and all three are refused, because all three end on
/// the same machine. A word nobody declares — <c>--replay</c>. A bare argument the command
/// has no reader for — <c>rempart scan capture.json</c>, the issue's own sentence one
/// keystroke away, which scanned the local machine and returned a report indistinguishable
/// from the replay that was meant. And an option that must carry a value, given none —
/// <c>rempart scan --from --json</c> fell back on the live scan, and <c>--rules</c> given
/// nothing runs the embedded catalog while the caller believes their own rules were loaded.
/// </para>
///
/// <para>
/// What is accepted comes from <see cref="CommandSurface"/> and from nowhere else, which is
/// what makes the refusal hold as the tool grows: <c>CommandSurfaceTests</c> holds that table
/// equal to the options the CLI really reads, so an option added tomorrow is refused until it
/// is declared there. There is no second list of accepted spellings to keep in step, and none
/// of rejected ones to complete. All three refusals read one record — the option names, their
/// arities, and how many bare arguments the command makes sense of — and each reads a
/// different part of it, which is what stops any part of that record from being decoration.
/// </para>
///
/// <para>
/// Two things it deliberately does not do. It does not read the help, because six declared
/// options are undocumented and people type them — « undocumented » and « inexistent » are
/// different, and merging them would break working command lines. And it says nothing about
/// what the arguments <em>mean</em>: whether two options contradict each other, whether a
/// path exists, whether a report is a report. Each command still answers for that. This door
/// answers for the shape its own declaration promised.
/// </para>
/// </summary>
public static class Usage
{
    /// <summary>
    /// The command word an unusable line already lands on, and the one command this check
    /// exempts.
    ///
    /// <para>
    /// The exemption is structural rather than a taste. The help is where the dispatch table
    /// sends every word it does not know, and <c>rempart --help</c> carries no command word
    /// at all — refusing options there would answer an unreadable line with a second
    /// unreadable line, and take the usage text away from the reader who needs it most. Every
    /// other command <em>acts</em> on what it was given, which is the entire harm.
    /// </para>
    ///
    /// <para>
    /// Declared here rather than in <c>Rempart.Cli</c>, which targets
    /// <c>net10.0-windows</c> and is not compiled by the Linux job, and confronted with the
    /// fallback arm of the dispatch table by
    /// <c>CommandSurfaceTests.The_command_the_usage_check_exempts_is_the_dispatch_fallback</c>.
    /// That holds the <em>constant</em>, which is only half of it: which commands
    /// <see cref="Check"/> really lets through is held by
    /// <c>UsageTests.Every_command_but_the_exempted_one_refuses_a_word_it_does_not_declare</c>,
    /// which walks <see cref="CommandSurface.All"/> instead of trusting this one — so that a
    /// second arm added to the condition below cannot quietly come to cover a command that
    /// does something. Measured: exempting <c>capture</c>, which writes a snapshot to disk,
    /// used to leave the whole suite green.
    /// </para>
    /// </summary>
    public const string Fallback = "help";

    /// <summary>
    /// What is wrong with this command line, or <c>null</c> when nothing is.
    ///
    /// <para>
    /// Takes the whole array, command word included — the very one the command would read —
    /// so that the answer is about the line that would actually run rather than about a
    /// tidied copy of it. <paramref name="command"/> is the word the dispatch resolved, which
    /// is <see cref="Fallback"/> when there was none; that case is exempt, so the walk below
    /// never has to wonder whether <c>args[0]</c> is a command word.
    /// </para>
    ///
    /// <para>
    /// One refusal at a time, and the unknown word first: a typo makes every later judgement
    /// a judgement about a line nobody typed. Told all three at once, a caller who wrote
    /// <c>--rule ./mes-regles</c> would be informed of the misspelling and of a bare argument
    /// that only exists because of it.
    /// </para>
    ///
    /// <para>
    /// Answers with a <see cref="FailureExit"/>, the pair the entry point already knows how
    /// to print and return, so refusing a line and failing on one leave by the same door.
    /// </para>
    /// </summary>
    public static FailureExit? Check(string command, string[] args)
    {
        if (string.Equals(command, Fallback, StringComparison.Ordinal))
        {
            return null;
        }

        // A word naming no command is not judged on its arguments: it already goes to the
        // help, which is the answer to a line nobody can parse. An option error about a
        // command that does not exist would bury the thing actually wrong.
        if (CommandSurface.Find(command) is not { } spec)
        {
            return null;
        }

        var declared = spec.Options.ToDictionary(
            option => option.Name, option => option.Arity, StringComparer.Ordinal);

        // One walk, and its two halves are read by two different refusals below. That is what
        // sharing the value-taking list buys, and it is not decoration: hand this walk an
        // empty one and « rempart scan --from capture.json » stops being a replay carrying a
        // path and becomes a command carrying a bare argument it never declared — refused, on
        // a line that works. The partition and the refusal cannot drift apart, because the
        // refusal is the partition read twice.
        var split = CommandLine.Split(args, CommandSurface.ValueTaking(command));

        var unknown = split.Options
            .Where(token => !declared.ContainsKey(token))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (unknown.Count > 0)
        {
            var named = Name(unknown);

            return Refuse(spec, unknown.Count == 1
                ? $"Option inconnue pour « {command} » : {named}."
                : $"Options inconnues pour « {command} » : {named}.");
        }

        var starved = Starved(args, declared);

        if (starved.Count > 0)
        {
            var named = Name(starved);

            return Refuse(spec, starved.Count == 1
                ? $"L'option {named} de « {command} » attend une valeur, et la ligne n'en donne "
                  + "aucune."
                : $"Les options {named} de « {command} » attendent une valeur, et la ligne n'en "
                  + "donne aucune.");
        }

        if (split.Positional.Count > spec.Positionals)
        {
            var named = Name([.. split.Positional.Skip(spec.Positionals)]);

            return Refuse(spec, spec.Positionals == 0
                ? $"« {command} » n'attend aucun argument : {named}."
                : $"« {command} » attend au plus {spec.Positionals} argument(s), et la ligne en "
                  + $"porte {split.Positional.Count} — en trop : {named}.");
        }

        return null;
    }

    /// <summary>
    /// The value-taking options this line names without giving one, each once.
    ///
    /// <para>
    /// The quietest half of the defect, and the one that leaves no trace at all: an option
    /// read with <see cref="CommandLine.OptionValue"/> and given nothing answers <c>null</c>,
    /// which is the same answer as never having been typed. <c>rempart scan --from --json</c>
    /// scanned the local machine having asked for a replay in as many words.
    /// </para>
    ///
    /// <para>
    /// « Given nothing » is the line <see cref="CommandLine.Split"/> already draws and is not
    /// redrawn here: the next token is a value only when it does not itself start with a dash.
    /// The two walks cannot disagree, because an option name starts with a dash and a token
    /// <c>Split</c> swallowed does not — so no token this loop stops on is one <c>Split</c>
    /// had already spoken for.
    /// </para>
    ///
    /// <para>
    /// An <see cref="OptionArity.OptionalValue"/> is left out by name: <c>--report</c> alone
    /// is what that arity exists for, and the point of the four readers disagreeing is that
    /// the disagreement is declared rather than guessed.
    /// </para>
    /// </summary>
    private static List<string> Starved(string[] args, Dictionary<string, OptionArity> declared)
    {
        var starved = new List<string>();

        for (var i = 1; i < args.Length; i++)
        {
            if (!declared.TryGetValue(args[i], out var arity)
                || arity is OptionArity.Flag or OptionArity.OptionalValue)
            {
                continue;
            }

            if (i + 1 >= args.Length || args[i + 1].StartsWith('-'))
            {
                starved.Add(args[i]);
            }
        }

        return [.. starved.Distinct(StringComparer.Ordinal)];
    }

    /// <summary>
    /// The sentence printed on stderr: what is wrong, that nothing ran — which is true because
    /// this runs ahead of the dispatch, and is the one fact separating this from the defect it
    /// closes — and then what the command does accept, derived from the surface rather than
    /// retyped.
    ///
    /// <para>
    /// The accepted list rides on all three refusals, including the two that are not about a
    /// spelling: <c>rempart scan capture.json</c> is somebody reaching for <c>--from</c> and
    /// not finding it, and <c>--from</c> is in that list. A message that only said « non »
    /// would leave them guessing the spelling, which is how the typo happened.
    /// </para>
    ///
    /// <para>
    /// A command with no option of its own says so, rather than printing an empty list that
    /// reads like truncation.
    /// </para>
    /// </summary>
    private static FailureExit Refuse(CommandSpec spec, string head)
    {
        var accepted = spec.Options.Count == 0
            ? $"« {spec.Name} » n'accepte aucune option."
            : "Options acceptées : "
              + string.Join(", ", spec.Options.Select(option => option.Name)
                  .OrderBy(name => name, StringComparer.Ordinal))
              + ".";

        return new FailureExit(ExitCode.Usage,
            $"{head} Rien n'a été exécuté." + Environment.NewLine + accepted);
    }

    /// <summary>
    /// Every offending word at once, not the first: a caller who fixes one, re-runs, and is
    /// told about the next is bisecting their own command line.
    /// </summary>
    private static string Name(IReadOnlyList<string> tokens) =>
        string.Join(", ", tokens.Select(token => $"« {token} »"));
}
