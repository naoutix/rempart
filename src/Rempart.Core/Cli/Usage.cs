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
/// something else. The quieter shape is the same: a typo on an option carrying a value drops
/// the command onto its default, so <c>--rule</c> runs the embedded catalog while the caller
/// believes their own rules were loaded.
/// </para>
///
/// <para>
/// What is accepted comes from <see cref="CommandSurface"/> and from nowhere else, which is
/// what makes the refusal hold as the tool grows: <c>CommandSurfaceTests</c> holds that table
/// equal to the options the CLI really reads, so an option added tomorrow is refused until it
/// is declared there. There is no second list of accepted spellings to keep in step, and none
/// of rejected ones to complete.
/// </para>
///
/// <para>
/// Two things it deliberately does not do. It does not read the help, because six declared
/// options are undocumented and people type them — « undocumented » and « inexistent » are
/// different, and merging them would break working command lines. And it says nothing about
/// how many bare arguments a command was given, or about options that contradict each other:
/// each command still answers for its own arguments, and this door only refuses a word the
/// command has no reader for.
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
    /// <c>CommandSurfaceTests.The_command_the_usage_check_exempts_is_the_dispatch_fallback</c>
    /// — so that the exemption cannot quietly come to cover a command that does something.
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

        var unknown = CommandSurface.Unknown(command, args);

        return unknown.Count == 0
            ? null
            : new FailureExit(ExitCode.Usage, Refusal(command, unknown));
    }

    /// <summary>
    /// The sentence printed on stderr. It names the offending words, states that nothing ran
    /// — which is true because this runs ahead of the dispatch, and is the one fact that
    /// separates this from the defect it closes — and then lists what the command does
    /// accept, derived from the surface rather than retyped.
    ///
    /// <para>
    /// Every unknown word at once, not the first: a caller who fixes one, re-runs, and is
    /// told about the next is bisecting their own command line. And a command with no option
    /// of its own says so, rather than printing an empty list that reads like truncation.
    /// </para>
    /// </summary>
    private static string Refusal(string command, IReadOnlyList<string> unknown)
    {
        var named = string.Join(", ", unknown.Select(option => $"« {option} »"));

        var head = unknown.Count == 1
            ? $"Option inconnue pour « {command} » : {named}."
            : $"Options inconnues pour « {command} » : {named}.";

        var accepted = CommandSurface.Find(command)?.Options ?? [];

        var tail = accepted.Count == 0
            ? $"« {command} » n'accepte aucune option."
            : "Options acceptées : "
              + string.Join(", ", accepted.Select(option => option.Name)
                  .OrderBy(name => name, StringComparer.Ordinal))
              + ".";

        return $"{head} Rien n'a été exécuté." + Environment.NewLine + tail;
    }
}
