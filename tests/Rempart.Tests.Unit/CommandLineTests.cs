using Rempart.Core.Cli;

namespace Rempart.Tests.Unit;

/// <summary>
/// The argument parser, which decides which file is read and which folder is written to.
///
/// <para>
/// Sixty lines that shipped without a test, in a tool whose commands take a private key,
/// an output directory and a signed manifest. The four readers disagree with one another
/// by design; every disagreement below is the behaviour that ships today, written down so
/// that changing it becomes a decision instead of an accident.
/// </para>
///
/// <para>
/// Two of these tests pin defects rather than features — cases 15 and 18. They are named
/// as such. Freezing a defect is not endorsing it: it is making sure the fix, when it
/// comes, is visible in a diff.
/// </para>
/// </summary>
public sealed class CommandLineTests
{
    // ---- options that must carry a value -----------------------------------

    [Fact]
    public void A_value_option_at_the_end_of_the_array_reads_as_absent()
    {
        Assert.Null(CommandLine.OptionValue(["scan", "--from"], "--from"));
        Assert.Null(CommandLine.OptionValue(["scan"], "--from"));
    }

    /// <summary>
    /// <c>--from --json</c> yields <c>"--json"</c>: the reader takes what follows without
    /// looking at it. Deliberate — an option that must have a value cannot guess that the
    /// user forgot it — and the reason <c>OptionalValue</c> exists for the cases where the
    /// guess matters.
    /// </summary>
    [Fact]
    public void A_value_option_swallows_the_next_token_even_when_it_is_an_option() =>
        Assert.Equal("--json", CommandLine.OptionValue(["scan", "--from", "--json"], "--from"));

    /// <summary>
    /// And the flag reader still sees that same token. Both readings are true at once, on
    /// the same array: <c>--json</c> is the value of <c>--from</c> and a flag that is set.
    /// </summary>
    [Fact]
    public void A_flag_is_seen_even_when_it_is_the_value_of_another_option() =>
        Assert.True(CommandLine.HasFlag(["scan", "--from", "--json"], "--json"));

    [Fact]
    public void A_single_value_option_keeps_only_its_first_occurrence() =>
        Assert.Equal("a", CommandLine.OptionValue(["scan", "--from", "a", "--from", "b"], "--from"));

    [Fact]
    public void Option_names_are_matched_case_sensitively() =>
        Assert.Null(CommandLine.OptionValue(["scan", "--FROM", "a"], "--from"));

    // ---- options whose value is optional -----------------------------------

    /// <summary>
    /// The case the parser exists for: without this, <c>rempart scan --report --json</c>
    /// writes the audit into a folder named <c>--json</c>.
    /// </summary>
    [Fact]
    public void An_optional_value_option_refuses_a_value_that_starts_with_a_dash() =>
        Assert.Null(CommandLine.OptionalValue(["scan", "--report", "--json"], "--report"));

    /// <summary>
    /// The value is opaque: never split, never normalised, never combined. A Windows path
    /// parses identically on the Linux job, which is what lets this test run there at all.
    /// </summary>
    [Fact]
    public void An_optional_value_option_accepts_the_folder_that_follows() =>
        Assert.Equal(@"D:\audits",
            CommandLine.OptionalValue(["scan", "--report", @"D:\audits"], "--report"));

    // ---- repeatable options ------------------------------------------------

    [Fact]
    public void A_repeated_value_option_yields_every_occurrence_in_order() =>
        Assert.Equal(["a", "b"],
            CommandLine.OptionValues(["synthesise", "--deny", "a", "--deny", "b"], "--deny"));

    /// <summary>
    /// The loop stops one short of the end, so a repeatable option in last position
    /// contributes nothing — silently, like the single-value readers.
    /// </summary>
    [Fact]
    public void A_repeated_option_at_the_end_of_the_array_contributes_nothing() =>
        Assert.Empty(CommandLine.OptionValues(["synthesise", "--deny"], "--deny"));

    /// <summary>
    /// <c>--deny --deny x</c> reads as the two values <c>--deny</c> and <c>x</c>: the
    /// first occurrence takes the second as its value, and the second is then read again
    /// on its own. Frozen here rather than discovered on someone's command line.
    /// </summary>
    [Fact]
    public void A_repeated_option_whose_value_is_its_own_name_is_read_verbatim() =>
        Assert.Equal(["--deny", "x"],
            CommandLine.OptionValues(["synthesise", "--deny", "--deny", "x"], "--deny"));

    // ---- positional arguments ----------------------------------------------

    [Fact]
    public void The_command_word_is_never_positional()
    {
        Assert.Equal(["a.json"], CommandLine.Positional(["diff", "a.json"], []));
        Assert.Empty(CommandLine.Positional(["index"], ["--out"]));
    }

    [Fact]
    public void A_positional_after_a_value_option_is_still_positional() =>
        Assert.Equal(["after.json"], CommandLine.Positional(
            ["diff", "--baseline", "b.json", "after.json"], ["--report", "--baseline"]));

    /// <summary>
    /// Two rules at once on the same line: <c>--report</c> consumes nothing because what
    /// follows it is an option, and <c>--baseline</c> does consume <c>b.json</c>. Only
    /// <c>after.json</c> is left, which is the file the command compares.
    /// </summary>
    [Fact]
    public void A_value_taking_option_does_not_swallow_the_next_option() =>
        Assert.Equal(["after.json"], CommandLine.Positional(
            ["diff", "--report", "--baseline", "b.json", "after.json"],
            ["--report", "--baseline"]));

    [Fact]
    public void A_flag_never_swallows_the_token_that_follows_it() =>
        Assert.Equal(["rapport.json"],
            CommandLine.Positional(["scan", "--json", "rapport.json"], ["--report"]));

    [Fact]
    public void An_empty_argument_array_yields_nothing()
    {
        Assert.Empty(CommandLine.Positional([], ["--out"]));
        Assert.Null(CommandLine.OptionValue([], "--out"));
        Assert.False(CommandLine.HasFlag([], "--out"));
        Assert.Empty(CommandLine.OptionValues([], "--out"));
    }

    [Fact]
    public void A_bare_dash_is_not_a_positional() =>
        Assert.Equal(["a.json"], CommandLine.Positional(["diff", "-", "a.json"], []));

    // ---- known defects, frozen ---------------------------------------------

    /// <summary>
    /// DEFECT, frozen. On <c>rempart diff --report --baseline b.json a.json</c> the two
    /// readers disagree: <c>Positional</c> applies the no-dash rule, so <c>--report</c>
    /// consumes nothing and the single file to compare is <c>a.json</c> — while
    /// <c>OptionValue("--report")</c> returns <c>"--baseline"</c> and the comparison is
    /// written into a folder of that name.
    ///
    /// <para>
    /// The cause is an arity mismatch: <c>diff</c> reads <c>--report</c> with
    /// <c>OptionValue</c> while <c>scan</c> reads it with <c>OptionalValue</c>. Recorded as
    /// DET-ARITE-REPORT in <c>docs/DEBT.md</c>; fixing it changes what an existing command
    /// line does, so it gets its own change rather than riding along with an extraction.
    /// </para>
    /// </summary>
    [Fact]
    public void Positional_and_OptionValue_disagree_on_a_value_that_starts_with_a_dash()
    {
        string[] args = ["diff", "--report", "--baseline", "b.json", "a.json"];

        Assert.Equal(["a.json"], CommandLine.Positional(args, ["--report", "--baseline"]));
        Assert.Equal("--baseline", CommandLine.OptionValue(args, "--report"));
    }

    /// <summary>
    /// DEFECT, frozen. <c>explain</c> reads its identifier at a fixed slot instead of
    /// through <c>Positional</c>, so <c>rempart explain --rules ./mes-regles WIN-CRED-001</c>
    /// finds no identifier and lists the whole catalog instead of explaining the rule.
    /// Recorded as DET-EXPLAIN-POSITIONNEL; fixed where the commands are split.
    /// </summary>
    [Fact]
    public void An_identifier_placed_after_an_option_is_not_seen() =>
        Assert.Null(CommandLine.WordAt(["explain", "--rules", "d", "WIN-CRED-001"], 1));

    [Fact]
    public void The_command_word_is_read_only_when_it_is_not_an_option()
    {
        Assert.Null(CommandLine.WordAt(["--json"], 0));
        Assert.Equal("scan", CommandLine.WordAt(["scan", "--json"], 0));
        Assert.Null(CommandLine.WordAt([], 0));
    }
}
