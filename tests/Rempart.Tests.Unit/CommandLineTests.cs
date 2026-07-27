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
/// Two of these tests used to pin defects rather than features — DET-ARITE-REPORT and
/// DET-EXPLAIN-POSITIONNEL, both now closed. Freezing a defect was never endorsing it: it
/// was making sure the fix, when it came, was visible in a diff. It was, and the last
/// section is what the diff shows — the assertions inverted rather than deleted, each
/// carrying the sentence it used to make.
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

    // ---- defects that were frozen here, now closed --------------------------

    /// <summary>
    /// The defect DET-ARITE-REPORT recorded, now asserted the other way round.
    ///
    /// <para>
    /// <b>What this used to say.</b> The test living here was named
    /// <c>Positional_and_OptionValue_disagree_on_a_value_that_starts_with_a_dash</c>, and
    /// it asserted the disagreement: on <c>rempart diff --report --baseline b.json a.json</c>
    /// <c>Positional</c> applied the no-dash rule, so <c>--report</c> consumed nothing —
    /// while <c>OptionValue("--report")</c>, the reader <c>diff</c> actually used, returned
    /// <c>"--baseline"</c> and the comparison went into a folder of that name. Two readers
    /// of one spelling, giving two answers about the same five tokens.
    /// </para>
    ///
    /// <para>
    /// <c>diff</c> now reads <c>--report</c> with <c>OptionalValue</c>, as <c>scan</c>
    /// always did. Both assertions below are about the same array on purpose: agreement is
    /// the property, and it cannot be stated by looking at either reader alone.
    /// <c>OptionValue</c> is still asserted for what it is — the disagreement was never a
    /// bug in that reader, only in choosing it here.
    /// </para>
    /// </summary>
    [Fact]
    public void Positional_and_OptionalValue_agree_on_a_value_that_starts_with_a_dash()
    {
        string[] args = ["diff", "--report", "--baseline", "b.json", "a.json"];

        Assert.Equal(["a.json"], CommandLine.Positional(args, ["--report", "--baseline"]));
        Assert.Null(CommandLine.OptionalValue(args, "--report"));

        // Unchanged, and still the reason the two readers are not interchangeable: this is
        // the answer diff used to file its report under.
        Assert.Equal("--baseline", CommandLine.OptionValue(args, "--report"));
    }

    /// <summary>
    /// <c>WordAt</c> at a non-zero index does not see an identifier written after an
    /// option — unchanged behaviour, and the reason <c>explain</c> stopped calling it that
    /// way.
    ///
    /// <para>
    /// This test froze DET-EXPLAIN-POSITIONNEL: <c>rempart explain --rules ./mes-regles
    /// WIN-CRED-001</c> read <c>--rules</c> at index 1, found no identifier, and listed the
    /// whole catalog instead of explaining the rule. The defect is closed and this
    /// assertion is untouched, because <c>WordAt</c> was never wrong — it answers about a
    /// fixed slot, which is exactly right for the command word at index 0 and exactly wrong
    /// for anything that an option may precede. What changed is the call site; the test
    /// below is the other half of the story.
    /// </para>
    /// </summary>
    [Fact]
    public void An_identifier_placed_after_an_option_is_not_seen() =>
        Assert.Null(CommandLine.WordAt(["explain", "--rules", "d", "WIN-CRED-001"], 1));

    /// <summary>
    /// And <c>Positional</c>, which <c>explain</c> now calls, does see it — with the
    /// command's real option list rather than a literal one, since a list that forgot
    /// <c>--rules</c> would hand back <c>["d", "WIN-CRED-001"]</c> and explain the folder.
    ///
    /// <para>
    /// The three orders are one property: where the identifier sits stops mattering. The
    /// bare form still yields nothing, which is what makes <c>rempart explain</c> list the
    /// catalog — closing the defect must not cost the listing.
    /// </para>
    /// </summary>
    [Fact]
    public void An_identifier_is_found_wherever_it_sits_among_the_options()
    {
        var valueTaking = CommandSurface.ValueTaking("explain");

        Assert.Equal(["WIN-CRED-001"], CommandLine.Positional(
            ["explain", "--rules", "d", "WIN-CRED-001"], valueTaking));

        Assert.Equal(["WIN-CRED-001"], CommandLine.Positional(
            ["explain", "WIN-CRED-001", "--rules", "d"], valueTaking));

        Assert.Empty(CommandLine.Positional(["explain", "--rules", "d"], valueTaking));
    }

    [Fact]
    public void The_command_word_is_read_only_when_it_is_not_an_option()
    {
        Assert.Null(CommandLine.WordAt(["--json"], 0));
        Assert.Equal("scan", CommandLine.WordAt(["scan", "--json"], 0));
        Assert.Null(CommandLine.WordAt([], 0));
    }
}
