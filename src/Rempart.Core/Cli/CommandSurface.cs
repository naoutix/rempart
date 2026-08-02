namespace Rempart.Core.Cli;

/// <summary>
/// How many tokens an option takes, and which reader of <see cref="CommandLine"/> takes
/// them. The four readers disagree on purpose, so the arity is not decoration: it names
/// which disagreement a given option was written against.
/// </summary>
public enum OptionArity
{
    /// <summary>Present or absent — <see cref="CommandLine.HasFlag"/>.</summary>
    Flag,

    /// <summary>
    /// Takes the next token whatever it looks like — <see cref="CommandLine.OptionValue"/>.
    /// </summary>
    Value,

    /// <summary>
    /// May be given bare — <see cref="CommandLine.OptionalValue"/>, which refuses a value
    /// starting with a dash so that <c>scan --report --json</c> does not file the reports
    /// into a folder named <c>--json</c>.
    /// </summary>
    OptionalValue,

    /// <summary>Accumulates every occurrence — <see cref="CommandLine.OptionValues"/>.</summary>
    RepeatableValue,
}

/// <summary>An option a command reads, and how it reads it.</summary>
public sealed record CommandOption(string Name, OptionArity Arity);

/// <summary>
/// One command's whole argument surface: what it accepts and how many bare arguments it
/// makes sense of.
///
/// <para>
/// <paramref name="Positionals"/> is a ceiling and not a count. Zero of them is legitimate
/// almost everywhere — <c>rempart explain</c> with no identifier lists the catalog, and that
/// is what it is for — so a command answers for having too few; what nobody could answer for
/// was having too many. <c>rempart scan capture.json</c> declared none, was given one, and
/// scanned the local machine.
/// </para>
/// </summary>
public sealed record CommandSpec(string Name, IReadOnlyList<CommandOption> Options, int Positionals);

/// <summary>
/// The hand-written table of what every command accepts.
///
/// <para>
/// Written by hand for the same reason the dispatch table is (ADR-001): a surface
/// discovered by reflection would not survive Native AOT, and a source generator would be
/// a second build-time dependency in a tool that advertises one dependency in total. The
/// cost of writing it by hand is that it can drift from the commands, which is precisely
/// what <c>CommandSurfaceTests</c> refuses to let happen.
/// </para>
///
/// <para>
/// It earns its keep immediately rather than only documenting: <see cref="ValueTaking"/>
/// replaces the two literal lists that <c>diff</c> and <c>index</c> used to hand to
/// <see cref="CommandLine.Positional"/>. Those lists were a third place to remember an
/// option, and forgetting one there is silent — the option's value would be mistaken for
/// a positional argument, so <c>rempart diff --baseline b.json a.json</c> would try to
/// compare <c>b.json</c> with <c>a.json</c> as if two reports had been named.
/// </para>
///
/// <para>
/// It sits in Core, not beside the commands, for the reason ADR-005 had to record twice:
/// <c>Rempart.Cli</c> targets <c>net10.0-windows</c> and the Linux job does not compile
/// it, so a table living there could carry no test that CI runs.
/// </para>
/// </summary>
public static class CommandSurface
{
    /// <summary>
    /// Every command the dispatch table knows, including <c>help</c> — which is reached
    /// both by name and as the fallback for anything unrecognised.
    /// </summary>
    public static IReadOnlyList<CommandSpec> All { get; } =
    [
        new("scan",
        [
            new("--from", OptionArity.Value),
            new("--json", OptionArity.Flag),
            new("--report", OptionArity.OptionalValue),
            new("--rules", OptionArity.Value),
            new("--store", OptionArity.Value),
            new("--analyze-store", OptionArity.Flag),
            new("--virustotal-key", OptionArity.Value),
            new("--fetch-pac", OptionArity.Flag),
            new("--probe-dns", OptionArity.Flag),
        ], Positionals: 0),

        new("report",
        [
            new("--from", OptionArity.Value),
            new("--out", OptionArity.Value),
            new("--format", OptionArity.Value),
        ], Positionals: 0),

        // --report is an OptionalValue here as it is on "scan". It was declared Value,
        // faithfully describing a diff that read it with OptionValue: "rempart diff
        // --report --baseline b.json a.json" then wrote the comparison into a folder named
        // "--baseline". DET-ARITE-REPORT, closed — the same spelling now names the same
        // reader on both commands.
        new("diff",
        [
            new("--baseline", OptionArity.Value),
            new("--report", OptionArity.OptionalValue),
        ], Positionals: 2),

        new("index",
        [
            new("--out", OptionArity.Value),
        ], Positionals: 1),

        // --baseline names the same file "diff" reads it from, and is spelled the same way
        // on purpose: one option, one meaning, whichever command is typing it.
        new("baseline",
        [
            new("--baseline", OptionArity.Value),
            new("--force", OptionArity.Flag),
        ], Positionals: 1),

        // Same surface as "index" and for the same reason: both read a folder of reports
        // and write one page out of it. Where they differ is the axis — index aggregates
        // machines, drift aggregates dates.
        new("drift",
        [
            new("--out", OptionArity.Value),
        ], Positionals: 1),

        new("capture",
        [
            new("--out", OptionArity.Value),
            new("--raw", OptionArity.Flag),
            new("--rules", OptionArity.Value),
            new("--store", OptionArity.Value),
            new("--analyze-store", OptionArity.Flag),
        ], Positionals: 0),

        // The identifier is read through Positional, so it is found wherever it sits among
        // the options. It used to be read at index 1, which made
        // "rempart explain --rules <dir> WIN-CRED-001" list the whole catalog instead of
        // explaining the rule — DET-EXPLAIN-POSITIONNEL, closed, and held shut by
        // Only_the_command_word_is_read_at_a_fixed_index.
        new("explain",
        [
            new("--rules", OptionArity.Value),
        ], Positionals: 1),

        new("synthesise",
        [
            new("--from", OptionArity.Value),
            new("--out", OptionArity.Value),
            new("--profile", OptionArity.Value),
            new("--name", OptionArity.Value),
            new("--rules", OptionArity.Value),
            new("--deny", OptionArity.RepeatableValue),
            new("--domain-joined", OptionArity.Flag),
            new("--not-elevated", OptionArity.Flag),
            new("--compromised", OptionArity.Flag),
        ], Positionals: 0),

        new("diagnose-wmi", [], Positionals: 0),

        new("diagnose-tasks", [], Positionals: 0),

        new("diagnose-drivers", [], Positionals: 0),

        new("diagnose-processes", [], Positionals: 0),

        new("diagnose-store",
        [
            new("--raw", OptionArity.Flag),
        ], Positionals: 0),

        new("keygen",
        [
            new("--out", OptionArity.Value),
        ], Positionals: 0),

        new("seal",
        [
            new("--dir", OptionArity.Value),
            new("--out", OptionArity.Value),
            new("--key", OptionArity.Value),
            new("--check", OptionArity.Flag),
        ], Positionals: 0),

        new("fetch-loldrivers",
        [
            new("--out", OptionArity.Value),
        ], Positionals: 0),

        new("fetch-bloatware",
        [
            new("--out", OptionArity.Value),
            new("--judgement", OptionArity.Value),
        ], Positionals: 0),

        new("sign",
        [
            new("--key", OptionArity.Value),
            new("--data", OptionArity.Value),
            new("--out", OptionArity.Value),
            new("--kind", OptionArity.Value),
            new("--published", OptionArity.Value),
        ], Positionals: 0),

        new("update",
        [
            new("--from", OptionArity.Value),
            new("--url", OptionArity.Value),
            new("--rules", OptionArity.Value),
            new("--store", OptionArity.Value),
            new("--apply", OptionArity.Flag),
            new("--yes", OptionArity.Flag),
        ], Positionals: 0),

        new("version", [], Positionals: 0),

        new("help", [], Positionals: 0),
    ];

    /// <summary>
    /// The spellings that ask for the help without naming a command word.
    ///
    /// <para>
    /// A first token wearing a dash is no command word — <see cref="CommandLine.WordAt"/>
    /// answers <c>null</c> — and every one of them used to resolve to the help and exit
    /// <c>0</c>. That took a fact about the parser for a fact about the person typing:
    /// <c>rempart -scan --from t.json</c> is a misspelt command word carrying an option, and
    /// the tool answered it with the usage text and a code of success. Declaring the spellings
    /// that really do ask for the help is what lets every other one be refused as the
    /// complement — the shape the option refusal already has, where what is accepted is
    /// written down and nothing enumerates what is not.
    /// </para>
    ///
    /// <para>
    /// <c>-h</c> is here by decision rather than by accident. It answered <c>0</c> before this
    /// list existed and for the same reason <c>-scan</c> did — nothing read either — but the
    /// two are not the same case, and that is the whole distinction: the help acts on nothing,
    /// so a line that asks for it and gets it is a run that did what it was asked, which is
    /// all the exit code answers for. It is the one single-dash token the tool accepts, and it
    /// is accepted because it is written here, never because of how it is spelt.
    /// </para>
    ///
    /// <para>
    /// Not <see cref="CommandOption"/>s of <c>help</c>, deliberately. An option is something a
    /// command reads with one of the four readers of <see cref="CommandLine"/>, and
    /// <c>CommandSurfaceTests</c> holds the declared options equal to the ones the CLI really
    /// reads — these are read by no command at all. They decide which door a line walks into
    /// before any command runs, which is why they sit beside the command names rather than
    /// under one of them.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> HelpFlags { get; } = ["--help", "-h"];

    /// <summary>The command's surface, or null when nothing goes by that name.</summary>
    public static CommandSpec? Find(string command) =>
        All.FirstOrDefault(c => string.Equals(c.Name, command, StringComparison.Ordinal));

    /// <summary>
    /// The options of a command that swallow the token after them — what
    /// <see cref="CommandLine.Positional"/> needs in order to tell a value from a bare
    /// argument.
    ///
    /// <para>
    /// Flags are the only ones left out. An <see cref="OptionArity.OptionalValue"/> belongs
    /// in the list even though it may appear bare, because <c>Positional</c> already skips
    /// the next token only when it does not start with a dash — the two agree by
    /// construction.
    /// </para>
    ///
    /// <para>
    /// An unknown command yields an empty list rather than throwing: that is what the
    /// caller would have hand-written anyway, and a lookup here must not be the thing that
    /// turns a typo into a crash.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> ValueTaking(string command) =>
        ValueTakingByCommand.TryGetValue(command, out var options) ? options : [];

    private static Dictionary<string, IReadOnlyList<string>> ValueTakingByCommand { get; } =
        All.ToDictionary(
            c => c.Name,
            c => (IReadOnlyList<string>)[.. c.Options
                .Where(o => o.Arity != OptionArity.Flag)
                .Select(o => o.Name)],
            StringComparer.Ordinal);
}
