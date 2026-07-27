namespace Rempart.Core.Cli;

/// <summary>
/// The hand-written argument parser — sixty lines that decide which file gets read and
/// which folder gets written to.
///
/// <para>
/// ADR-001 plans for a library once the number of commands justifies one; until then this
/// is what stands between a command line and the filesystem, and it lived in
/// <c>Program.cs</c> where no test could reach it. It sits in Core for the same reason the
/// console renderer does: <c>Rempart.Cli</c> targets <c>net10.0-windows</c>, so a test
/// written beside it would never run on the Linux job.
/// </para>
///
/// <para>
/// The four readers disagree with one another on purpose, and the disagreements are the
/// behaviour, not accidents to tidy up: <see cref="OptionValue"/> takes the next token
/// whatever it looks like, <see cref="OptionalValue"/> refuses one that starts with a
/// dash, <see cref="OptionValues"/> stops one short of the end, and
/// <see cref="Positional"/> starts past the command word. Each is relied on somewhere.
/// Values are opaque strings — nothing here splits, combines or normalises a path, which
/// is what lets a Windows command line be parsed identically on the Linux job.
/// </para>
/// </summary>
public static class CommandLine
{
    /// <summary>
    /// Value of an option that must have one. Takes the next token even when it is itself
    /// an option: <c>--from --json</c> yields <c>"--json"</c>. Callers that cannot live
    /// with that use <see cref="OptionalValue"/>.
    /// </summary>
    public static string? OptionValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    public static bool HasFlag(string[] args, string name) => Array.IndexOf(args, name) >= 0;

    /// <summary>
    /// Value of an option that may be given without one — <c>--report</c> alone, or
    /// <c>--report D:\audits</c>.
    ///
    /// <see cref="OptionValue"/> would swallow the next option as a value and quietly
    /// write the reports into a folder named <c>--json</c>.
    /// </summary>
    public static string? OptionalValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length && !args[index + 1].StartsWith('-')
            ? args[index + 1]
            : null;
    }

    /// <summary>All occurrences of a repeatable option.</summary>
    public static IReadOnlyList<string> OptionValues(string[] args, string name)
    {
        var values = new List<string>();
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == name)
            {
                values.Add(args[i + 1]);
            }
        }

        return values;
    }

    /// <summary>
    /// Arguments that are not options, and not the value of one.
    ///
    /// The hand-written parser has no notion of arity, so a bare scan of non-dash tokens
    /// would take the folder in <c>--report ./out</c> for a file to compare.
    /// </summary>
    public static IReadOnlyList<string> Positional(string[] args, IReadOnlyList<string> valueTaking)
    {
        var positional = new List<string>();

        for (var i = 1; i < args.Length; i++)
        {
            if (args[i].StartsWith('-'))
            {
                if (valueTaking.Contains(args[i]) && i + 1 < args.Length
                    && !args[i + 1].StartsWith('-'))
                {
                    i++;
                }

                continue;
            }

            positional.Add(args[i]);
        }

        return positional;
    }

    /// <summary>
    /// The word at a fixed slot, when it is a word and not an option — the command name at
    /// index 0, and nothing else.
    ///
    /// <para>
    /// Index 0 is the one slot where a fixed index is the right tool: no option can precede
    /// the command word, so the position is a fact rather than an assumption.
    /// <c>explain</c> used to read its identifier at index 1 the same way, and that was the
    /// assumption — <c>rempart explain --rules d W-001</c> found <c>--rules</c> there, so it
    /// listed the whole catalog instead of explaining the rule (DET-EXPLAIN-POSITIONNEL).
    /// It goes through <see cref="Positional"/> now, which is what knows that an option
    /// swallows the token behind it. Anything after the command word belongs to
    /// <c>Positional</c>; a second <c>WordAt</c> call at a non-zero index would be that
    /// defect coming back, and <c>CommandSurfaceTests</c> refuses one.
    /// </para>
    /// </summary>
    public static string? WordAt(string[] args, int index) =>
        args.Length > index && !args[index].StartsWith('-') ? args[index] : null;
}
