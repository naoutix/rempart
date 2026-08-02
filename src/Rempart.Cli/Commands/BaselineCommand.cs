using Rempart.Core.Diff;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Promotes a report to the reference every later comparison is held to.
///
/// <para>
/// Until now the baseline was put in place by a copy, and a copy cannot refuse. This
/// command can: what it exists for is the four ways a promotion goes wrong silently — a
/// truncated file, a report that is not one, a report of another machine, a report produced
/// by another catalog. <see cref="BaselinePromotion"/> decides all four; this reads and
/// writes files and nothing else.
/// </para>
/// </summary>
internal static class BaselineCommand
{
    public static int Run(string[] args)
    {
        var positional = Positional(args, Rempart.Core.Cli.CommandSurface.ValueTaking("baseline"));

        if (positional.Count == 0)
        {
            Console.Error.WriteLine(
                "Indiquer le rapport à promouvoir : rempart baseline <rapport.json>. "
                + $"Il devient la référence de « rempart diff » ({BaselinePath()}).");
            return 1;
        }

        var target = OptionValue(args, "--baseline") ?? BaselinePath();
        string candidate;

        try
        {
            candidate = File.ReadAllText(positional[0]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Rapport illisible : {positional[0]} ({ex.Message})");
            return 1;
        }

        var decision = BaselinePromotion.Judge(candidate, ReadCurrent(target), HasFlag(args, "--force"));

        if (!decision.Writes)
        {
            Console.Error.WriteLine(decision.Sentence);
            return 1;
        }

        try
        {
            Install(candidate, target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Référence non installée dans {target} : {ex.Message}");
            return 1;
        }

        Console.WriteLine(decision.Sentence);
        return 0;
    }

    /// <summary>
    /// The reference in place, or null when there is none. An unreadable one is handed over
    /// as it is rather than swallowed: deciding what an unreadable reference means belongs
    /// to <see cref="BaselinePromotion"/>, which says so out loud instead of overwriting it
    /// in silence.
    /// </summary>
    private static string? ReadCurrent(string target)
    {
        if (!File.Exists(target))
        {
            return null;
        }

        try
        {
            return File.ReadAllText(target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Written beside the target and moved onto it, never written through it.
    ///
    /// <para>
    /// This is the defect the issue describes, in the one place it could still happen after
    /// every check has passed: a write interrupted halfway leaves a truncated
    /// <c>baseline.json</c>, which is exactly the silent poison the refusals above exist to
    /// prevent. A move within one directory is atomic, so an interruption leaves the old
    /// reference whole rather than half of the new one.
    /// </para>
    ///
    /// <para>
    /// The promoted text is written as it was read, not re-serialised: the reference must be
    /// the report, byte for byte, or two runs of this command on one file could install two
    /// different baselines.
    /// </para>
    /// </summary>
    private static void Install(string candidate, string target)
    {
        var directory = Path.GetDirectoryName(target);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var staged = target + ".tmp";
        File.WriteAllText(staged, candidate);
        File.Move(staged, target, overwrite: true);
    }
}
