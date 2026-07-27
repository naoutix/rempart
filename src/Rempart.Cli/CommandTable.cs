using Rempart.Cli.Commands;

namespace Rempart.Cli;

/// <summary>
/// The dispatch table: a command word, and the class that runs it.
///
/// <para>
/// Written out by hand, and that is the decision, not an omission. ADR-001 rules out
/// reflection — a registry built from <c>Assembly.GetTypes</c> or from an attribute would
/// not survive Native AOT — and ADR-005 rules out a source generator, which would add a
/// second build-time dependency to a tool whose supply chain is one of its arguments.
/// </para>
///
/// <para>
/// What that costs is a table that can drift: a command class added without its line here
/// is simply unreachable, and nothing complains. <c>CommandSurfaceTests</c> reads this
/// file and compares it to <c>CommandSurface</c>, which is the same technique the replay
/// wiring guard uses, and for the same reason — this repository has already shipped the
/// silent-omission failure three times (D2, D2b, the component store).
/// </para>
/// </summary>
internal static class CommandTable
{
    /// <summary>
    /// The command that word names. Every arm is a method group, so the table stays a
    /// table: no argument is read here, and a command cannot quietly change what the
    /// dispatch does before reaching it.
    /// </summary>
    public static Func<string[], int> Dispatch(string command) => command switch
    {
        "scan" => ScanCommand.Run,
        "report" => ReportCommand.Run,
        "diff" => DiffCommand.Run,
        "index" => IndexCommand.Run,
        "capture" => CaptureCommand.Run,
        "explain" => ExplainCommand.Run,
        "synthesise" => SynthesiseCommand.Run,
        "diagnose-wmi" => DiagnoseWmiCommand.Run,
        "diagnose-tasks" => DiagnoseTasksCommand.Run,
        "diagnose-drivers" => DiagnoseDriversCommand.Run,
        "diagnose-processes" => DiagnoseProcessesCommand.Run,
        "diagnose-store" => DiagnoseStoreCommand.Run,
        "keygen" => KeygenCommand.Run,
        "seal" => SealCommand.Run,
        "fetch-loldrivers" => FetchLoldriversCommand.Run,
        "sign" => SignCommand.Run,
        "update" => UpdateCommand.Run,
        "version" => VersionCommand.Run,
        "help" => HelpCommand.Run,

        // Anything else, typo included: the usage text rather than an error. Named above
        // as well, so that "help" is a row of the table like the rest — a command
        // reachable only through this arm would be one the guard could not see.
        _ => HelpCommand.Run,
    };
}
