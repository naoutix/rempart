using Rempart.Cli;
using Rempart.Core.Cli;
using static Rempart.Core.Cli.CommandLine;

// The entry point, and nothing else: the console's encoding, the dispatch, and the one
// place an exception becomes an exit code.
//
// It used to be this plus sixteen commands in the same file, which is what ADR-005 set
// out to undo. What a command does now lives in Commands/, what two commands share in
// CliHost, and what a command accepts in Rempart.Core/Cli/CommandSurface.cs — in Core
// because the Linux job does not compile this project, so a table declared here could
// carry no test that CI runs.

// The Windows console is not UTF-8 by default: without this, accented diagnostics
// come out garbled, and they are exactly what needs to be read first.
Console.OutputEncoding = System.Text.Encoding.UTF8;

try
{
    // No command word at all reads as a request for the help, the same as an unknown one.
    var command = WordAt(args, 0) ?? Usage.Fallback;

    // Ahead of the dispatch, and that order is the correction rather than a detail: behind
    // it, an option nobody declared would be reported after scan had read the machine and
    // written a report — the defect entire, with a sentence added at the end. Held there by
    // CommandSurfaceTests.The_usage_check_runs_before_the_dispatch, since nothing compiles
    // this project on the Linux job.
    if (Usage.Check(command, args) is { } usage)
    {
        Console.Error.WriteLine(usage.Message);
        return (int)usage.Code;
    }

    return CommandTable.Dispatch(command)(args);
}
catch (Exception ex)
{
    // The last resort, and the only one: a command that means to fail says so with a
    // return code. Reaching here means something was not foreseen — and an incomplete
    // snapshot is told apart from the rest, because the caller fixes that by capturing
    // again rather than by filing a bug.
    var failure = ExitCodes.ForException(ex);
    Console.Error.WriteLine(failure.Message);
    return (int)failure.Code;
}
