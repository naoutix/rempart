using static Rempart.Cli.CliHost;

namespace Rempart.Cli.Commands;

/// <summary>
/// Prints the version, read from the assembly rather than typed here — it had already
/// diverged twice from the batch actually shipped.
/// </summary>
internal static class VersionCommand
{
    /// <summary>Ignores its arguments: the version takes none.</summary>
    public static int Run(string[] args)
    {
        _ = args;
        return Print(ToolVersion());
    }
}
