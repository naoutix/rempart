using System.Xml.Linq;
using Rempart.Core.Cli;

namespace Rempart.Tests.Unit;

/// <summary>
/// The scheduled task this repository ships, checked against the binary it drives.
///
/// <para>
/// It is a file a user imports and then forgets. A line that stops being accepted — an
/// option renamed, a command word dropped — would fail weeks later on someone else's
/// machine, at an hour nobody watches, with nothing connecting the failure to the commit
/// that caused it. So the line is read off the file and put through the same door a typed
/// line goes through, which is the technique <c>BuildChainParityTests</c> uses on the
/// workflows and for the same reason.
/// </para>
/// </summary>
public sealed class ScheduledTaskDefinitionTests
{
    private const string Definition = "tools/scheduled-task/rempart-derive.xml";

    private static XDocument Task() => XDocument.Parse(RepositoryFiles.Read(Definition));

    private static string Element(string name) =>
        Task().Descendants().Single(e => e.Name.LocalName == name).Value;

    [Fact]
    public void The_shipped_task_runs_a_line_the_binary_accepts()
    {
        var typed = Element("Arguments")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Usage.Check answers null when the line is one the binary honours, and a
        // FailureExit carrying code 6 otherwise — the door a mistyped word goes through.
        Assert.Null(Usage.Check(typed[0], typed));
    }

    /// <summary>
    /// And the command word is one that exists, which the check above cannot be relied on to
    /// prove on its own: it answers about a line, so a line the surface never declared would
    /// have to be spelled wrong in exactly the right way to be caught twice.
    /// </summary>
    [Fact]
    public void The_shipped_task_names_a_command_the_surface_declares()
    {
        var word = Element("Arguments").Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];

        Assert.NotNull(CommandSurface.Find(word));
    }

    /// <summary>
    /// The decision #101 turns on, pinned so it cannot be relaxed by accident: this
    /// repository does not ship a file that runs a binary as administrator on a schedule.
    /// A non-elevated run exits 5 with some controls unverifiable, and the drift page says
    /// so — whoever wants more raises this themselves, knowing what they grant.
    /// </summary>
    [Fact]
    public void The_shipped_task_does_not_ask_for_elevation()
    {
        Assert.Equal("LeastPrivilege", Element("RunLevel"));
    }

    /// <summary>
    /// The two paths a reader has to edit name the same folder. Left disagreeing, the task
    /// registers and then runs the binary with a working directory somewhere else, which is
    /// where <c>--report</c> would land its reports — a series quietly written where nobody
    /// looks for it.
    /// </summary>
    [Fact]
    public void The_two_paths_to_edit_name_one_folder()
    {
        var command = Element("Command");
        var workingDirectory = Element("WorkingDirectory");

        Assert.EndsWith(@"\rempart.exe", command, StringComparison.Ordinal);
        Assert.Equal(
            command[..command.LastIndexOf('\\')],
            workingDirectory,
            StringComparer.Ordinal);
    }

    /// <summary>
    /// The definition stays ASCII. A Task Scheduler XML is read by <c>schtasks</c> before
    /// anything in this repository sees it, and encoding is where that import fails first;
    /// no accented word in a comment is worth that failure on someone else's machine.
    /// </summary>
    [Fact]
    public void The_definition_carries_nothing_but_ascii()
    {
        var offending = RepositoryFiles.Read(Definition)
            .Where(character => character > 127)
            .Distinct()
            .ToList();

        Assert.True(offending.Count == 0,
            $"caractères non ASCII dans {Definition} : {string.Join(", ", offending)}");
    }
}
