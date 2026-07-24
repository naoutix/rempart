using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

internal sealed class FakeProcessProvider(params RunningProcess[] processes) : IProcessProvider
{
    public IReadOnlyList<RunningProcess> Enumerate() => processes;
}

public class ProcessTests
{
    private static RunningProcess Proc(string path, int pid = 100, int parent = 4, string cmd = "") =>
        new(pid, parent, System.IO.Path.GetFileName(path), path, cmd);

    private static IReadOnlyList<Finding> Collect(
        ISignatureProvider signatures, params RunningProcess[] processes) =>
        new RunningProcessesCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: signatures,
            processes: new FakeProcessProvider(processes)));

    /// <summary>
    /// A validly signed process does not stand out: on a healthy machine, nearly all of
    /// them are, and listing them for review would make the report unreadable.
    /// </summary>
    [Fact]
    public void A_signed_process_is_benign()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\Program Files\App\app.exe", SignatureStatus.Valid),
            Proc(@"C:\Program Files\App\app.exe"));

        Assert.Equal(FindingSeverity.Benign, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// A running unsigned binary is suspicious, on the same footing as an unsigned
    /// startup entry or driver — the scale is shared.
    /// </summary>
    [Fact]
    public void An_unsigned_process_is_suspicious()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\tmp\x.exe", SignatureStatus.Unsigned),
            Proc(@"C:\tmp\x.exe"));

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// The same executable in several instances yields a single finding, judged once,
    /// with the instance count. Twelve <c>svchost.exe</c> are not twelve findings.
    /// </summary>
    [Fact]
    public void Instances_of_the_same_executable_collapse_to_one_finding()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\Windows\System32\svchost.exe", SignatureStatus.Valid),
            Proc(@"C:\Windows\System32\svchost.exe", pid: 10),
            Proc(@"C:\Windows\System32\svchost.exe", pid: 20),
            Proc(@"C:\Windows\System32\svchost.exe", pid: 30));

        var finding = Assert.Single(findings);
        Assert.Equal("3", finding.Details["instances"]);

        // Pid and parent are only given for a single instance: with several, they
        // identify nothing stable.
        Assert.False(finding.Details.ContainsKey("pid"));
    }

    /// <summary>
    /// The command line is kept, taken from the first instance that carries one —
    /// without elevation, another user's may come back empty.
    /// </summary>
    [Fact]
    public void The_command_line_is_kept_from_the_first_instance_that_has_one()
    {
        var findings = Collect(
            new FakeSignatureProvider().With(@"C:\W\p.exe", SignatureStatus.Valid),
            Proc(@"C:\W\p.exe", pid: 1, cmd: ""),
            Proc(@"C:\W\p.exe", pid: 2, cmd: "p.exe --secret"));

        Assert.Equal("p.exe --secret", Assert.Single(findings).Details["commande"]);
    }

    /// <summary>
    /// The executable path is a clean path: the account name is hashed inside it. The
    /// command line, though, is emptied — not scrubbed. It carries the account in forms
    /// a "\Users\x\" replacement cannot see: a URL-encoded path, a secret passed as an
    /// argument, or the very command of the capture session. Claiming to anonymise it
    /// would be false.
    /// </summary>
    [Fact]
    public void Anonymiser_scrubs_the_path_and_empties_the_command_line()
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Processes =
            [
                new RunningProcess(1, 4, "tool.exe", @"C:\Users\leoar\tool.exe",
                    // Account in URL-encoded form: ScrubProfile would not see it.
                    @"tool.exe --path C:%5CUsers%5Cleoar%5Csecret --token abc123"),
            ],
        };

        var process = Anonymiser.Apply(snapshot).Processes![0];

        Assert.DoesNotContain("leoar", process.Path, StringComparison.Ordinal);
        Assert.EndsWith(@"\tool.exe", process.Path, StringComparison.Ordinal);
        Assert.Equal("", process.CommandLine);
    }
}
