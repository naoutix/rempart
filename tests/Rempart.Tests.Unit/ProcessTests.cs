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
    /// Un processus validement signé ne ressort pas : sur une machine saine, la quasi-
    /// totalité l'est, et les lister à examiner rendrait le rapport illisible.
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
    /// Un binaire non signé qui tourne est suspect, au même titre qu'un démarrage ou un
    /// pilote non signé — l'échelle est commune.
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
    /// Un même exécutable en plusieurs instances donne un seul constat, jugé une fois,
    /// avec le nombre d'instances. Douze <c>svchost.exe</c> ne sont pas douze constats.
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

        // Pid et parent ne sont donnés que pour une instance unique : à plusieurs, ils
        // n'identifient rien de stable.
        Assert.False(finding.Details.ContainsKey("pid"));
    }

    /// <summary>
    /// La ligne de commande est retenue, prise sur la première instance qui en porte une —
    /// hors élévation, celle d'un autre utilisateur peut rester vide.
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
    /// Le chemin de l'exécutable est un chemin propre : on y hache le compte. La ligne de
    /// commande, elle, est vidée — pas nettoyée. Elle porte le compte sous des formes
    /// qu'un remplacement de « \Users\x\ » ne voit pas : un chemin URL-encodé, un secret
    /// en argument, ou la commande même de la session de capture. Prétendre l'anonymiser
    /// serait faux.
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
                    // Compte sous forme URL-encodée : ScrubProfile ne le verrait pas.
                    @"tool.exe --path C:%5CUsers%5Cleoar%5Csecret --token abc123"),
            ],
        };

        var process = Anonymiser.Apply(snapshot).Processes![0];

        Assert.DoesNotContain("leoar", process.Path, StringComparison.Ordinal);
        Assert.EndsWith(@"\tool.exe", process.Path, StringComparison.Ordinal);
        Assert.Equal("", process.CommandLine);
    }
}
