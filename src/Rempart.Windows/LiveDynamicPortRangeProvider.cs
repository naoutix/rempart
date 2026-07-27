using System.Diagnostics;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads the machine's dynamic port range from <c>netsh</c>.
///
/// <para>
/// <b>Why not the registry.</b> The obvious place would be
/// <c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</c>, and it was checked rather
/// than assumed: on this workstation that key carries <c>DataBasePath</c>, <c>Hostname</c>,
/// <c>DhcpNameServer</c> and no port range at all. <c>MaxUserPort</c> is the pre-Vista
/// mechanism, absent by default and superseded when it is present. Reading it would answer
/// « rien » on an ordinary machine, which the caller could not tell from « pas configuré ».
/// </para>
///
/// <para>
/// <b>Why not an API.</b> There is none that is documented. The range lives in the TCP/IP
/// stack and <c>netsh</c> reaches it through NSI, whose entry points are undocumented and
/// unversioned — exactly the kind of dependency a tool that ships one production dependency
/// has no business taking. So: the same decision as the component store, which runs DISM for
/// the same reason, with the same two precautions.
/// </para>
///
/// <para>
/// <b>Absolute path, not the search path.</b> <c>netsh.exe</c> is taken from the system
/// directory. Resolving it through <c>PATH</c> would let a file dropped in the working
/// directory decide what an audit tool runs — on the machines this tool exists to distrust.
/// </para>
///
/// <para>
/// <b>Four tables, one answer.</b> TCP and UDP, IPv4 and IPv6, each configurable
/// independently. Folding them into the single band the judgement uses is
/// <see cref="DynamicPortRangeRead.Combine"/>'s business, in Core, where a test can reach it:
/// what is left here is running the tool and parsing what it printed.
/// </para>
/// </summary>
public sealed class LiveDynamicPortRangeProvider(TimeSpan? timeout = null)
    : IDynamicPortRangeProvider
{
    /// <summary>
    /// The four tables, as argument lists. Kept as data so a test can assert that nothing
    /// here ever becomes a <c>set</c>: the same tool reconfigures the stack, and the
    /// difference between reading a machine and modifying it is one word.
    /// </summary>
    public static readonly IReadOnlyList<string[]> Queries =
    [
        ["int", "ipv4", "show", "dynamicport", "tcp"],
        ["int", "ipv4", "show", "dynamicport", "udp"],
        ["int", "ipv6", "show", "dynamicport", "tcp"],
        ["int", "ipv6", "show", "dynamicport", "udp"],
    ];

    private readonly TimeSpan budget = timeout ?? TimeSpan.FromSeconds(10);

    public DynamicPortRangeRead Read()
    {
        var executable = Path.Combine(Environment.SystemDirectory, "netsh.exe");

        if (!File.Exists(executable))
        {
            return DynamicPortRangeRead.Failed($"netsh introuvable : {executable}");
        }

        // Four readings in, one band out. What to say about them — spanning, disagreement,
        // a table that refused — is a judgement and lives in Core, where the Linux job holds
        // it: this method's job is to run the tool and hand over what it said.
        return DynamicPortRangeRead.Combine(
            [.. Queries.Select(query =>
                ($"{query[1]}/{query[4]}", ReadOne(executable, query)))]);
    }

    private DynamicPortRange? ReadOne(string executable, string[] arguments)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return null;
            }

            // Both streams are drained while the process runs: reading one to the end first
            // deadlocks as soon as the other fills its pipe buffer.
            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit((int)budget.TotalMilliseconds))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Exited between the check and the kill: nothing to stop.
                }

                return null;
            }

            return process.ExitCode == 0
                ? DynamicPortRange.Parse(output.GetAwaiter().GetResult())
                : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            return null;
        }
    }
}
