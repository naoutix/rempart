using System.Globalization;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Enumerates running processes via WMI (<c>Win32_Process</c>).
///
/// <para>
/// Same choice as for drivers: WMI provides path, parent, and command line in a single
/// query, without a chain of P/Invoke calls (toolhelp, then opening each process for
/// its path, then the PEB for the command line). The command line of a process owned
/// by another user can stay empty without elevation — that is a permissions gap, not
/// an absence, and the collector does not interpret it any other way.
/// </para>
///
/// <para>
/// Processes without a path — <c>System</c>, <c>Registry</c>, memory compression — are
/// skipped: they are kernel pseudo-processes with no file to assess. Keeping them
/// would only add unverifiable noise.
/// </para>
/// </summary>
public sealed class LiveProcessProvider(IWmiProvider wmi) : IProcessProvider
{
    private const string Namespace = @"root\CIMV2";

    public LiveProcessProvider()
        : this(new Wmi.LiveWmiProvider())
    {
    }

    public IReadOnlyList<RunningProcess> Enumerate()
    {
        var read = wmi.Query(Namespace, "Win32_Process",
            ["ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine"]);

        if (read.Status != ReadStatus.Found)
        {
            return [];
        }

        var processes = new List<RunningProcess>();

        foreach (var instance in read.Instances)
        {
            var path = instance.Find("ExecutablePath");
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            processes.Add(new RunningProcess(
                Number(instance.Find("ProcessId")),
                Number(instance.Find("ParentProcessId")),
                instance.Find("Name") ?? System.IO.Path.GetFileName(path),
                path,
                instance.Find("CommandLine") ?? string.Empty));
        }

        return processes;
    }

    private static int Number(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;
}
