using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Running processes.
///
/// <para>
/// The question is the same as for the other surfaces: for what executes, what attests
/// to its origin? On a hardened machine, an unsigned process does not belong — it is
/// the first sign of a dropped binary. The judgement is that of
/// <see cref="SignatureLadder"/>, the same scale as autoruns, tasks and drivers: the
/// same missing signature must not be suspicious here and harmless elsewhere.
/// </para>
///
/// <para>
/// The same executable often runs as several instances — a dozen <c>svchost.exe</c>,
/// several <c>chrome.exe</c>. Judging them one by one would repeat the same
/// verification and flood the report with identical findings. Processes are therefore
/// grouped by binary, judged once, with the instance count.
/// </para>
/// </summary>
public sealed class RunningProcessesCollector : IFindingCollector
{
    public string Name => "processes";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        var byExecutable = providers.Processes.Enumerate()
            .GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase);

        foreach (var group in byExecutable)
        {
            var representative = group.First();
            var judgement = SignatureLadder.Judge(group.Key, providers.Signatures);

            var details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["instances"] = group.Count().ToString(),
            };

            if (group.Count() == 1)
            {
                details["pid"] = representative.Pid.ToString();
                details["parent"] = representative.ParentPid.ToString();
            }

            // Command line, taken from the first instance that has one: without
            // elevation, those of other users' processes stay empty, and that is a
            // permissions gap, not an actual absence.
            if (group.Select(p => p.CommandLine).FirstOrDefault(c => c.Length > 0) is { } command)
            {
                details["commande"] = command;
            }

            SignatureLadder.Describe(judgement.Signature, details);

            findings.Add(new Finding(
                "process", representative.Name, group.Key,
                judgement.Severity, judgement.Reasons, details));
        }

        return findings;
    }
}
