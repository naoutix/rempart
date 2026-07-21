using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Processus en cours d'exécution.
///
/// <para>
/// La question est la même que pour les autres surfaces : ce qui s'exécute, qu'est-ce
/// qui atteste de son origine ? Sur une machine durcie, un processus non signé n'a rien
/// à y faire — c'est le premier signe d'un binaire déposé. Le jugement est celui de
/// <see cref="SignatureLadder"/>, la même échelle que les démarrages, les tâches et les
/// pilotes : une même absence de signature ne doit pas être suspecte ici et anodine
/// ailleurs.
/// </para>
///
/// <para>
/// Un même exécutable tourne souvent en plusieurs instances — une douzaine de
/// <c>svchost.exe</c>, plusieurs <c>chrome.exe</c>. Les juger un par un répéterait la
/// même vérification et noierait le rapport sous des constats identiques. On regroupe
/// donc par binaire, jugé une fois, avec le nombre d'instances.
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

            // Une ligne de commande, prise sur la première instance qui en a une : hors
            // élévation, celles des autres utilisateurs restent vides, et c'est une
            // lacune de droits, pas une absence.
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
