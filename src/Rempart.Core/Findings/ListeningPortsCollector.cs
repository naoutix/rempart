using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Ports en écoute, jugés par leur surface d'exposition.
///
/// <para>
/// Un port ouvert n'est pas une menace en soi — une machine en tient toujours plusieurs.
/// Ce qui compte, c'est le couple : sur quelle adresse écoute-t-il, et quel binaire le
/// tient. Un service signé de Windows sur <c>0.0.0.0</c> est la norme ; un binaire non
/// signé sur <c>0.0.0.0</c> est la forme d'une porte dérobée. La même absence de
/// signature qui rend un processus suspect (<see cref="SignatureLadder"/>) le rend ici
/// suspect aussi — mais seulement quand le port est réellement joignable.
/// </para>
///
/// <para>
/// L'écoute purement locale (<c>127.0.0.1</c>, <c>::1</c>) reste bénigne : elle n'expose
/// rien au réseau. Un binaire non signé qui n'écoute que la boucle est déjà relevé par le
/// collecteur de processus ; le redoubler ici brouillerait la seule question qui fait la
/// valeur de ce collecteur — qu'est-ce qui est joignable de l'extérieur ?
/// </para>
/// </summary>
public sealed class ListeningPortsCollector : IFindingCollector
{
    public string Name => "listening-ports";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        // PID → chemin du binaire propriétaire. Les ports ne portent qu'un PID ; c'est la
        // table des processus qui le relie à un fichier, donc à une signature.
        var ownerByPid = new Dictionary<int, string>();
        foreach (var process in providers.Processes.Enumerate())
        {
            ownerByPid[process.Pid] = process.Path;
        }

        // Un même binaire tient souvent plusieurs ports : on juge sa signature une fois.
        var judgements = new Dictionary<string, SignatureJudgement>(StringComparer.OrdinalIgnoreCase);

        var ports = providers.ListeningPorts.Enumerate()
            .OrderBy(p => p.Protocol, StringComparer.Ordinal)
            .ThenBy(p => p.Port)
            .ThenBy(p => p.LocalAddress, StringComparer.Ordinal);

        var findings = new List<Finding>();
        foreach (var port in ports)
        {
            findings.Add(Judge(port, ownerByPid, judgements, providers.Signatures));
        }

        return findings;
    }

    private static Finding Judge(
        ListeningPort port,
        IReadOnlyDictionary<int, string> ownerByPid,
        Dictionary<string, SignatureJudgement> judgements,
        ISignatureProvider signatures)
    {
        ownerByPid.TryGetValue(port.Pid, out var ownerPath);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["protocole"] = port.Protocol,
            ["adresse"] = port.LocalAddress,
            ["port"] = port.Port.ToString(),
            ["pid"] = port.Pid.ToString(),
            ["exposition"] = port.IsLoopbackOnly ? "locale"
                : port.IsAllInterfaces ? "toutes les interfaces"
                : "interface réseau",
        };

        // Propriétaire non résolu — le processus System (PID 4, qui tient le partage de
        // fichiers et NetBIOS), ou un service hors de portée sans élévation. On ne peut
        // pas juger sa signature, et l'absence de preuve n'est pas une preuve : sur un
        // scan non élevé, presque tous les services système sont dans ce cas, et les
        // hisser tous noierait le seul signal qui compte. On les inventorie, gravité
        // bénigne — l'exposition reste dans les détails pour un rejeu élevé ou la règle
        // pare-feu à venir.
        if (string.IsNullOrEmpty(ownerPath))
        {
            return new Finding("listening-port", Location(port), $"PID {port.Pid}",
                FindingSeverity.Benign, [], details);
        }

        if (!judgements.TryGetValue(ownerPath, out var judgement))
        {
            judgement = SignatureLadder.Judge(ownerPath, signatures);
            judgements[ownerPath] = judgement;
        }

        SignatureLadder.Describe(judgement.Signature, details);

        // L'écoute locale ne franchit aucune interface : le binaire non signé qui la tient
        // est l'affaire du collecteur de processus, pas d'une exposition réseau. On énumère
        // le port sans le hisser.
        if (port.IsLoopbackOnly)
        {
            return new Finding("listening-port", Location(port), ownerPath,
                FindingSeverity.Benign,
                ["Écoute locale uniquement — hors de portée du réseau."], details);
        }

        var reach = port.IsAllInterfaces
            ? "toutes les interfaces"
            : $"l'interface {port.LocalAddress}";

        // Exposé : la gravité suit la signature du propriétaire. Signé de Microsoft sur
        // 0.0.0.0, c'est un service système normal ; non signé, c'est un port ouvert sur
        // le réseau par un binaire dont rien n'atteste l'origine.
        if (judgement.Severity == FindingSeverity.Benign)
        {
            return new Finding("listening-port", Location(port), ownerPath,
                FindingSeverity.Benign, [], details);
        }

        return new Finding("listening-port", Location(port), ownerPath,
            judgement.Severity,
            [$"Port exposé sur {reach}, tenu par un binaire non attesté.", .. judgement.Reasons],
            details);
    }

    private static string Location(ListeningPort port) =>
        $"{port.Protocol} {port.LocalAddress}:{port.Port}";
}
