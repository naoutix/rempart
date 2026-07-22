using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Ports en écoute, jugés par leur surface d'exposition réelle.
///
/// <para>
/// Un port ouvert n'est pas une menace en soi — une machine en tient toujours plusieurs.
/// Ce qui compte, c'est le croisement de trois faits : sur quelle adresse écoute-t-il,
/// quel binaire le tient, et le pare-feu le laisse-t-il entrer. Un port qu'un binaire non
/// signé expose sur <c>0.0.0.0</c> <b>et</b> que le pare-feu autorise en profil Public est
/// réellement joignable depuis un réseau non maîtrisé ; le même port bloqué par le pare-feu
/// ne l'est pas. Les classer pareil serait le défaut que ce lot corrige.
/// </para>
///
/// <para>
/// L'écoute purement locale (<c>127.0.0.1</c>, <c>::1</c>) reste bénigne : elle n'expose
/// rien au réseau, et le binaire non signé qui la tient est déjà relevé par le collecteur
/// de processus. La signature suit la même échelle (<see cref="SignatureLadder"/>) que les
/// processus et les pilotes.
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

        var firewall = providers.Firewall.Read();

        // Un même binaire tient souvent plusieurs ports : on juge sa signature une fois.
        var judgements = new Dictionary<string, SignatureJudgement>(StringComparer.OrdinalIgnoreCase);

        // Plusieurs processus lient parfois le même point d'écoute — quatre instances de
        // Chrome tiennent mDNS sur 0.0.0.0:5353. Le même couple protocole/adresse/port/
        // propriétaire ne fait qu'un constat, jugé une fois, avec le nombre d'instances ;
        // les répéter noierait le rapport, comme pour les processus. Deux adresses de bind
        // distinctes restent deux constats : c'est l'adresse qui porte l'exposition.
        var groups = providers.ListeningPorts.Enumerate()
            .GroupBy(p => (p.Protocol, p.LocalAddress, p.Port,
                Owner: ownerByPid.TryGetValue(p.Pid, out var op) && op.Length > 0
                    ? op : $"pid:{p.Pid}"))
            .OrderBy(g => g.Key.Protocol, StringComparer.Ordinal)
            .ThenBy(g => g.Key.Port)
            .ThenBy(g => g.Key.LocalAddress, StringComparer.Ordinal);

        var findings = new List<Finding>();
        foreach (var group in groups)
        {
            findings.Add(Judge(
                group.First(), ownerByPid, group.Count(), firewall, judgements, providers.Signatures));
        }

        return findings;
    }

    private static Finding Judge(
        ListeningPort port,
        IReadOnlyDictionary<int, string> ownerByPid,
        int instances,
        FirewallState firewall,
        Dictionary<string, SignatureJudgement> judgements,
        ISignatureProvider signatures)
    {
        ownerByPid.TryGetValue(port.Pid, out var ownerPath);
        var owner = string.IsNullOrEmpty(ownerPath) ? null : ownerPath;

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["protocole"] = port.Protocol,
            ["adresse"] = port.LocalAddress,
            ["port"] = port.Port.ToString(),
            ["exposition"] = port.IsLoopbackOnly ? "locale"
                : port.IsAllInterfaces ? "toutes les interfaces"
                : "interface réseau",
        };

        details[instances > 1 ? "instances" : "pid"] =
            instances > 1 ? instances.ToString() : port.Pid.ToString();

        SignatureJudgement? judgement = null;
        if (owner is not null)
        {
            if (!judgements.TryGetValue(owner, out var judged))
            {
                judged = SignatureLadder.Judge(owner, signatures);
                judgements[owner] = judged;
            }

            judgement = judged;
            SignatureLadder.Describe(judgement.Signature, details);
        }

        var target = owner ?? $"PID {port.Pid}";

        // L'écoute locale ne franchit aucune interface : rien à exposer. Le binaire non
        // signé qui la tient est l'affaire du collecteur de processus.
        if (port.IsLoopbackOnly)
        {
            return new Finding("listening-port", Location(port), target,
                FindingSeverity.Benign,
                ["Écoute locale uniquement — hors de portée du réseau."], details);
        }

        // Le fait qui départage : ce port, le pare-feu le laisse-t-il entrer sur Public ?
        var reach = firewall.InboundReachability(port.Protocol, port.Port, owner);
        var unsigned = judgement is { Severity: FindingSeverity.Suspicious };

        return reach switch
        {
            // Réellement joignable depuis un réseau non maîtrisé. Non signé, c'est un port
            // ouvert au monde par un binaire dont rien n'atteste l'origine ; signé, c'est
            // un service exposé qui mérite tout de même un regard.
            FirewallReachability.Reachable => Reachable(port, target, judgement, unsigned, details),

            // Ouvert, mais le pare-feu ne le laisse pas entrer : pas exposé en l'état. On
            // l'inventorie sans le hisser, quelle que soit la signature — la promesse du lot.
            FirewallReachability.Blocked => Blocked(port, target, details),

            // Pare-feu non lu (capture antérieure à sa collecte) : la règle croisée se
            // retire, et l'on retombe sur la signature seule.
            _ => Unknown(port, target, unsigned, judgement, details),
        };
    }

    private static Finding Reachable(
        ListeningPort port, string target, SignatureJudgement? judgement, bool unsigned,
        Dictionary<string, string> details)
    {
        details["pare-feu"] = "autorisé en entrée (Public)";
        var reach = port.IsAllInterfaces ? "toutes les interfaces" : $"l'interface {port.LocalAddress}";

        if (unsigned)
        {
            return new Finding("listening-port", Location(port), target,
                FindingSeverity.Suspicious,
                [$"Joignable depuis un réseau public (écoute sur {reach}, autorisé par le "
                 + "pare-feu) et tenu par un binaire non attesté.", .. judgement!.Reasons],
                details);
        }

        return new Finding("listening-port", Location(port), target,
            FindingSeverity.Notable,
            [$"Service joignable depuis un réseau public : écoute sur {reach} et autorisé "
             + "en entrée par le pare-feu sur le profil Public."],
            details);
    }

    private static Finding Blocked(
        ListeningPort port, string target, Dictionary<string, string> details)
    {
        details["pare-feu"] = "bloqué en entrée (Public)";
        return new Finding("listening-port", Location(port), target,
            FindingSeverity.Benign, [], details);
    }

    private static Finding Unknown(
        ListeningPort port, string target, bool unsigned, SignatureJudgement? judgement,
        Dictionary<string, string> details)
    {
        // Sans état de pare-feu, on ne prétend pas trancher l'atteignabilité : un binaire
        // non signé exposé reste suspect sur sa seule signature, le reste est inventorié.
        if (unsigned)
        {
            var reach = port.IsAllInterfaces ? "toutes les interfaces" : $"l'interface {port.LocalAddress}";
            return new Finding("listening-port", Location(port), target,
                FindingSeverity.Suspicious,
                [$"Port exposé sur {reach}, tenu par un binaire non attesté.", .. judgement!.Reasons],
                details);
        }

        return new Finding("listening-port", Location(port), target,
            FindingSeverity.Benign, [], details);
    }

    private static string Location(ListeningPort port) =>
        $"{port.Protocol} {port.LocalAddress}:{port.Port}";
}
