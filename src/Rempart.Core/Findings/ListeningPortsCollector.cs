using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Listening ports, judged by their actual exposure surface.
///
/// <para>
/// An open port is not a threat in itself — a machine always holds several. What matters
/// is the crossing of three facts: which address it listens on, which binary holds it,
/// and whether the firewall lets it in. A port that an unsigned binary exposes on
/// <c>0.0.0.0</c> <b>and</b> that the firewall allows on the Public profile is genuinely
/// reachable from an untrusted network; the same port blocked by the firewall is not.
/// Ranking them the same would be the flaw this batch fixes.
/// </para>
///
/// <para>
/// Purely local listening (<c>127.0.0.1</c>, <c>::1</c>) stays benign: it exposes nothing
/// to the network, and the unsigned binary holding it is already reported by the process
/// collector. The signature follows the same ladder (<see cref="SignatureLadder"/>) as
/// processes and drivers.
/// </para>
/// </summary>
public sealed class ListeningPortsCollector : IFindingCollector
{
    public string Name => "listening-ports";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        // PID → path of the owning binary. Ports only carry a PID; the process table is
        // what links it to a file, hence to a signature.
        var ownerByPid = new Dictionary<int, string>();
        foreach (var process in providers.Processes.Enumerate())
        {
            ownerByPid[process.Pid] = process.Path;
        }

        var firewall = providers.Firewall.Read();

        // The same binary often holds several ports: its signature is judged once.
        var judgements = new Dictionary<string, SignatureJudgement>(StringComparer.OrdinalIgnoreCase);

        // Several processes sometimes bind the same listening endpoint — four Chrome
        // instances hold mDNS on 0.0.0.0:5353. The same protocol/address/port/owner
        // tuple makes a single finding, judged once, carrying the instance count;
        // repeating them would drown the report, as with processes. Two distinct bind
        // addresses remain two findings: the address is what carries the exposure.
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

        // Local listening crosses no interface: nothing to expose. The unsigned binary
        // holding it is the process collector's business.
        if (port.IsLoopbackOnly)
        {
            return new Finding("listening-port", Location(port), target,
                FindingSeverity.Benign,
                ["Écoute locale uniquement — hors de portée du réseau."], details);
        }

        // The deciding fact: does the firewall let this port in on the Public profile?
        var reach = firewall.InboundReachability(port.Protocol, port.Port, owner);
        var unsigned = judgement is { Severity: FindingSeverity.Suspicious };

        return reach switch
        {
            // Genuinely reachable from an untrusted network. Unsigned, it is a port
            // opened to the world by a binary whose origin nothing attests; signed, it
            // is an exposed service that still deserves a look.
            FirewallReachability.Reachable => Reachable(port, target, judgement, unsigned, details),

            // Open, but the firewall does not let it in: not exposed as things stand. It is
            // inventoried without escalation, whatever the signature — this batch's promise.
            FirewallReachability.Blocked => Blocked(port, target, details),

            // Firewall not read (capture predates its collection): the cross-check rule
            // steps aside, and we fall back on the signature alone.
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
        // Without firewall state, we do not claim to settle reachability: an exposed
        // unsigned binary stays suspicious on its signature alone, the rest is inventoried.
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
