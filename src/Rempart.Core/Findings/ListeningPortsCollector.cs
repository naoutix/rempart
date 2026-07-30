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
        var read = providers.ListeningPorts.Enumerate();
        var findings = new List<Finding>();

        if (read.Status != ReadStatus.Found)
        {
            // An unreadable listening table is not a machine with nothing exposed: no
            // running machine listens on zero ports. Said out loud rather than shown as an
            // empty inventory, which is how it read before DET-PORTS-MUET was closed.
            //
            // Added rather than returned: a partial read keeps the endpoints it did get.
            // Only the total failure leaves this finding on its own, because Ports is then
            // empty and the loop below has nothing to iterate.
            //
            // Unreadable, and this is the one surface where that is not a concession: the
            // listening tables are read from iphlpapi, which asks no privilege to enumerate
            // them, and IListeningPortProvider documents no refusal — its two speaking states
            // are a call that never returned a size and a table that answered with an error,
            // « four tables queried, they fail one at a time ». Replayed, an absent capture
            // lands here too, and no console however elevated re-reads a snapshot. Nothing
            // reaching this branch is a permission, so nothing here may offer one.
            findings.Add(Finding.Unread(
                "listening-port", "ports en écoute", AuditGap.Unreadable, read.Diagnostic,
                "Lecture des points d'écoute sans réponse : un service exposé au réseau "
                + "resterait invisible."));
        }

        // PID → path of the owning binary. Ports only carry a PID; the process table is
        // what links it to a file, hence to a signature.
        // A failed process read is not fatal here: the ports are still worth reporting,
        // they simply lose their owning binary. The processes collector says the read
        // failed, so this one does not repeat it — it degrades and stays quiet.
        var ownerByPid = new Dictionary<int, string>();
        foreach (var process in providers.Processes.Enumerate().Processes)
        {
            ownerByPid[process.Pid] = process.Path;
        }

        var firewall = providers.Firewall.Read();

        if (firewall.Diagnostic is { } failure)
        {
            // Said out loud, exactly as the listening table above is. A failed firewall
            // read removes the cross-check from every port below it, and an audit that
            // quietly loses its reachability question reads like one that asked it and got
            // a reassuring answer.
            //
            // Only a read that *failed* speaks: the diagnostic is left null both for a state
            // that was read and for one nobody looked at, so a capture predating the firewall
            // collection replays as FirewallState.Unread and lands here with nothing.
            // Announcing it on every older capture would be the crying wolf this repository
            // keeps refusing.
            //
            // Refused, because that is what FirewallState says the field means — « why the
            // firewall could not be read, when the read was attempted and refused » — and
            // what the live read builds it from: every surface it adds to the unreadable list
            // it adds on KeyExists or ListValues coming back AccessDenied, the registry's only
            // way of saying no. The rules key that answers with nothing parseable is the one
            // entry that is a failure instead, and it travels in the same sentence with no
            // way to be told apart; see the spillover note on the pull request.
            findings.Add(Finding.Refused("listening-port", "pare-feu", [failure]));
        }

        // The same binary often holds several ports: its signature is judged once.
        var judgements = new Dictionary<string, SignatureJudgement>(StringComparer.OrdinalIgnoreCase);

        // Several processes sometimes bind the same listening endpoint — four Chrome
        // instances hold mDNS on 0.0.0.0:5353. The same protocol/address/port/owner
        // tuple makes a single finding, judged once, carrying the instance count;
        // repeating them would drown the report, as with processes. Two distinct bind
        // addresses remain two findings: the address is what carries the exposure.
        var groups = read.Ports
            .GroupBy(p => (p.Protocol, p.LocalAddress, p.Port,
                Owner: ownerByPid.TryGetValue(p.Pid, out var op) && op.Length > 0
                    ? op : $"pid:{p.Pid}"))
            .OrderBy(g => g.Key.Protocol, StringComparer.Ordinal)
            .ThenBy(g => g.Key.Port)
            .ThenBy(g => g.Key.LocalAddress, StringComparer.Ordinal);

        // Read once, before the loop: the range is a fact about the machine, not about a
        // port, and asking the provider per endpoint would run netsh dozens of times.
        var dynamicRange = providers.DynamicPortRange.Read();

        foreach (var group in groups)
        {
            var finding = Judge(
                group.First(), ownerByPid, group.Count(), firewall, judgements, providers.Signatures);

            findings.Add(MarkIfEphemeral(finding, group.Key.Port, dynamicRange));
        }

        return findings;
    }

    /// <summary>
    /// Flags a benign socket in the dynamic range so <c>rempart diff</c> does not report
    /// it as movement.
    ///
    /// <para>
    /// A browser holds several of these and the operating system renumbers them
    /// constantly: two scans seconds apart differ on nothing else. Left unmarked, every
    /// comparison would open on that churn, and a comparison that always shows movement
    /// stops being read.
    /// </para>
    ///
    /// <para>
    /// <b>Only when benign.</b> A port that was judged notable or suspicious keeps the
    /// ordinary treatment, whatever its number: an unsigned binary reachable from a
    /// public network is news every single time, and the point of this marker is to
    /// silence noise, never a judgement.
    /// </para>
    ///
    /// <para>
    /// <b>The band is read from the machine, and the note says so.</b> It used to be the
    /// constant 49152 asserted about every machine (DET-PLAGE-DYNAMIQUE). That constant is
    /// still the fallback — a range the tool could not read must not stop the marker
    /// working — but the two cases no longer print the same sentence, because « the machine
    /// hands out 49152–65535 » and « nobody could ask, so we assumed it » are the same
    /// numbers and not the same claim.
    /// </para>
    /// </summary>
    private static Finding MarkIfEphemeral(
        Finding finding, int port, DynamicPortRangeRead read)
    {
        var (range, measured) = read.Effective();

        if (finding.Severity != FindingSeverity.Benign || !range.Contains(port))
        {
            return finding;
        }

        return finding with
        {
            Details = new Dictionary<string, string>(finding.Details, StringComparer.Ordinal)
            {
                [FindingDetails.Ephemeral] = measured
                    ? $"Port de la plage dynamique relevée sur la machine ({range.Describe()}) : "
                        + "le système en attribue un autre à chaque ouverture. Son numéro "
                        + "n'identifie rien de stable."
                    : $"Port de la plage dynamique par défaut de Windows ({range.Describe()}), "
                        + "faute d'avoir pu lire celle de la machine : le système en attribue "
                        + "un autre à chaque ouverture. Son numéro n'identifie rien de stable.",
            },
        };
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
        // The detail says the firewall was not consulted, where the other two branches say
        // what it answered. Leaving the key out was honest and unreadable: a port with no
        // « pare-feu » line looks like a port whose line was not worth printing, next to
        // ports that carry one — and the reader has no way to tell « non lu » from an
        // oversight. Absence of a claim has to be a claim.
        details["pare-feu"] = "non lu";

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
