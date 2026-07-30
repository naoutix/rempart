using Rempart.Core.Findings;

namespace Rempart.Core.Reputation;

/// <summary>The reputation of a hash with a third-party service.</summary>
public sealed record HashReputation(int Malicious, int Total);

/// <summary>
/// What a lookup returned: a reputation when the service knows the hash, and always a
/// readable summary — « 0/72 », « inconnu », « clé refusée ».
///
/// A null <see cref="Reputation"/> does not mean "safe": the file may be unknown to the
/// service, or the lookup may have failed. The summary says which.
/// </summary>
public sealed record ReputationResult(HashReputation? Reputation, string Summary);

/// <summary>
/// Looks up the reputation of a hash. Abstracted so the enrichment can be tested without
/// network access or API key (ADR-001, D5): a fake source returns known verdicts.
/// </summary>
public interface IReputationSource
{
    ReputationResult Lookup(string sha256);
}

/// <summary>
/// Enriches findings with the reputation of their binary — the only enrichment that goes
/// out to the network, and only when the user asks for it (ADR-001, D9).
///
/// <para>
/// Only findings already flagged and carrying a hash are looked up. A benign, signed
/// binary is not: its signature already attests to its origin, and querying hundreds of
/// healthy files would exhaust the API quota without learning anything. This is a
/// complement to the findings, not a second analysis pass.
/// </para>
///
/// <para>
/// This runs on a finished scan, one step before it is serialised, which is what makes
/// <see cref="LookedUp"/> necessary: nothing used to stand between a throwing source and
/// the top of the process but the <c>catch</c> filters of whichever source happened to be
/// plugged in, and those filters named the failures foreseen. The guard sits here rather
/// than only in <see cref="VirusTotalReputation"/>, so the invariant holds for whichever
/// <see cref="IReputationSource"/> is plugged in — a failed lookup is a line in the
/// report, never an audit thrown away for an enrichment the run could do without.
/// </para>
///
/// <para>
/// What it cannot reach is the step before it: <c>ScanCommand</c> builds the source one
/// line above this call, so a source that throws from its constructor still costs the
/// report. <see cref="VirusTotalReputation"/> no longer does — it took the user's key
/// straight into an HTTP header, which validates it — but the guarantee below stops at
/// <see cref="IReputationSource.Lookup"/>.
/// </para>
/// </summary>
public static class FindingEnrichment
{
    public static IReadOnlyList<Finding> WithReputation(
        IReadOnlyList<Finding> findings, IReputationSource source) =>
        [.. findings.Select(finding => Enrich(finding, source))];

    private static Finding Enrich(Finding finding, IReputationSource source)
    {
        if (finding.Severity == FindingSeverity.Benign
            || !finding.Details.TryGetValue("sha256", out var sha256)
            || sha256.Length == 0)
        {
            return finding;
        }

        var result = LookedUp(source, sha256);

        var details = finding.Details.ToDictionary(
            entry => entry.Key, entry => entry.Value, StringComparer.Ordinal);
        details["virustotal"] = result.Summary;

        // A detection confirms a suspicion: the finding is raised to suspicious and this
        // is stated first among the reasons. An unknown hash or a failed lookup lowers
        // nothing — "unknown to VirusTotal" is not "clean".
        if (result.Reputation is { Malicious: > 0 } reputation)
        {
            return finding with
            {
                Severity = FindingSeverity.Suspicious,
                Reasons =
                [
                    $"Signalé malveillant par {reputation.Malicious} moteur(s) sur "
                    + $"{reputation.Total} (VirusTotal).",
                    .. finding.Reasons,
                ],
                Details = details,
            };
        }

        return finding with { Details = details };
    }

    /// <summary>
    /// The lookup, and whatever it throws turned into the reading it should have been.
    /// Untyped on purpose: any list of exception types here would be one more list to keep
    /// right against a third-party service, and the ones that reach a real run are exactly
    /// those a list left out.
    ///
    /// <para>
    /// The wording is its own, never « inconnu de VirusTotal »: a lookup that failed and a
    /// hash the service has never seen are two different facts, and the second is a
    /// verdict. Returning no <see cref="HashReputation"/> is what keeps the finding at the
    /// severity the scan established — a failure teaches nothing, so it lowers and raises
    /// nothing.
    /// </para>
    /// </summary>
    private static ReputationResult LookedUp(IReputationSource source, string sha256)
    {
        try
        {
            return source.Lookup(sha256);
        }
        catch (Exception ex)
        {
            return new(null, $"réputation indisponible : {ex.Message}");
        }
    }
}
