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

        var result = source.Lookup(sha256);

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
}
