using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// What an update would change in the active catalog.
///
/// <para>
/// The baseline is a floor (ADR-002, D12): an update can fix or add a check, never
/// remove an embedded one. A check present in the baseline and absent from the update is
/// therefore not "removed" — it stays, unchanged. That is why this diff has no "removed"
/// category: it would always be empty, and keeping it around would eventually invite
/// filling it, which would break the floor.
/// </para>
/// </summary>
public sealed record CatalogDiff(
    IReadOnlyList<string> Added,
    IReadOnlyList<RuleChange> Modified,
    int Unchanged)
{
    public bool ChangesNothing => Added.Count == 0 && Modified.Count == 0;

    /// <summary>
    /// Compares an incoming catalog to the active one, by identifier.
    ///
    /// "Modified" is judged on the per-rule fingerprint, not on the text: rewording a
    /// justification does not modify a check, changing a threshold does. This is the
    /// same measure as the catalog fingerprint, so a report and a diff never contradict
    /// each other about what "changed".
    /// </summary>
    public static CatalogDiff Between(
        IReadOnlyList<Rule> current, IReadOnlyList<Rule> incoming)
    {
        var byId = current.ToDictionary(
            r => r.Id, RuleCatalog.RuleFingerprint, StringComparer.OrdinalIgnoreCase);

        var added = new List<string>();
        var modified = new List<RuleChange>();
        var unchanged = 0;

        foreach (var rule in incoming)
        {
            var incomingPrint = RuleCatalog.RuleFingerprint(rule);

            if (!byId.TryGetValue(rule.Id, out var currentPrint))
            {
                added.Add(rule.Id);
            }
            else if (!string.Equals(currentPrint, incomingPrint, StringComparison.Ordinal))
            {
                modified.Add(new RuleChange(rule.Id, currentPrint, incomingPrint));
            }
            else
            {
                unchanged++;
            }
        }

        return new CatalogDiff(
            [.. added.OrderBy(id => id, StringComparer.Ordinal)],
            [.. modified.OrderBy(c => c.Id, StringComparer.Ordinal)],
            unchanged);
    }
}

/// <summary>
/// A modified check, with the before and after fingerprints. Showing both makes it
/// possible to tell apart at a glance two updates that touch the same rule.
/// </summary>
public sealed record RuleChange(string Id, string Before, string After);
