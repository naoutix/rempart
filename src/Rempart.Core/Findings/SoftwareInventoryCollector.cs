using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Core.Findings;

/// <summary>
/// Inventory of installed software — one finding per entry, benign by default, escalated
/// when the bloatware catalog (M5b) recognises the entry.
///
/// <para>
/// The inventory alone enumerates. The catalog sits on top without rewriting this
/// collector: it can only aggravate a finding, never invent one. Unrecognised software
/// stays benign. Mirrors <see cref="LoadedDriversCollector"/> with the driver list.
/// </para>
/// </summary>
public sealed class SoftwareInventoryCollector(BloatwareCatalog? catalog = null) : IFindingCollector
{
    private readonly BloatwareCatalog catalog = catalog ?? BloatwareCatalog.Empty;

    public string Name => "software";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var software in providers.SoftwareInventory.Read())
        {
            var details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["source"] = software.Source.ToString(),
                ["provisionné"] = software.Provisioned ? "oui" : "non",
                ["survives_feature_update"] = software.SurvivesFeatureUpdate ? "oui" : "non",
            };

            if (!string.IsNullOrEmpty(software.Version))
            {
                details["version"] = software.Version;
            }

            if (!string.IsNullOrEmpty(software.Publisher))
            {
                details["éditeur"] = software.Publisher;
            }

            var severity = FindingSeverity.Benign;
            var reasons = new List<string>();

            // The catalog can only aggravate: recognised software rises to Notable
            // (unwanted) or Suspicious (security risk). The risk is mapped here, in
            // code — the data carries no hardcoded severity.
            if (this.catalog.Match(software) is { } hit)
            {
                severity = hit.Risk == BloatwareRisk.SecurityRelevant
                    ? FindingSeverity.Suspicious
                    : FindingSeverity.Notable;
                reasons.Add(hit.Impact);
                details["bloatware"] = hit.Category;
                details["catalogue"] = hit.Id;
            }

            findings.Add(new Finding(
                "software", software.Source.ToString(), software.Name, severity, reasons, details));
        }

        return findings;
    }
}
