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
///
/// <para>
/// The catalog is demanded, as the blocklist is next door. It used to default to
/// <see cref="BloatwareCatalog.Empty"/>, and an empty catalog recognises nothing: every
/// entry stays benign, so a collector built without it answers exactly like one facing a
/// clean machine. Dropping the argument from the registration in <c>ScanEngine</c> left the
/// whole suite green. Saying « rien à confronter » now costs a written
/// <see cref="BloatwareCatalog.Empty"/>, which is a sentence a reader can disagree with.
/// </para>
/// </summary>
public sealed class SoftwareInventoryCollector(BloatwareCatalog catalog) : IFindingCollector
{
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
            if (catalog.Match(software) is { } hit)
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
