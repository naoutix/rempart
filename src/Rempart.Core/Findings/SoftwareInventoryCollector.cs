using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Core.Findings;

/// <summary>
/// Inventaire des logiciels installés — un constat par entrée, bénin par défaut, escaladé
/// si le catalogue bloatware (M5b) reconnaît l'entrée.
///
/// <para>
/// L'inventaire seul énumère. Le catalogue vient par-dessus, sans réécrire ce collecteur :
/// il ne peut qu'aggraver un constat, jamais l'inventer. Un logiciel non reconnu reste
/// bénin. Calque de <see cref="LoadedDriversCollector"/> avec la liste de pilotes.
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

            // Le catalogue ne peut qu'aggraver : un logiciel reconnu monte à Notable
            // (indésirable) ou Suspicious (risque de sécurité). Le risque est mappé ici,
            // dans le code — la donnée ne porte pas de gravité en dur.
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
