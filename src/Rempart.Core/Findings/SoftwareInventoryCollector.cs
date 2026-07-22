using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Inventaire des logiciels installés — un constat par entrée, bénin.
///
/// <para>
/// L'inventaire seul ne juge rien : il énumère. Ce qui compte s'y ajoute au croisement avec
/// le catalogue bloatware (M5b), qui escalade les entrées reconnues sans réécrire ce
/// collecteur. On garde ici la distinction provisionné/utilisateur et
/// <c>survives_feature_update</c> : ce sont elles qui, plus tard, distinguent un bloatware
/// qu'on peut retirer d'un bloatware qui revient à chaque mise à jour de fonctionnalité.
/// </para>
/// </summary>
public sealed class SoftwareInventoryCollector : IFindingCollector
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

            findings.Add(new Finding(
                "software", software.Source.ToString(), software.Name,
                FindingSeverity.Benign, [], details));
        }

        return findings;
    }
}
