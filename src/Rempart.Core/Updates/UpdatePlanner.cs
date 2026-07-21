using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>Le sort d'un jeu de données du manifeste, une fois confronté à ce qu'on a reçu.</summary>
public sealed record DatasetPreview(
    string Name,
    string Version,
    bool Verified,
    string? Problem,
    CatalogDiff? Diff);

/// <summary>
/// Ce qu'une mise à jour ferait, sans l'avoir faite.
///
/// D14 l'exige : <c>update</c> télécharge, vérifie, puis montre ce qui change avant
/// d'appliquer. Cet objet est ce « ce qui change » — produit sans rien écrire, pour
/// qu'un refus après lecture ne laisse aucune trace.
/// </summary>
public sealed record UpdatePreview(
    ManifestStatus Status,
    string Explanation,
    string? PublishedAtUtc,
    IReadOnlyList<DatasetPreview> Datasets)
{
    public bool Trusted => Status == ManifestStatus.Trusted;

    /// <summary>
    /// Un manifeste de confiance ne suffit pas : chaque fichier qu'il décrit doit aussi
    /// correspondre à son empreinte. Un seul qui manque à l'appel interdit d'appliquer —
    /// on ne pose pas la moitié d'une mise à jour.
    /// </summary>
    public bool ReadyToApply => Trusted && Datasets.Count > 0 && Datasets.All(d => d.Verified);
}

/// <summary>
/// Prépare une mise à jour : vérifie le manifeste et chaque jeu de données, puis établit
/// le différentiel — sans rien écrire.
///
/// <para>
/// La lecture des octets est injectée plutôt que faite ici : le même code prépare une
/// mise à jour qu'elle vienne d'un fichier local (le cas de la clé USB, D11) ou plus
/// tard du réseau, et se teste sans ni l'un ni l'autre. C'est la règle des providers
/// (ADR-001, D5) appliquée à la mise à jour.
/// </para>
/// </summary>
public static class UpdatePlanner
{
    /// <param name="readDataset">
    /// Résout le nom d'un jeu de données en ses octets, ou <c>null</c> s'il est
    /// introuvable. Un fichier absent est un problème du jeu de données, pas une panne
    /// de la préparation : les autres continuent d'être examinés.
    /// </param>
    public static UpdatePreview Prepare(
        string manifestJson,
        ManifestVerifier verifier,
        Func<string, byte[]?> readDataset,
        IReadOnlyList<Rule> currentRules)
    {
        var verdict = verifier.Verify(manifestJson);

        if (!verdict.IsTrusted || verdict.Payload is null)
        {
            // Manifeste non fiable : on ne regarde même pas les jeux de données. Leur
            // intégrité ne veut rien dire si ce qui les décrit n'est pas authentique.
            return new UpdatePreview(verdict.Status, verdict.Explanation, null, []);
        }

        var datasets = verdict.Payload.Datasets
            .Select(entry => Examine(entry, readDataset, currentRules))
            .ToList();

        return new UpdatePreview(
            ManifestStatus.Trusted,
            verdict.Explanation,
            verdict.Payload.PublishedAtUtc,
            datasets);
    }

    private static DatasetPreview Examine(
        ManifestEntry entry, Func<string, byte[]?> readDataset, IReadOnlyList<Rule> currentRules)
    {
        var bytes = readDataset(entry.Name);

        if (bytes is null)
        {
            return new DatasetPreview(entry.Name, entry.Version, Verified: false,
                "Fichier introuvable à côté du manifeste.", null);
        }

        if (!ManifestVerifier.FileMatches(entry, bytes))
        {
            // Le manifeste est authentique mais le fichier ne correspond pas : reçu
            // corrompu ou substitué. Distinct d'une signature invalide, et à traiter
            // comme tel — ne rien appliquer, mais ne pas crier à la falsification.
            return new DatasetPreview(entry.Name, entry.Version, Verified: false,
                "Empreinte ou taille ne correspond pas au manifeste : fichier corrompu " +
                "ou incomplet.", null);
        }

        try
        {
            var incoming = RuleLoader.Load(
                System.Text.Encoding.UTF8.GetString(bytes), entry.Name);

            return new DatasetPreview(entry.Name, entry.Version, Verified: true, null,
                CatalogDiff.Between(currentRules, incoming));
        }
        catch (RuleFormatException ex)
        {
            // Fichier authentique et intègre, mais que cette version ne sait pas lire.
            // Ce n'est pas une attaque : le dire plutôt que de laisser croire à une
            // corruption.
            return new DatasetPreview(entry.Name, entry.Version, Verified: false,
                $"Jeu de données illisible par cette version : {ex.Message}", null);
        }
    }
}
