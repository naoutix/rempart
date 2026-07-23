using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// Le catalogue effectivement évalué, une fois le socle embarqué complété d'une mise à
/// jour si elle est présente et de confiance.
/// </summary>
public sealed record CatalogResolution(
    IReadOnlyList<Rule> Rules,
    DriverBlocklist Blocklist,
    BloatwareCatalog Catalog,
    string AsOfUtc,

    /// <summary>
    /// Ce qu'il faut dire du magasin dans le rapport, ou <c>null</c> s'il n'y en a pas.
    /// Une mise à jour appliquée se voit ; une mise à jour refusée aussi — jamais en
    /// silence (ADR-002, D17).
    /// </summary>
    string? UpdateNote);

/// <summary>
/// Le magasin de données mises à jour : ce qu'écrit <c>rempart update --apply</c>, et
/// ce que relit chaque scan.
///
/// <para>
/// Point central de l'ADR-002. Deux invariants le gouvernent. <b>D13</b> : rien n'est
/// chargé sans vérification — le scan re-vérifie signature et empreintes à chaque
/// lecture, il ne fait pas confiance à ce qu'un <c>--apply</c> antérieur a écrit ; un
/// fichier du magasin altéré depuis est donc rejeté, pas chargé. <b>D12</b> : le socle
/// embarqué est un plancher — la mise à jour peut corriger ou ajouter un contrôle,
/// jamais en retirer un.
/// </para>
/// </summary>
public static class UpdateStore
{
    public const string ManifestFileName = "manifest.json";

    /// <summary>
    /// Recopie un manifeste vérifié et ses jeux de données dans le magasin.
    ///
    /// Ne re-vérifie pas : l'appelant vient de le faire (<see cref="UpdatePlanner"/>).
    /// Le scan, lui, re-vérifiera — c'est là qu'est la garantie, pas ici.
    /// </summary>
    public static void Apply(string sourceManifestPath, string storeDirectory, IEnumerable<string> datasetNames)
    {
        Directory.CreateDirectory(storeDirectory);

        var sourceDir = Path.GetDirectoryName(Path.GetFullPath(sourceManifestPath))
            ?? throw new InvalidOperationException("Manifeste sans dossier parent.");

        File.Copy(sourceManifestPath, Path.Combine(storeDirectory, ManifestFileName), overwrite: true);

        foreach (var name in datasetNames)
        {
            File.Copy(
                WithinOrThrow(sourceDir, name),
                WithinOrThrow(storeDirectory, name),
                overwrite: true);
        }
    }

    /// <summary>
    /// Écrit un manifeste vérifié et ses jeux de données depuis des octets — le cas du
    /// téléchargement, où il n'y a pas de dossier source à copier. Les octets sont ceux
    /// que la préparation vient de vérifier, jamais retéléchargés : le scan les
    /// re-vérifiera de toute façon.
    /// </summary>
    public static void Write(
        string storeDirectory, byte[] manifest, IReadOnlyDictionary<string, byte[]> datasets)
    {
        Directory.CreateDirectory(storeDirectory);
        File.WriteAllBytes(Path.Combine(storeDirectory, ManifestFileName), manifest);

        foreach (var (name, bytes) in datasets)
        {
            File.WriteAllBytes(WithinOrThrow(storeDirectory, name), bytes);
        }
    }

    /// <summary>
    /// Résout le catalogue à évaluer : le socle, complété par la mise à jour du magasin
    /// si elle vérifie.
    /// </summary>
    /// <param name="baseRules">
    /// Le socle — règles embarquées, éventuellement additionnées des règles
    /// <c>--rules</c>. La mise à jour se pose par-dessus, sans jamais en retirer.
    /// </param>
    public static CatalogResolution Resolve(
        string storeDirectory, IReadOnlyList<Rule> baseRules, ManifestVerifier verifier)
    {
        var manifestPath = Path.Combine(storeDirectory, ManifestFileName);

        if (!File.Exists(manifestPath))
        {
            // Cas normal hors-ligne : pas de magasin, pas de note. Le binaire seul reste
            // pleinement utilisable (D12).
            return new CatalogResolution(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);
        }

        var verdict = verifier.Verify(File.ReadAllText(manifestPath));

        if (!verdict.IsTrusted || verdict.Payload is null)
        {
            // Une mise à jour refusée ne s'applique pas — et ne se tait pas. Le socle
            // tient, le rapport dit pourquoi la mise à jour n'a pas été retenue.
            return Refused(baseRules,
                $"Mise à jour présente mais refusée ({verdict.Status}) : {verdict.Explanation} " +
                "Socle embarqué conservé.");
        }

        var incoming = new List<Rule>();
        var blocklist = DriverBlocklist.Empty;
        var catalog = BloatwareCatalog.Embedded;

        foreach (var entry in verdict.Payload.Datasets)
        {
            var path = TryWithin(storeDirectory, entry.Name);
            var bytes = path is not null && File.Exists(path) ? File.ReadAllBytes(path) : null;

            if (bytes is null || !ManifestVerifier.FileMatches(entry, bytes))
            {
                // Un seul jeu de données qui manque ou ne correspond plus, et l'on ne
                // pose rien : on n'applique pas la moitié d'une mise à jour. Le fichier
                // a pu être altéré après l'écriture — c'est exactement ce que la
                // re-vérification attrape.
                return Refused(baseRules,
                    $"Mise à jour présente mais un jeu de données ({entry.Name}) ne correspond " +
                    "plus à son empreinte : altéré ou incomplet. Socle embarqué conservé.");
            }

            var text = System.Text.Encoding.UTF8.GetString(bytes);

            try
            {
                switch (entry.Kind)
                {
                    case DatasetKind.Rules:
                        incoming.AddRange(RuleLoader.Load(text, entry.Name));
                        break;

                    case DatasetKind.Drivers:
                        blocklist = DriverBlocklist.Parse(text);
                        break;

                    case DatasetKind.Bloatware:
                        catalog = BloatwareCatalog.Merge(BloatwareCatalog.Embedded, BloatwareCatalog.Parse(text));
                        break;

                    default:
                        // Type qu'une version plus récente comprend, pas celle-ci : refuser
                        // tout, plutôt que d'appliquer ce qu'on sait lire et taire le reste.
                        return Refused(baseRules,
                            $"Mise à jour d'un type inconnu ({entry.Kind}) : installer une " +
                            "version plus récente. Socle embarqué conservé.");
                }
            }
            catch (Exception ex) when (ex is RuleFormatException or System.Text.Json.JsonException)
            {
                return Refused(baseRules,
                    $"Mise à jour présente mais illisible par cette version ({entry.Name}) : " +
                    $"{ex.Message} Socle embarqué conservé.");
            }
        }

        var merged = Merge(baseRules, incoming);
        var driverNote = blocklist.Count > 0 ? $", {blocklist.Count} pilotes surveillés" : "";
        var bloatNote = catalog.Count > BloatwareCatalog.Embedded.Count
            ? $", {catalog.Count} entrées bloatware" : "";

        return new CatalogResolution(merged, blocklist, catalog, verdict.Payload.PublishedAtUtc,
            $"Mise à jour appliquée, publiée le {verdict.Payload.PublishedAtUtc} : " +
            $"{merged.Count} contrôles ({baseRules.Count} au socle){driverNote}{bloatNote}.");
    }

    private static CatalogResolution Refused(IReadOnlyList<Rule> baseRules, string note) =>
        new(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, note);

    /// <summary>
    /// Fusionne la mise à jour dans le socle (D12).
    ///
    /// Une règle entrante de même identifiant remplace celle du socle — une correction ;
    /// une règle entrante inédite s'ajoute. Aucune règle du socle ne disparaît, même si
    /// la mise à jour ne la mentionne pas : le plancher tient. L'ordre du socle est
    /// préservé pour que la liste des échecs d'un rapport reste stable d'une version à
    /// l'autre.
    /// </summary>
    private static IReadOnlyList<Rule> Merge(
        IReadOnlyList<Rule> baseRules, IReadOnlyList<Rule> incoming)
    {
        var overrides = incoming.ToDictionary(r => r.Id, r => r, StringComparer.OrdinalIgnoreCase);
        var result = new List<Rule>(baseRules.Count);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in baseRules)
        {
            if (overrides.TryGetValue(rule.Id, out var replacement))
            {
                result.Add(replacement);
                used.Add(rule.Id);
            }
            else
            {
                result.Add(rule);
            }
        }

        foreach (var rule in incoming)
        {
            if (!used.Contains(rule.Id))
            {
                result.Add(rule);
            }
        }

        return result;
    }

    private static string WithinOrThrow(string directory, string name) =>
        TryWithin(directory, name)
        ?? throw new InvalidOperationException(
            $"Nom de jeu de données hors du dossier : {name}");

    /// <summary>
    /// Résout un nom dans un dossier, ou <c>null</c> s'il s'en échappe. Un nom comme
    /// « ..\\.. » ne doit pas devenir un chemin arbitraire — le séparateur final évite
    /// aussi de confondre le dossier avec un frère au nom voisin.
    /// </summary>
    private static string? TryWithin(string directory, string name)
    {
        var root = Path.GetFullPath(directory)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(root, name));

        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? full : null;
    }
}
