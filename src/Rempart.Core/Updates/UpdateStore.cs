using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// The catalog actually evaluated, once the embedded baseline has been extended with
/// an update when one is present and trusted.
/// </summary>
public sealed record CatalogResolution(
    IReadOnlyList<Rule> Rules,
    DriverBlocklist Blocklist,
    BloatwareCatalog Catalog,
    string AsOfUtc,

    /// <summary>
    /// What the report must say about the store, or <c>null</c> when there is nothing
    /// to say. An applied update is visible; a refused one too — never in silence
    /// (ADR-002, D17).
    /// </summary>
    string? UpdateNote);

/// <summary>
/// The updated-data store: what <c>rempart update --apply</c> writes, and what every
/// scan reads back.
///
/// <para>
/// Centrepiece of ADR-002. Two invariants govern it. <b>D13</b>: nothing is loaded
/// without verification — the scan re-checks signature and hashes on every read; it
/// does not trust what an earlier <c>--apply</c> wrote, so a store file tampered with
/// since then is rejected, not loaded. <b>D12</b>: the embedded baseline is a floor —
/// an update may fix or add a check, never remove one.
/// </para>
/// </summary>
public static class UpdateStore
{
    public const string ManifestFileName = "manifest.json";

    /// <summary>
    /// Copies a verified manifest and its datasets into the store.
    ///
    /// Does not re-verify: the caller just did (<see cref="UpdatePlanner"/>). The
    /// scan will re-verify — that is where the guarantee lives, not here.
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
    /// Writes a verified manifest and its datasets from bytes — the download case,
    /// where there is no source folder to copy from. The bytes are the ones the
    /// preparation step just verified, never re-downloaded: the scan will re-verify
    /// them anyway.
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
    /// Resolves the catalog to evaluate: the baseline, extended with the store's
    /// update when it verifies.
    /// </summary>
    /// <param name="baseRules">
    /// The baseline — embedded rules, possibly joined by the <c>--rules</c> ones.
    /// The update layers on top, never removing any.
    /// </param>
    public static CatalogResolution Resolve(
        string storeDirectory, IReadOnlyList<Rule> baseRules, ManifestVerifier verifier)
    {
        var manifestPath = Path.Combine(storeDirectory, ManifestFileName);

        if (!File.Exists(manifestPath))
        {
            // The normal offline case: no store, no note. The binary alone stays
            // fully usable (D12).
            return new CatalogResolution(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);
        }

        var verdict = verifier.Verify(File.ReadAllText(manifestPath));

        if (!verdict.IsTrusted || verdict.Payload is null)
        {
            // A refused update is not applied — and is not silent either. The baseline
            // holds, and the report says why the update was not retained.
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
                // One dataset missing or no longer matching, and nothing is installed:
                // half an update is never applied. The file may have been tampered
                // with after being written — exactly what re-verification catches.
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
                        // A kind a newer version understands, not this one: refuse it
                        // all, rather than apply what we can read and silence the rest.
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
        var bloatNote = catalog.Count != BloatwareCatalog.Embedded.Count
            ? $", {catalog.Count} entrées bloatware" : "";

        return new CatalogResolution(merged, blocklist, catalog, verdict.Payload.PublishedAtUtc,
            $"Mise à jour appliquée, publiée le {verdict.Payload.PublishedAtUtc} : " +
            $"{merged.Count} contrôles ({baseRules.Count} au socle){driverNote}{bloatNote}.");
    }

    private static CatalogResolution Refused(IReadOnlyList<Rule> baseRules, string note) =>
        new(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, note);

    /// <summary>
    /// Merges the update into the baseline (D12).
    ///
    /// An incoming rule with a known identifier replaces the baseline one — a fix; a
    /// brand-new incoming rule is appended. No baseline rule ever disappears, even
    /// when the update does not mention it: the floor holds. Baseline order is
    /// preserved so a report's list of failures stays stable from one version to
    /// the next.
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
    /// Resolves a name inside a folder, or <c>null</c> when it escapes it. A name
    /// like « ..\\.. » must not become an arbitrary path — the trailing separator
    /// also avoids mistaking the folder for a sibling with a close name.
    /// </summary>
    private static string? TryWithin(string directory, string name)
    {
        var root = Path.GetFullPath(directory)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(root, name));

        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? full : null;
    }
}
