using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>The outcome for one manifest dataset, after checking it against what was received.</summary>
public sealed record DatasetPreview(
    string Name,
    string Version,
    string Kind,
    bool Verified,
    string? Problem,
    /// <summary>Diff, for a rules dataset.</summary>
    CatalogDiff? Diff = null,
    /// <summary>Entry count, for a driver blocklist.</summary>
    int DriverCount = 0);

/// <summary>
/// What an update would do, without having done it.
///
/// Required by D14: <c>update</c> downloads, verifies, then shows what changes before
/// applying. This object is that "what changes" — produced without writing anything, so
/// that declining after reading it leaves no trace.
/// </summary>
public sealed record UpdatePreview(
    ManifestStatus Status,
    string Explanation,
    string? PublishedAtUtc,
    IReadOnlyList<DatasetPreview> Datasets)
{
    public bool Trusted => Status == ManifestStatus.Trusted;

    /// <summary>
    /// A trusted manifest is not enough: every file it describes must also match its
    /// hash. A single missing or failing one blocks applying — half an update is never
    /// applied.
    /// </summary>
    public bool ReadyToApply => Trusted && Datasets.Count > 0 && Datasets.All(d => d.Verified);
}

/// <summary>
/// Prepares an update: verifies the manifest and every dataset, then computes the diff —
/// without writing anything.
///
/// <para>
/// Reading the bytes is injected rather than done here: the same code prepares an update
/// whether it comes from a local file (the USB stick case, D11) or later from the
/// network, and it can be tested with neither. This is the provider rule (ADR-001, D5)
/// applied to updates.
/// </para>
/// </summary>
public static class UpdatePlanner
{
    /// <param name="readDataset">
    /// Resolves a dataset name to its bytes, or <c>null</c> if it cannot be found. A
    /// missing file is a problem with that dataset, not a failure of the preparation:
    /// the other datasets are still examined.
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
            // Untrusted manifest: the datasets are not examined at all. Their integrity
            // means nothing if what describes them is not authentic.
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
            return Unverified(entry, "Fichier introuvable à côté du manifeste.");
        }

        if (!ManifestVerifier.FileMatches(entry, bytes))
        {
            // The manifest is authentic but the file does not match: what was received
            // is corrupted or substituted. Distinct from an invalid signature, and
            // handled as such — apply nothing, but do not report it as tampering.
            return Unverified(entry,
                "Empreinte ou taille ne correspond pas au manifeste : fichier corrompu " +
                "ou incomplet.");
        }

        var text = System.Text.Encoding.UTF8.GetString(bytes);

        try
        {
            return entry.Kind switch
            {
                DatasetKind.Rules => new DatasetPreview(
                    entry.Name, entry.Version, entry.Kind, Verified: true, null,
                    Diff: CatalogDiff.Between(currentRules, RuleLoader.Load(text, entry.Name))),

                DatasetKind.Drivers => new DatasetPreview(
                    entry.Name, entry.Version, entry.Kind, Verified: true, null,
                    DriverCount: DriverBlocklist.Parse(text).Count),

                // Kind unknown to this version: neither rules nor drivers. The manifest
                // is newer than the binary. Do not guess; refuse — and say so, so the
                // takeaway is "update the binary", not "corrupted".
                _ => Unverified(entry,
                    $"Type de jeu de données inconnu de cette version : « {entry.Kind} ». " +
                    "Installer une version plus récente."),
            };
        }
        catch (Exception ex) when (ex is RuleFormatException or System.Text.Json.JsonException)
        {
            // The file is authentic and intact, but this version cannot parse it. Not
            // an attack: say so rather than let it look like corruption.
            return Unverified(entry, $"Jeu de données illisible par cette version : {ex.Message}");
        }
    }

    private static DatasetPreview Unverified(ManifestEntry entry, string problem) =>
        new(entry.Name, entry.Version, entry.Kind, Verified: false, problem);
}
