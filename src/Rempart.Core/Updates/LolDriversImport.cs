using System.Text.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Transforme la liste officielle LOLDrivers en une <see cref="DriverBlocklistFile"/>
/// prête à signer.
///
/// <para>
/// Côté publication, en ligne : l'outil va chercher la donnée, l'éditeur la signe. Ce
/// n'est pas un raccourci sur la confiance — la source amont (loldrivers.io) est un
/// choix de l'éditeur, et c'est <b>sa signature</b>, pas ce téléchargement, que les
/// machines auditées vérifient. Le même principe qu'un mainteneur qui empaquette une
/// source amont puis signe : il choisit ce en quoi il croit, et sa signature engage.
/// </para>
///
/// <para>
/// Lu par <c>JsonDocument</c> plutôt que par des types générés : le schéma de la source
/// est vaste (une trentaine de champs par échantillon) et n'appartient pas à ce projet.
/// On n'y lit que ce dont on a besoin — empreinte, nom, catégorie — et un champ qui
/// changerait ailleurs ne casse rien.
/// </para>
/// </summary>
public static class LolDriversImport
{
    public const string SourceUrl = "https://www.loldrivers.io/api/drivers.json";

    /// <summary>
    /// Aplati les échantillons de chaque pilote en une liste d'empreintes uniques. Un
    /// échantillon sans SHA-256 exploitable est écarté : une entrée qu'on ne peut pas
    /// confronter à un pilote chargé n'a aucune valeur, et l'inventer en aurait une
    /// négative.
    /// </summary>
    public static DriverBlocklistFile Transform(string rawJson, string asOfUtc)
    {
        using var document = JsonDocument.Parse(rawJson);

        var bySha = new Dictionary<string, BlockedDriver>(StringComparer.Ordinal);

        foreach (var entry in document.RootElement.EnumerateArray())
        {
            var category = Text(entry, "Category") ?? "unknown";

            if (!entry.TryGetProperty("KnownVulnerableSamples", out var samples)
                || samples.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var sample in samples.EnumerateArray())
            {
                var sha = Text(sample, "SHA256")?.Trim().ToLowerInvariant();
                if (sha is null || !IsSha256(sha))
                {
                    continue;
                }

                var name = FirstNonEmpty(sample, "Filename", "OriginalFilename", "InternalName",
                    "Product") ?? sha[..12];

                // La première occurrence d'une empreinte est gardée : une même empreinte
                // ne se recatalogue pas.
                bySha.TryAdd(sha, new BlockedDriver(sha, Truncate(name, 120), category));
            }
        }

        var drivers = bySha.Values
            .OrderBy(d => d.Sha256, StringComparer.Ordinal)
            .ToList();

        return new DriverBlocklistFile(asOfUtc, SourceUrl, drivers);
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? FirstNonEmpty(JsonElement element, params string[] properties)
    {
        foreach (var property in properties)
        {
            if (Text(element, property) is { Length: > 0 } value && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];
}
