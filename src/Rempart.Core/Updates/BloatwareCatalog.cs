using System.Reflection;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Providers;

namespace Rempart.Core.Updates;

/// <summary>Risque porté par une entrée du catalogue — mappé en gravité par le collecteur.</summary>
public enum BloatwareRisk { Unwanted, SecurityRelevant }

/// <summary>Comment une entrée reconnaît un logiciel installé.</summary>
public enum BloatwareMatch { Pfn, Uninstall, Name, Publisher }

/// <summary>
/// Une entrée du catalogue : comment reconnaître un logiciel, et ce qu'il coûte.
/// <see cref="Impact"/> est obligatoire — une entrée sans note d'impact n'entre pas.
/// </summary>
public sealed record BloatwareEntry(
    string Id,
    BloatwareMatch Match,
    string Value,
    string Category,
    BloatwareRisk Risk,
    string Impact);

/// <summary>Le fichier de catalogue tel qu'il est sérialisé et signé.</summary>
public sealed record BloatwareCatalogFile(string AsOfUtc, string? Source, List<BloatwareEntry> Entries);

/// <summary>
/// Le catalogue bloatware, interrogeable par logiciel installé.
///
/// <para>
/// Transposition du patron <see cref="DriverBlocklist"/> du hash de fichier à l'identité
/// logicielle : un logiciel n'a pas d'empreinte stable, d'où l'appariement hybride —
/// identifiant exact (PFN Appx, clé Uninstall) quand il existe, motif de nom/éditeur
/// curaté en repli.
/// </para>
///
/// <para>
/// Le catalogue ne juge pas la gravité : il rend une entrée porteuse d'un
/// <see cref="BloatwareRisk"/>, que le collecteur mappe. Ne rien inventer : une entrée
/// sans impact ou sans identifiant lève au chargement, un fichier illisible aussi.
/// </para>
/// </summary>
public sealed class BloatwareCatalog
{
    private readonly IReadOnlyList<BloatwareEntry> entries;

    public string AsOfUtc { get; }

    public int Count => entries.Count;

    private BloatwareCatalog(string asOfUtc, IReadOnlyList<BloatwareEntry> entries)
    {
        AsOfUtc = asOfUtc;
        this.entries = entries;
    }

    public static readonly BloatwareCatalog Empty = new("", []);

    private static BloatwareCatalog? cachedEmbedded;

    /// <summary>
    /// Le socle embarqué : le plancher bloatware livré dans le binaire (D12), complété par
    /// un catalogue signé quand il est présent. Chargé une fois depuis les ressources.
    /// </summary>
    public static BloatwareCatalog Embedded
    {
        get
        {
            if (cachedEmbedded is not null)
            {
                return cachedEmbedded;
            }

            var assembly = typeof(BloatwareCatalog).Assembly;
            var name = assembly.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("bloatware-baseline.json", StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException(
                    "Socle bloatware embarqué introuvable. Vérifier l'inclusion de data/bloatware-baseline.json en ressource.");

            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            return cachedEmbedded = Parse(reader.ReadToEnd());
        }
    }

    /// <summary>Date de référence du socle embarqué — à avancer à chaque révision.</summary>
    public static string EmbeddedAsOfUtc => Embedded.AsOfUtc;

    /// <summary>
    /// Cherche l'entrée qui reconnaît ce logiciel. Plusieurs correspondances possibles
    /// (un motif nom et un motif éditeur) : le <b>risque le plus élevé</b> gagne,
    /// départage stable par <see cref="BloatwareEntry.Id"/> pour une sortie déterministe.
    /// <c>null</c> si rien ne correspond — le logiciel reste bénin.
    /// </summary>
    public BloatwareEntry? Match(InstalledSoftware software) =>
        entries
            .Where(e => Matches(e, software))
            .OrderByDescending(e => e.Risk)
            .ThenBy(e => e.Id, StringComparer.Ordinal)
            .FirstOrDefault();

    private static bool Matches(BloatwareEntry entry, InstalledSoftware sw) => entry.Match switch
    {
        // Exact et borné à la bonne source : un PFN ne s'apparie qu'à un Appx, une clé
        // Uninstall qu'à une désinstallation — sans quoi une même chaîne collerait à tort.
        BloatwareMatch.Pfn =>
            sw.Source == SoftwareSource.Appx && string.Equals(sw.Identifier, entry.Value, StringComparison.OrdinalIgnoreCase),
        BloatwareMatch.Uninstall =>
            sw.Source == SoftwareSource.Uninstall && string.Equals(sw.Identifier, entry.Value, StringComparison.OrdinalIgnoreCase),
        BloatwareMatch.Name =>
            sw.Name.Contains(entry.Value, StringComparison.OrdinalIgnoreCase),
        BloatwareMatch.Publisher =>
            sw.Publisher is { } p && p.Contains(entry.Value, StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    /// <summary>
    /// Fusionne un catalogue entrant dans un socle : une entrée de même
    /// <see cref="BloatwareEntry.Id"/> remplace celle du socle, une entrée inédite
    /// s'ajoute, aucune entrée du socle ne disparaît (D12). Calque de la fusion des règles.
    /// </summary>
    public static BloatwareCatalog Merge(BloatwareCatalog @base, BloatwareCatalog incoming)
    {
        var overrides = incoming.entries.ToDictionary(e => e.Id, e => e, StringComparer.OrdinalIgnoreCase);
        var result = new List<BloatwareEntry>(@base.entries.Count);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in @base.entries)
        {
            if (overrides.TryGetValue(entry.Id, out var replacement))
            {
                result.Add(replacement);
                used.Add(entry.Id);
            }
            else
            {
                result.Add(entry);
            }
        }

        foreach (var entry in incoming.entries)
        {
            if (!used.Contains(entry.Id))
            {
                result.Add(entry);
            }
        }

        var asOf = string.CompareOrdinal(incoming.AsOfUtc, @base.AsOfUtc) > 0 ? incoming.AsOfUtc : @base.AsOfUtc;
        return new BloatwareCatalog(asOf, result);
    }

    public static BloatwareCatalog Parse(string json)
    {
        var file = JsonSerializer.Deserialize(json, RempartJsonContext.Default.BloatwareCatalogFile)
            ?? throw new JsonException("Catalogue bloatware illisible.");

        // La clé « entries » absente signale un fichier d'un autre type (ex. une liste de
        // blocage sans --kind) : un tableau vide serait un « update applied » silencieux
        // sur rien. Une clé présente mais vide reste un catalogue vide légitime.
        var entries = file.Entries
            ?? throw new JsonException("Catalogue bloatware sans clé « entries » : fichier probablement d'un autre type.");

        // Une entrée sans identifiant, sans valeur/identifiant de correspondance ou sans
        // note d'impact n'a aucune valeur d'audit : lever plutôt que charger un catalogue
        // tronqué (identifiant, valeur et note d'impact sont tous obligatoires — une
        // Value vide ferait matcher un motif Name/Publisher sur tout logiciel).
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Id)
                || string.IsNullOrWhiteSpace(entry.Value)
                || string.IsNullOrWhiteSpace(entry.Impact))
            {
                throw new JsonException(
                    $"Entrée de catalogue invalide ({entry.Id}) : identifiant, valeur et note d'impact obligatoires.");
            }
        }

        return new BloatwareCatalog(file.AsOfUtc ?? "", entries);
    }
}
