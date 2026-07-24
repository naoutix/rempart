using System.Reflection;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Providers;

namespace Rempart.Core.Updates;

/// <summary>Risk carried by a catalog entry — mapped to a severity by the collector.</summary>
public enum BloatwareRisk { Unwanted, SecurityRelevant }

/// <summary>How an entry recognizes an installed piece of software.</summary>
public enum BloatwareMatch { Pfn, Uninstall, Name, Publisher }

/// <summary>
/// A catalog entry: how to recognize a piece of software, and what it costs.
/// <see cref="Impact"/> is mandatory — an entry without an impact note does not get in.
/// </summary>
public sealed record BloatwareEntry(
    string Id,
    BloatwareMatch Match,
    string Value,
    string Category,
    BloatwareRisk Risk,
    string Impact);

/// <summary>The catalog file as it is serialized and signed.</summary>
public sealed record BloatwareCatalogFile(string AsOfUtc, string? Source, List<BloatwareEntry> Entries);

/// <summary>
/// The bloatware catalog, queryable by installed software.
///
/// <para>
/// Transposes the <see cref="DriverBlocklist"/> pattern from file hashes to software
/// identity: software has no stable fingerprint, hence the hybrid matching — an exact
/// identifier (Appx PFN, Uninstall key) when one exists, a curated name/publisher
/// pattern as fallback.
/// </para>
///
/// <para>
/// The catalog does not judge severity: it returns an entry carrying a
/// <see cref="BloatwareRisk"/>, which the collector maps. Invent nothing: an entry
/// without an impact note or identifier throws at load time, as does an unreadable file.
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
    /// The embedded baseline: the bloatware floor shipped in the binary (D12), extended by
    /// a signed catalog when one is present. Loaded once from embedded resources.
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

    /// <summary>Reference date of the embedded baseline — move forward on every revision.</summary>
    public static string EmbeddedAsOfUtc => Embedded.AsOfUtc;

    /// <summary>
    /// Finds the entry that recognizes this software. Several matches are possible
    /// (a name pattern and a publisher pattern): the <b>highest risk</b> wins, with a
    /// stable tie-break on <see cref="BloatwareEntry.Id"/> for deterministic output.
    /// <c>null</c> when nothing matches — the software remains benign.
    /// </summary>
    public BloatwareEntry? Match(InstalledSoftware software) =>
        entries
            .Where(e => Matches(e, software))
            .OrderByDescending(e => e.Risk)
            .ThenBy(e => e.Id, StringComparer.Ordinal)
            .FirstOrDefault();

    private static bool Matches(BloatwareEntry entry, InstalledSoftware sw) => entry.Match switch
    {
        // Exact and bounded to the right source: a PFN only matches an Appx package, an
        // Uninstall key only an uninstall entry — otherwise the same string would stick wrongly.
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
    /// Merges an incoming catalog into a baseline: an entry with the same
    /// <see cref="BloatwareEntry.Id"/> replaces the baseline one, a new entry is added,
    /// and no baseline entry ever disappears (D12). Mirrors the rule merge.
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

        // A missing "entries" key signals a file of another type (e.g. a blocklist signed
        // without --kind): an empty array would be a silent "update applied" over nothing.
        // A key that is present but empty remains a legitimate empty catalog.
        var entries = file.Entries
            ?? throw new JsonException("Catalogue bloatware sans clé « entries » : fichier probablement d'un autre type.");

        // An entry without an id, without a match value/identifier, or without an impact
        // note has no audit value: throw rather than load a truncated catalog (id, value
        // and impact note are all mandatory — an empty Value would make a Name/Publisher
        // pattern match every piece of software).
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
