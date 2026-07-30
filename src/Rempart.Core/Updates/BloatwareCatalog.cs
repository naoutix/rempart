using System.Reflection;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Providers;

namespace Rempart.Core.Updates;

/// <summary>Risk carried by a catalog entry — mapped to a severity by the collector.</summary>
public enum BloatwareRisk { Unwanted, SecurityRelevant }

/// <summary>How an entry recognizes an installed piece of software.</summary>
public enum BloatwareMatch { Pfn, Uninstall, Name, Publisher, PackageName }

/// <summary>
/// Where an impact note comes from.
///
/// <para>
/// The default is deliberate and conservative: a note nobody has checked against a running
/// machine says so, rather than borrowing the authority of one that has. Most of the
/// catalogue is imported, and describing what removing a piece of software breaks is exactly
/// the kind of claim this project has three times been wrong about by deducing it instead of
/// observing it (ADR-006, D20).
/// </para>
/// </summary>
public enum ImpactProvenance
{
    /// <summary>Derived from the third-party list the entry was imported from.</summary>
    Upstream,

    /// <summary>Confronted with the software actually installed on a machine.</summary>
    Verified,
}

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
    string Impact,
    /// <summary>
    /// Optional with a default, so a catalogue signed before this field existed reads back
    /// as the unverified thing it was rather than failing to load.
    /// </summary>
    ImpactProvenance ImpactSource = ImpactProvenance.Upstream);

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
///
/// <para>
/// "Throws at load time" means <see cref="JsonException"/>, and that is the whole point.
/// A <c>record</c> imposes nothing on deserialisation, so <c>"entries":[null]</c> used to
/// reach <c>entry.Id</c> and raise a <see cref="NullReferenceException"/> that neither
/// <see cref="UpdateStore"/> nor <see cref="UpdatePlanner"/> catches — a refusal that
/// escapes its callers' filters is not a refusal, it is the end of the scan. Same reading
/// as <see cref="DriverBlocklist"/>, one file over.
/// </para>
///
/// <para>
/// The rule binds every refusal this file makes, not just the hole. Two entries sharing an
/// <see cref="BloatwareEntry.Id"/> passed the reader intact and blew up one line later in
/// <see cref="Merge"/>, on the <c>ToDictionary</c> that indexes the incoming catalogue —
/// an <see cref="ArgumentException"/>, through the same unfiltered gap. It is refused here
/// instead, where the refusal is a <see cref="JsonException"/> and where
/// <see cref="UpdatePlanner"/> also sees it, so the file is turned away before
/// <c>update --apply</c> writes it rather than at every scan that follows.
/// </para>
/// </summary>
public sealed class BloatwareCatalog
{
    private readonly IReadOnlyList<BloatwareEntry> entries;

    public string AsOfUtc { get; }

    public int Count => entries.Count;

    /// <summary>
    /// The entries, for guards that check their <em>shape</em> rather than their effect —
    /// nothing else relates a match mode to the form its value must take, and getting that
    /// pairing wrong recognizes nothing without failing.
    /// </summary>
    public IReadOnlyList<BloatwareEntry> Entries => entries;

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

        // The name part of a Package Family Name, which is "<Name>_<PublisherId>". Third-party
        // lists catalogue the name alone, because that is what identifies an application; the
        // publisher hash is derived from an identity they do not carry. Equality on the
        // segment, never a prefix test -- "Microsoft.Xbox" must not claim
        // "Microsoft.XboxGamingOverlay".
        BloatwareMatch.PackageName =>
            sw.Source == SoftwareSource.Appx
            && sw.Identifier is { } pfn
            && string.Equals(NameSegmentOf(pfn), entry.Value, StringComparison.OrdinalIgnoreCase),

        _ => false,
    };

    /// <summary>
    /// The name part of a Package Family Name. Split on the <b>last</b> underscore: a package
    /// name cannot contain one today, so first and last agree, and the last one stays right if
    /// that ever stops being true. A value carrying no hash is returned whole, so a capture
    /// that recorded a bare name still compares instead of quietly matching nothing.
    /// </summary>
    private static string NameSegmentOf(string packageFamilyName)
    {
        var separator = packageFamilyName.LastIndexOf('_');
        return separator < 0 ? packageFamilyName : packageFamilyName[..separator];
    }

    /// <summary>
    /// Merges an incoming catalog into a baseline: an entry with the same
    /// <see cref="BloatwareEntry.Id"/> replaces the baseline one, a new entry is added,
    /// and no baseline entry ever disappears (D12). Mirrors the rule merge.
    /// </summary>
    public static BloatwareCatalog Merge(BloatwareCatalog @base, BloatwareCatalog incoming)
    {
        // Indexing by id cannot throw here: the constructor is private, so every catalogue
        // comes from Parse, Empty or the embedded baseline (itself parsed), and Parse
        // refuses a duplicate id under this very comparer. It did not always, and this line
        // is where a signed catalogue carrying "B1" twice used to raise an
        // ArgumentException — past the reader that had just accepted it, and past both
        // callers' catch filters.
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

        // The identifiers already seen, compared the way Merge indexes them.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            // A hole, in either of the two shapes it comes in: the element itself written
            // null, or a field the record declares and the JSON never supplied. Checked
            // before anything reads the entry, because reading it was the bug — and
            // Category is in the list although the test below does not ask it to be
            // non-empty: it is copied into a finding's details as a value, where a null
            // becomes a null in the report.
            if (entry is null || entry.Id is null || entry.Value is null
                || entry.Category is null || entry.Impact is null)
            {
                throw new JsonException(
                    "Entrée de catalogue trouée : identifiant, valeur, catégorie et note "
                    + "d'impact sont obligatoires, et l'entrée elle-même ne peut être nulle. "
                    + "Rien n'est chargé.");
            }

            // An entry without an id, without a match value/identifier, or without an impact
            // note has no audit value: throw rather than load a truncated catalog (id, value
            // and impact note are all mandatory — an empty Value would make a Name/Publisher
            // pattern match every piece of software).
            if (string.IsNullOrWhiteSpace(entry.Id)
                || string.IsNullOrWhiteSpace(entry.Value)
                || string.IsNullOrWhiteSpace(entry.Impact))
            {
                throw new JsonException(
                    $"Entrée de catalogue invalide ({entry.Id}) : identifiant, valeur et note d'impact obligatoires.");
            }

            // Two entries under one identifier. Not a hole — every field is there — but the
            // id is the key Merge indexes the catalogue by, so the file loaded and the merge
            // threw. Refused rather than deduplicated, and that is where this reader parts
            // company with the fingerprint index in DriverBlocklist: there the key *is* the
            // driver, so a repeated fingerprint is the same driver twice and keeping the
            // first loses no coverage. Here the id is an arbitrary label; two entries
            // sharing it recognise two different pieces of software, and keeping one
            // quietly makes the other benign.
            if (!seen.Add(entry.Id))
            {
                throw new JsonException(
                    $"Catalogue bloatware avec l'identifiant « {entry.Id} » en double : "
                    + "chaque entrée doit porter un identifiant distinct, la casse ne "
                    + "distinguant pas deux identifiants. Rien n'est chargé.");
            }
        }

        return new BloatwareCatalog(file.AsOfUtc ?? "", entries);
    }
}
