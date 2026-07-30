using System.Text.Json;
using Rempart.Core.Json;

namespace Rempart.Core.Updates;

/// <summary>A driver known to be vulnerable or malicious, identified by fingerprint.</summary>
public sealed record BlockedDriver(string Sha256, string Name, string Category);

/// <summary>The blocklist file as it is serialized and signed.</summary>
public sealed record DriverBlocklistFile(
    string AsOfUtc,
    string? Source,
    List<BlockedDriver> Drivers);

/// <summary>
/// The list of known vulnerable drivers (LOLDrivers), queryable by fingerprint.
///
/// <para>
/// This dataset is the textbook case for ADR-002: ~1,500 entries refreshed every week,
/// which it would be pointless to ship frozen. The shipped baseline is therefore
/// deliberately <b>empty</b> — an honest floor (D12), not a stale list that would give
/// a false impression of coverage. The real list arrives signed, via
/// <c>rempart update</c>, once the channel is wired to this kind of data.
/// </para>
///
/// <para>
/// Invent nothing: embedding fingerprints "from memory" would produce false security
/// data — either silent or misleading. The mechanism is here; the material comes from
/// a verifiable source or from nowhere.
/// </para>
///
/// <para>
/// <b>A hole in the file is refused, never dereferenced.</b> A <c>record</c> imposes
/// nothing on deserialisation: <c>"drivers":[null]</c> is well-formed JSON that arrives
/// here as an entry whose every field is null, and the fingerprint index below used to
/// walk straight into it. The <see cref="NullReferenceException"/> that came out is
/// caught by neither <see cref="UpdateStore"/> nor <see cref="UpdatePlanner"/>, which
/// filter on <see cref="JsonException"/> — so a dataset with a hole in it ended the scan
/// instead of taking the documented "update refused, embedded baseline kept" path. It has
/// to be signed to get this far, which makes it robustness rather than an open door; the
/// fallback exists precisely for a file that is authentic and unreadable all the same.
/// </para>
/// </summary>
public sealed class DriverBlocklist
{
    private readonly Dictionary<string, BlockedDriver> bySha256;

    public string AsOfUtc { get; }

    public int Count => bySha256.Count;

    /// <summary>
    /// The drivers actually loaded, for guards that check the <em>shape</em> of what got in
    /// rather than what it matches. Nothing on the scan path reads this —
    /// <see cref="Match(string?)"/> is the whole interface a collector needs — but a guard
    /// that cannot see the entries cannot tell a list refused from a list loaded with a hole
    /// in it, and telling those apart is the point.
    /// </summary>
    public IReadOnlyCollection<BlockedDriver> Drivers => bySha256.Values;

    private DriverBlocklist(string asOfUtc, IEnumerable<BlockedDriver> drivers)
    {
        AsOfUtc = asOfUtc;

        // Indexed by lowercase fingerprint: that is the form the signature provider
        // returns fingerprints in, and a case-sensitive comparison would miss a driver
        // over a mere difference in formatting.
        bySha256 = drivers
            .Where(d => !string.IsNullOrWhiteSpace(d.Sha256))
            .GroupBy(d => d.Sha256.Trim().ToLowerInvariant(), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
    }

    public static readonly DriverBlocklist Empty = new("", []);

    /// <summary>
    /// Looks up a driver by fingerprint. <c>null</c> when the fingerprint is missing or
    /// unknown — a driver whose fingerprint could not be computed is not declared safe,
    /// it is simply not found here, and its verdict remains that of its signature.
    /// </summary>
    public BlockedDriver? Match(string? sha256) =>
        sha256 is { Length: > 0 } && bySha256.TryGetValue(sha256.Trim().ToLowerInvariant(), out var d)
            ? d
            : null;

    public static DriverBlocklist Parse(string json)
    {
        var file = JsonSerializer.Deserialize(json, RempartJsonContext.Default.DriverBlocklistFile);

        // An unreadable file is not an empty list: throw rather than load a truncated
        // security list "as best we can". The caller (the store) turns this into a
        // visible refusal.
        if (file is null)
        {
            throw new JsonException("Liste de blocage illisible.");
        }

        // A missing "drivers" key signals a file of another type (e.g. a bloatware catalog
        // signed without --kind, routed here by default): an empty array would load an
        // empty blocklist without throwing — a silent "update applied" over nothing. A
        // key that is present but empty remains a legitimate empty list.
        var drivers = file.Drivers
            ?? throw new JsonException("Liste de blocage sans clé « drivers » : fichier probablement d'un autre type.");

        // Refused as a whole rather than entry by entry: this is a security list, and an
        // entry quietly discarded is a driver the scan will then call benign. All three
        // fields count — Name and Category are not decoration, they travel into a finding's
        // reasons and details, where a null becomes a null in the report.
        //
        // Holes only. A fingerprint that is present but blank is still dropped by the index
        // in the constructor, exactly as before: that is a value, not a missing field, and
        // it is not what this guard was written for.
        for (var index = 0; index < drivers.Count; index++)
        {
            var driver = drivers[index];

            if (driver is null || driver.Sha256 is null
                || driver.Name is null || driver.Category is null)
            {
                throw new JsonException(
                    $"Entrée n° {index + 1} de la liste de blocage trouée : empreinte, nom et "
                    + "catégorie sont obligatoires. Rien n'est chargé.");
            }
        }

        return new DriverBlocklist(file.AsOfUtc ?? "", drivers);
    }
}
