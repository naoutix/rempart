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
/// </summary>
public sealed class DriverBlocklist
{
    private readonly Dictionary<string, BlockedDriver> bySha256;

    public string AsOfUtc { get; }

    public int Count => bySha256.Count;

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

        return new DriverBlocklist(file.AsOfUtc ?? "", drivers);
    }
}
