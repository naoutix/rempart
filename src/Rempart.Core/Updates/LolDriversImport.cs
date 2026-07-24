using System.Text.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Transforms the official LOLDrivers list into a <see cref="DriverBlocklistFile"/>
/// ready for signing.
///
/// <para>
/// Publisher-side, online: the tool fetches the data, the publisher signs it. This is
/// no shortcut on trust — the upstream source (loldrivers.io) is the publisher's
/// choice, and it is <b>their signature</b>, not this download, that audited machines
/// verify. The same principle as a maintainer packaging an upstream source and then
/// signing it: they choose what they believe in, and their signature commits them.
/// </para>
///
/// <para>
/// Read with <c>JsonDocument</c> rather than generated types: the source schema is
/// vast (some thirty fields per sample) and does not belong to this project. Only what
/// is needed gets read — fingerprint, name, category — and a field changing elsewhere
/// breaks nothing.
/// </para>
/// </summary>
public static class LolDriversImport
{
    public const string SourceUrl = "https://www.loldrivers.io/api/drivers.json";

    /// <summary>
    /// Flattens each driver's samples into a list of unique fingerprints. A sample
    /// without a usable SHA-256 is discarded: an entry that cannot be checked against
    /// a loaded driver has no value, and inventing one would have a negative value.
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

                // The first occurrence of a fingerprint is kept: the same fingerprint
                // is never cataloged twice.
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
