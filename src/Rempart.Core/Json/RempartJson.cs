using System.Text.Json;
using System.Text.Json.Serialization;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Core.Json;

/// <summary>
/// Source-generated serialisation: reflection is not available under Native AOT, which
/// the single-binary deliverable depends on.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
[JsonSerializable(typeof(ScanResult))]
[JsonSerializable(typeof(Dns.DnsProbeReport))]
[JsonSerializable(typeof(MachineSnapshot))]
[JsonSerializable(typeof(SignedManifest))]
[JsonSerializable(typeof(ManifestPayload))]
[JsonSerializable(typeof(DriverBlocklistFile))]
[JsonSerializable(typeof(BloatwareCatalogFile))]
[JsonSerializable(typeof(ManifestEntry))]
public sealed partial class RempartJsonContext : JsonSerializerContext;

/// <summary>
/// Compact variant, without indentation. For large data artifacts — an indented list of
/// 2,000 drivers would triple in size and indentation adds nothing to a file that is
/// meant to be transferred and signed.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
[JsonSerializable(typeof(DriverBlocklistFile))]
[JsonSerializable(typeof(BloatwareCatalogFile))]
internal sealed partial class CompactJsonContext : JsonSerializerContext;

public static class RempartJson
{
    public static string Serialise(ScanResult result) =>
        JsonSerializer.Serialize(result, RempartJsonContext.Default.ScanResult);

    public static string Serialise(MachineSnapshot snapshot) =>
        JsonSerializer.Serialize(snapshot, RempartJsonContext.Default.MachineSnapshot);

    public static string Serialise(SignedManifest manifest) =>
        JsonSerializer.Serialize(manifest, RempartJsonContext.Default.SignedManifest);

    /// <summary>Serialises a blocklist without indentation — it is an artifact meant for transfer.</summary>
    public static string SerialiseCompact(DriverBlocklistFile blocklist) =>
        JsonSerializer.Serialize(blocklist, CompactJsonContext.Default.DriverBlocklistFile);

    /// <summary>Serialises a bloatware catalog without indentation — an artifact to transfer and sign.</summary>
    public static string SerialiseCompact(BloatwareCatalogFile catalog) =>
        JsonSerializer.Serialize(catalog, CompactJsonContext.Default.BloatwareCatalogFile);

    public static MachineSnapshot DeserialiseSnapshot(string json) =>
        JsonSerializer.Deserialize(json, RempartJsonContext.Default.MachineSnapshot)
        ?? throw new InvalidDataException("Instantané illisible.");
}
