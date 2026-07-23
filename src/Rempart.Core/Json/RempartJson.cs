using System.Text.Json;
using System.Text.Json.Serialization;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Core.Json;

/// <summary>
/// Sérialisation par génération de source : la réflexion n'est pas disponible sous
/// Native AOT, dont dépend le livrable en binaire unique.
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
/// Variante compacte, sans indentation. Pour les artefacts de données volumineux —
/// une liste de 2 000 pilotes indentée triplerait de taille sans rien apporter, sinon
/// à un fichier destiné à voyager et à être signé.
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

    /// <summary>Sérialise une liste de blocage sans indentation — c'est un artefact à transporter.</summary>
    public static string SerialiseCompact(DriverBlocklistFile blocklist) =>
        JsonSerializer.Serialize(blocklist, CompactJsonContext.Default.DriverBlocklistFile);

    /// <summary>Sérialise un catalogue bloatware sans indentation — artefact à transporter et signer.</summary>
    public static string SerialiseCompact(BloatwareCatalogFile catalog) =>
        JsonSerializer.Serialize(catalog, CompactJsonContext.Default.BloatwareCatalogFile);

    public static MachineSnapshot DeserialiseSnapshot(string json) =>
        JsonSerializer.Deserialize(json, RempartJsonContext.Default.MachineSnapshot)
        ?? throw new InvalidDataException("Instantané illisible.");
}
