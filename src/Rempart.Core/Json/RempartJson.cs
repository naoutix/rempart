using System.Text.Json;
using System.Text.Json.Serialization;
using Rempart.Core.Engine;
using Rempart.Core.Snapshots;

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
[JsonSerializable(typeof(MachineSnapshot))]
public sealed partial class RempartJsonContext : JsonSerializerContext;

public static class RempartJson
{
    public static string Serialise(ScanResult result) =>
        JsonSerializer.Serialize(result, RempartJsonContext.Default.ScanResult);

    public static string Serialise(MachineSnapshot snapshot) =>
        JsonSerializer.Serialize(snapshot, RempartJsonContext.Default.MachineSnapshot);

    public static MachineSnapshot DeserialiseSnapshot(string json) =>
        JsonSerializer.Deserialize(json, RempartJsonContext.Default.MachineSnapshot)
        ?? throw new InvalidDataException("Instantané illisible.");
}
