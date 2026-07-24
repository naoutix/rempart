using System.Text.Json;

namespace Rempart.Core.Browsers;

/// <summary>
/// Tolerant readers over <see cref="JsonElement"/>: a missing or mistyped property
/// degrades to nothing rather than throwing — browser files are third-party input.
/// </summary>
internal static class JsonValues
{
    public static string? String(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    public static IEnumerable<string> Strings(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                yield return item.GetString()!;
            }
        }
    }
}
