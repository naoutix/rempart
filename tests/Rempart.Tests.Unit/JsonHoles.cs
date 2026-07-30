using System.Text.Json.Nodes;

namespace Rempart.Tests.Unit;

/// <summary>
/// Punching holes in a serialised shape, and finding them again in what was read back.
///
/// <para>
/// Shared rather than copied because the reason to have it is the same everywhere it is
/// used: a <c>record</c> imposes nothing on deserialisation, so a field a reader treats as
/// mandatory arrives null the moment the JSON says so, and the only guard that keeps up
/// with a record gaining a field is one derived from the serialised shape instead of from
/// a list written by hand. It was written for the manifest verifier
/// (<see cref="ManifestTests"/>); the datasets that travel through the same channel need
/// exactly the same sweep, and a second copy would be the kind of hand-kept duplicate
/// this walk exists to avoid.
/// </para>
///
/// <para>
/// One blind spot, worth knowing before relying on it: a field of <b>value</b> type that
/// is removed deserialises to its zero, not to a hole — a missing <c>sizeBytes</c> reads
/// as 0 and a missing enum as its first member. The sweep sees holes, so it does not see
/// those.
/// </para>
/// </summary>
internal static class JsonHoles
{
    /// <summary>
    /// Every way one field can go missing from a JSON tree: each property and each array
    /// element in turn, set to null then removed. Both forms matter — a record field left
    /// out of the JSON and one written as <c>null</c> land on the same null reference.
    /// </summary>
    public static IEnumerable<(string Label, JsonNode Node)> Holes(JsonNode tree)
    {
        foreach (var path in Paths(tree))
        {
            var label = string.Join("/", path);

            yield return ($"{label} nul", Punch(tree, path, remove: false));
            yield return ($"{label} absent", Punch(tree, path, remove: true));
        }
    }

    /// <summary>Every property and element position in a tree, as a path of names and indices.</summary>
    public static List<List<object>> Paths(JsonNode? node, List<object>? prefix = null)
    {
        prefix ??= [];
        var paths = new List<List<object>>();

        switch (node)
        {
            case JsonObject properties:
                foreach (var (name, value) in properties)
                {
                    var here = new List<object>(prefix) { name };
                    paths.Add(here);
                    paths.AddRange(Paths(value, here));
                }

                break;

            case JsonArray elements:
                for (var index = 0; index < elements.Count; index++)
                {
                    var here = new List<object>(prefix) { index };
                    paths.Add(here);
                    paths.AddRange(Paths(elements[index], here));
                }

                break;
        }

        return paths;
    }

    /// <summary>Copies a tree with the node at <paramref name="path"/> nulled or removed.</summary>
    public static JsonNode Punch(JsonNode tree, IReadOnlyList<object> path, bool remove)
    {
        var copy = JsonNode.Parse(tree.ToJsonString())!;
        var parent = copy;

        for (var step = 0; step < path.Count - 1; step++)
        {
            parent = path[step] is string name ? parent[name]! : parent[(int)path[step]]!;
        }

        if (path[^1] is string property)
        {
            if (remove)
            {
                parent.AsObject().Remove(property);
            }
            else
            {
                parent.AsObject()[property] = null;
            }
        }
        else if (remove)
        {
            parent.AsArray().RemoveAt((int)path[^1]);
        }
        else
        {
            parent.AsArray()[(int)path[^1]] = null;
        }

        return copy;
    }

    /// <summary>Path of the first JSON null in a tree, or <c>null</c> when it has no hole.</summary>
    public static string? FirstNull(JsonNode? tree, string prefix = "")
    {
        return tree switch
        {
            null => prefix.Length == 0 ? "la racine" : prefix,

            JsonObject properties => properties
                .Select(property => FirstNull(property.Value, $"{prefix}/{property.Key}"))
                .FirstOrDefault(found => found is not null),

            JsonArray elements => elements
                .Select((element, index) => FirstNull(element, $"{prefix}/{index}"))
                .FirstOrDefault(found => found is not null),

            _ => null,
        };
    }
}
