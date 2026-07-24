using System.Text.Json;
using Rempart.Core.Providers;

namespace Rempart.Core.Browsers;

/// <summary>
/// Pure decoding of Firefox's <c>extensions.json</c>. No file access: testable
/// without a browser.
///
/// <para>
/// Only user-installed extensions are kept (<c>type == "extension"</c>,
/// <c>location == "app-profile"</c>): themes, dictionaries and Mozilla system add-ons
/// would be pure noise. <c>signedState</c> 2 means signed by addons.mozilla.org; an
/// absent field counts as signed — missing data must not fabricate a sideload.
/// </para>
/// </summary>
public static class FirefoxExtensions
{
    public static IReadOnlyList<BrowserExtension> Parse(string extensionsJson, string profile)
    {
        var result = new List<BrowserExtension>();

        try
        {
            using var document = JsonDocument.Parse(extensionsJson);

            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("addons", out var addons)
                || addons.ValueKind != JsonValueKind.Array)
            {
                return result;
            }

            foreach (var addon in addons.EnumerateArray())
            {
                if (Decode(addon, profile) is { } extension)
                {
                    result.Add(extension);
                }
            }
        }
        catch (JsonException)
        {
        }

        return result;
    }

    private static BrowserExtension? Decode(JsonElement addon, string profile)
    {
        if (addon.ValueKind != JsonValueKind.Object
            || JsonValues.String(addon, "type") != "extension"
            || JsonValues.String(addon, "location") != "app-profile"
            || JsonValues.String(addon, "id") is not { Length: > 0 } id)
        {
            return null;
        }

        var name = addon.TryGetProperty("defaultLocale", out var locale)
            && locale.ValueKind == JsonValueKind.Object
            ? JsonValues.String(locale, "name")
            : null;

        var active = addon.TryGetProperty("active", out var a)
            && a.ValueKind == JsonValueKind.True;

        var signed = !addon.TryGetProperty("signedState", out var signedState)
            || signedState.ValueKind != JsonValueKind.Number
            || signedState.GetInt32() >= 2;

        IReadOnlyList<string> permissions = [];
        IReadOnlyList<string> origins = [];

        if (addon.TryGetProperty("userPermissions", out var granted)
            && granted.ValueKind == JsonValueKind.Object)
        {
            permissions = [.. JsonValues.Strings(granted, "permissions")];
            origins = [.. JsonValues.Strings(granted, "origins")];
        }

        return new BrowserExtension(
            "Firefox", profile, id, name ?? id,
            JsonValues.String(addon, "version") ?? "",
            permissions, origins, active, signed);
    }
}
