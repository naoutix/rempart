using System.Text.Json;

namespace Rempart.Core.Browsers;

/// <summary>A parsed Chromium extension manifest. Themes and apps yield null.</summary>
public sealed record ChromiumManifest(
    string Name,
    string Version,
    string? DefaultLocale,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> HostAccess);

/// <summary>One entry of <c>extensions.settings</c>, already filtered and decoded.</summary>
public sealed record ChromiumExtensionSetting(
    string Id,
    string RelativePath,
    bool Enabled,
    bool FromStore,
    IReadOnlyList<string>? GrantedApi,
    IReadOnlyList<string>? GrantedHosts);

/// <summary>
/// Pure decoding of the Chromium extension files (manifest.json, Preferences /
/// Secure Preferences, _locales messages). No file access: testable without a browser.
///
/// <para>
/// Field semantics were verified against a real Chrome 150 and Edge profile
/// (2026-07-24) rather than taken from documentation — see the M5c design note. Two
/// findings matter: <c>state</c> no longer exists (enabled/disabled is carried by
/// <c>disable_reasons</c>), and <c>from_webstore</c> is false for Microsoft Add-ons
/// installs on Edge, so only <c>location</c> can tell a sideload apart.
/// </para>
/// </summary>
public static class ChromiumExtensions
{
    public static ChromiumManifest? ParseManifest(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || root.TryGetProperty("theme", out _)
                || root.TryGetProperty("app", out _))
            {
                return null;
            }

            // MV2 mixes host patterns into "permissions"; MV3 separates them into
            // "host_permissions". Classify by shape so both versions come out alike.
            var api = new List<string>();
            var hosts = new List<string>();

            foreach (var token in JsonValues.Strings(root, "permissions"))
            {
                (IsHostPattern(token) ? hosts : api).Add(token);
            }

            hosts.AddRange(JsonValues.Strings(root, "host_permissions"));

            return new ChromiumManifest(
                JsonValues.String(root, "name") ?? "",
                JsonValues.String(root, "version") ?? "",
                JsonValues.String(root, "default_locale"),
                api,
                hosts);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves a <c>__MSG_key__</c> placeholder against the extension's
    /// <c>_locales/&lt;default_locale&gt;/messages.json</c>. Chrome matches the key
    /// case-insensitively; an unresolved placeholder keeps the raw name — an honest
    /// oddity in the report beats an invented one.
    /// </summary>
    public static string ResolveName(string rawName, string? messagesJson)
    {
        if (messagesJson is null
            || !rawName.StartsWith("__MSG_", StringComparison.Ordinal)
            || !rawName.EndsWith("__", StringComparison.Ordinal))
        {
            return rawName;
        }

        var key = rawName[6..^2];

        try
        {
            using var document = JsonDocument.Parse(messagesJson);

            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return rawName;
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (string.Equals(property.Name, key, StringComparison.OrdinalIgnoreCase)
                    && property.Value.ValueKind == JsonValueKind.Object
                    && JsonValues.String(property.Value, "message") is { } message)
                {
                    return message;
                }
            }
        }
        catch (JsonException)
        {
        }

        return rawName;
    }

    public static IReadOnlyList<ChromiumExtensionSetting> ParseSettings(string preferencesJson)
    {
        var result = new List<ChromiumExtensionSetting>();

        try
        {
            using var document = JsonDocument.Parse(preferencesJson);

            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("extensions", out var extensions)
                || extensions.ValueKind != JsonValueKind.Object
                || !extensions.TryGetProperty("settings", out var settings)
                || settings.ValueKind != JsonValueKind.Object)
            {
                return result;
            }

            foreach (var entry in settings.EnumerateObject())
            {
                if (Decode(entry.Name, entry.Value) is { } setting)
                {
                    result.Add(setting);
                }
            }
        }
        catch (JsonException)
        {
        }

        return result;
    }

    private static ChromiumExtensionSetting? Decode(string id, JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        // Sync leaves stub entries with no path; components point into the browser's
        // own installation with an absolute path. Only a path relative to the profile
        // denotes an extension actually installed there. Absolute is detected by hand:
        // System.IO.Path reads Windows paths wrongly when fixtures replay on Linux.
        var path = JsonValues.String(value, "path");

        if (string.IsNullOrEmpty(path) || IsAbsolute(path))
        {
            return null;
        }

        // Enabled/disabled lives in disable_reasons on current Chrome/Edge; "state"
        // only remains in older captures (0 = disabled).
        var disabled =
            (value.TryGetProperty("disable_reasons", out var reasons)
                && reasons.ValueKind == JsonValueKind.Array
                && reasons.GetArrayLength() > 0)
            || (value.TryGetProperty("state", out var state)
                && state.ValueKind == JsonValueKind.Number
                && state.GetInt32() == 0);

        // location 2 (external pref), 3 (external registry) and 4 (unpacked) are the
        // sideload vectors. Store (1) and enterprise policy (10) are not. Absent
        // location is treated as a store install: missing data must not fabricate a
        // suspicion.
        var location = value.TryGetProperty("location", out var loc)
            && loc.ValueKind == JsonValueKind.Number ? loc.GetInt32() : 1;

        IReadOnlyList<string>? grantedApi = null;
        IReadOnlyList<string>? grantedHosts = null;

        if (value.TryGetProperty("granted_permissions", out var granted)
            && granted.ValueKind == JsonValueKind.Object)
        {
            grantedApi = [.. JsonValues.Strings(granted, "api")];
            grantedHosts =
            [
                .. JsonValues.Strings(granted, "explicit_host")
                    .Concat(JsonValues.Strings(granted, "scriptable_host"))
                    .Distinct(StringComparer.Ordinal),
            ];
        }

        return new ChromiumExtensionSetting(
            id, path, !disabled, location is not (2 or 3 or 4), grantedApi, grantedHosts);
    }

    private static bool IsHostPattern(string token) =>
        token == "<all_urls>" || token.Contains("://", StringComparison.Ordinal);

    private static bool IsAbsolute(string path) =>
        path.StartsWith('\\') || path.StartsWith('/')
        || (path.Length >= 2 && path[1] == ':');
}
