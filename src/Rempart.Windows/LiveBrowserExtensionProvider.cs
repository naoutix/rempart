using Rempart.Core.Browsers;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Enumerates the browser extensions of the current user's profiles.
///
/// <para>
/// Chromium family: <c>Extensions</c> settings are read from <c>Secure Preferences</c>
/// and <c>Preferences</c> (observed: the entries live in the former), then joined with
/// each extension's <c>manifest.json</c> — settings without a manifest on disk are
/// sync leftovers, not installs. Firefox: <c>extensions.json</c> per profile. All
/// decoding is in Rempart.Core.Browsers; this class only finds and reads the files.
/// </para>
///
/// <para>
/// Scope: the user running the scan — same perimeter as the WinINET proxy. An
/// unreadable profile or file is skipped, never fatal: a partial inventory that says
/// nothing wrong beats a scan that dies on a locked browser file.
/// </para>
/// </summary>
public sealed class LiveBrowserExtensionProvider : IBrowserExtensionProvider
{
    private static readonly (string Browser, string RelativeRoot)[] ChromiumRoots =
    [
        ("Chrome", @"Google\Chrome\User Data"),
        ("Edge", @"Microsoft\Edge\User Data"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data"),
        ("Chromium", @"Chromium\User Data"),
    ];

    public IReadOnlyList<BrowserExtension> Read()
    {
        var result = new List<BrowserExtension>();

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var (browser, relativeRoot) in ChromiumRoots)
        {
            ReadChromiumBrowser(browser, Path.Combine(local, relativeRoot), result);
        }

        ReadFirefox(Path.Combine(roaming, @"Mozilla\Firefox\Profiles"), result);

        return result;
    }

    private static void ReadChromiumBrowser(string browser, string root, List<BrowserExtension> result)
    {
        if (!Directory.Exists(root))
        {
            return;
        }

        foreach (var profileDir in Directory.EnumerateDirectories(root))
        {
            var profile = Path.GetFileName(profileDir);

            if (profile != "Default" && !profile.StartsWith("Profile ", StringComparison.Ordinal))
            {
                continue;
            }

            try
            {
                ReadChromiumProfile(browser, profileDir, profile, result);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A profile locked or unreadable mid-scan: skip it, keep the others.
            }
        }
    }

    private static void ReadChromiumProfile(
        string browser, string profileDir, string profile, List<BrowserExtension> result)
    {
        // Entries observed in Secure Preferences; Preferences kept as a fallback for
        // older or divergent Chromium builds. First win per id — Secure read first.
        var settings = new Dictionary<string, ChromiumExtensionSetting>(StringComparer.Ordinal);

        foreach (var file in new[] { "Secure Preferences", "Preferences" })
        {
            if (TryReadAllText(Path.Combine(profileDir, file)) is { } json)
            {
                foreach (var setting in ChromiumExtensions.ParseSettings(json))
                {
                    settings.TryAdd(setting.Id, setting);
                }
            }
        }

        foreach (var setting in settings.Values)
        {
            var extensionDir = Path.Combine(profileDir, "Extensions", setting.RelativePath);

            // No manifest on disk: a sync leftover, not an install.
            if (TryReadAllText(Path.Combine(extensionDir, "manifest.json")) is not { } manifestJson
                || ChromiumExtensions.ParseManifest(manifestJson) is not { } manifest)
            {
                continue;
            }

            var name = manifest.Name;

            if (name.StartsWith("__MSG_", StringComparison.Ordinal)
                && manifest.DefaultLocale is { Length: > 0 } localeName)
            {
                var messages = TryReadAllText(
                    Path.Combine(extensionDir, "_locales", localeName, "messages.json"));
                name = ChromiumExtensions.ResolveName(name, messages);
            }

            result.Add(new BrowserExtension(
                browser, profile, setting.Id, name, manifest.Version,
                setting.GrantedApi ?? manifest.Permissions,
                setting.GrantedHosts ?? manifest.HostAccess,
                setting.Enabled, setting.FromStore));
        }
    }

    private static void ReadFirefox(string profilesRoot, List<BrowserExtension> result)
    {
        if (!Directory.Exists(profilesRoot))
        {
            return;
        }

        foreach (var profileDir in Directory.EnumerateDirectories(profilesRoot))
        {
            if (TryReadAllText(Path.Combine(profileDir, "extensions.json")) is { } json)
            {
                result.AddRange(FirefoxExtensions.Parse(json, Path.GetFileName(profileDir)));
            }
        }
    }

    private static string? TryReadAllText(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
