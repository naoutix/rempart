namespace Rempart.Core.Providers;

/// <summary>
/// A browser extension installed in a user profile, with the permissions it was
/// actually granted.
///
/// <para>
/// An extension is third-party code running inside the most exposed tool on the
/// machine. Its granted permissions say exactly what it can do — read every page,
/// steal cookies, talk to a native binary. What matters for the audit: where it came
/// from (a store install or a sideload), and how far its reach extends.
/// </para>
/// </summary>
public sealed record BrowserExtension(
    /// <summary>Chrome, Edge, Brave, Chromium or Firefox.</summary>
    string Browser,

    /// <summary>Profile directory name (never a path — no Windows user name leaks).</summary>
    string Profile,

    string Id,
    string Name,
    string Version,

    /// <summary>Granted API permissions ("storage", "nativeMessaging", …).</summary>
    IReadOnlyList<string> Permissions,

    /// <summary>Granted host patterns ("&lt;all_urls&gt;", "https://example.com/*", …).</summary>
    IReadOnlyList<string> HostAccess,

    bool Enabled,

    /// <summary>
    /// False when the install path is a sideload vector: Chromium location 2/3/4
    /// (external pref, external registry, unpacked), or a Firefox extension not
    /// signed by addons.mozilla.org. Store and enterprise-policy installs are true.
    /// </summary>
    bool FromStore);

/// <summary>
/// Enumerates the browser extensions of the current user's profiles, already decoded.
/// Abstracted like the rest (ADR-001, D5): the judgment is tested against a given
/// list, without a browser installed.
/// </summary>
public interface IBrowserExtensionProvider
{
    IReadOnlyList<BrowserExtension> Read();
}
