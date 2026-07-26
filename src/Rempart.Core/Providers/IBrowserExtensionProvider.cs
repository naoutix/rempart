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
/// <summary>
/// The extensions found, plus the profiles that could not be read.
///
/// <para>
/// Unlike drivers or processes, <b>an empty list here is an ordinary answer</b>: plenty of
/// machines carry no browser extension, and flagging that would cry wolf. What must be
/// said is the profile whose file could not be parsed — before this, a corrupt
/// <c>Secure Preferences</c> silently removed a whole profile from the inventory, which
/// is exactly where a sideloaded extension would sit.
/// </para>
/// </summary>
public sealed record BrowserExtensionRead(
    ReadStatus Status,
    IReadOnlyList<BrowserExtension> Extensions,
    string? Diagnostic = null)
{
    public static BrowserExtensionRead Found(IReadOnlyList<BrowserExtension> extensions) =>
        new(ReadStatus.Found, extensions);

    /// <summary>
    /// What was read, and what could not be. Partial by design: the extensions that were
    /// decoded stay in the inventory, and the unreadable profile is named beside them.
    /// </summary>
    public static BrowserExtensionRead Partial(
        IReadOnlyList<BrowserExtension> extensions, IReadOnlyList<string> unreadable) =>
        new(ReadStatus.AccessDenied, extensions,
            "Profil(s) de navigateur illisible(s) : " + string.Join(", ", unreadable)
            + ". Une extension installée dans ce profil n'apparaît pas dans l'inventaire.");
}

public interface IBrowserExtensionProvider
{
    BrowserExtensionRead Read();
}
