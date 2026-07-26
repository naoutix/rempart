namespace Rempart.Core.Software;

/// <summary>
/// Decomposes an Appx package full name.
///
/// <para>
/// The canonical form is <c>Name_Version_Architecture_ResourceId_PublisherHash</c>,
/// segments joined by underscores — e.g.
/// <c>AdobeNotificationClient_7.0.2.14_x64__enpm4xejd91yc</c>. Parse() extracts the name
/// and the version; FamilyName() derives the package's stable identifier
/// (name_publisherHash). Pure, no reflection. Never throws: an atypical name (a GUID,
/// missing segments) returns the full name as is, without a version.
/// </para>
/// </summary>
public static class AppxPackageName
{
    public static (string Name, string? Version) Parse(string fullName)
    {
        var parts = fullName.Split('_');
        if (parts.Length < 2 || parts[0].Length == 0)
        {
            return (fullName, null);
        }

        // The version is the second segment when it has version form (digits and dots).
        var version = parts[1].Length > 0 && parts[1].All(c => char.IsDigit(c) || c == '.')
            ? parts[1]
            : null;

        return (parts[0], version);
    }

    /// <summary>
    /// Whether the full name designates a split resource package — a scale or language
    /// asset of another package (<c>split.scale-150</c>, <c>split.language-fr</c>) — and
    /// not an application in its own right.
    ///
    /// <para>
    /// Windows keeps such an entry in the Appx repository after the package it belonged to
    /// is uninstalled, with no main entry left beside it. Reporting it as installed names
    /// software that is not there — the audit then asks the reader to uninstall something
    /// they cannot find.
    /// </para>
    /// <para>
    /// The test is on the resource segment starting with <c>split.</c>, deliberately not on
    /// it being non-empty: two dozen genuinely installed system packages, the Windows shell
    /// among them, carry <c>neutral</c> in that position. Erasing those from the inventory
    /// would be a worse error than the false positive this rule removes — an audit that
    /// stays silent about installed software.
    /// </para>
    /// </summary>
    public static bool IsResourcePackage(string fullName)
    {
        var parts = fullName.Split('_');

        // The resource segment is second to last: the publisher hash closes the name, so
        // this holds even for an identity name that itself contains an underscore.
        return parts.Length >= 5
            && parts[^2].StartsWith("split.", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Derives the Package Family Name (<c>Name_PublisherHash</c>) from a full name
    /// <c>Name_Version_Arch__PublisherHash</c>: the name (before the first <c>_</c>) and
    /// the publisher hash (after the last <c>_</c>). A name without separators is
    /// returned as is — it is already an identifier.
    /// </summary>
    public static string FamilyName(string fullName)
    {
        var first = fullName.IndexOf('_');
        var last = fullName.LastIndexOf('_');
        return first < 0 || first == last
            ? fullName
            : string.Concat(fullName.AsSpan(0, first), "_", fullName.AsSpan(last + 1));
    }
}
