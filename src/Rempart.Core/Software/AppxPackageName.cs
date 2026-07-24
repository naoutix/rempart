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
