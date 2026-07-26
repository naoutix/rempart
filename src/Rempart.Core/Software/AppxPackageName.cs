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
    /// Keeps, for each installed identity, only the highest registered version.
    ///
    /// <para>
    /// Windows leaves older versions of a package registered after an update: on the test
    /// machine <c>Microsoft.ECApp</c> and <c>Microsoft.LockApp</c> each appeared three
    /// times, for 113 distinct family names across 148 raw entries. Reporting all of them
    /// is not a false positive — the software is installed — but it inflates the inventory
    /// with rows that describe one thing.
    /// </para>
    ///
    /// <para>
    /// <b>The identity is the family name <i>and</i> the architecture</b>, never the family
    /// alone. <c>Microsoft.NET.Native.Framework</c> ships an <c>x64</c> and an <c>x86</c>
    /// package that share a family name and are both genuinely installed; grouping on the
    /// family would erase one of them, trading a harmless duplicate for a missing entry.
    /// </para>
    ///
    /// <para>
    /// Versions are compared as numbers. As text, <c>10.0.26100.900</c> sorts after
    /// <c>10.0.26100.8737</c>, which would keep the older build. An entry whose version
    /// cannot be parsed is kept rather than dropped: losing a package is worse than
    /// listing it twice.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> LatestPerIdentity(IEnumerable<string> fullNames)
    {
        var best = new Dictionary<string, (string FullName, Version? Version)>(
            StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var fullName in fullNames)
        {
            var parts = fullName.Split('_');
            var architecture = parts.Length >= 5 ? parts[^3] : string.Empty;
            var identity = FamilyName(fullName) + "|" + architecture;

            _ = Version.TryParse(Parse(fullName).Version, out var version);

            if (!best.TryGetValue(identity, out var current))
            {
                best[identity] = (fullName, version);
                order.Add(identity);
                continue;
            }

            // A version that did not parse never displaces one that did: without a
            // number to compare, there is no ground to call it newer.
            if (version is not null && (current.Version is null || version > current.Version))
            {
                best[identity] = (fullName, version);
            }
        }

        return [.. order.Select(identity => best[identity].FullName)];
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
