using System.Globalization;

namespace Rempart.Core.Providers;

/// <summary>
/// Turns the servicing stack's analysis output into figures.
///
/// <para>
/// Pure, so the one part that can silently go wrong — reading a number out of text — is
/// testable without an elevated Windows machine. The tool is asked for English output
/// (<c>/English</c>) precisely so this parser faces one set of labels rather than one
/// per system language.
/// </para>
///
/// <para>
/// <b>It refuses rather than guesses.</b> If the expected labels are not there — a
/// changed format, a language that came through anyway, output truncated by an error —
/// the result is a failed read carrying what was seen, never a set of zeros. Zero
/// reclaimable bytes is an answer; "the output did not say" is a different one, and a
/// report must not print the first when it means the second.
/// </para>
/// </summary>
public static class ComponentStoreParser
{
    private const string ActualSize = "Actual Size of Component Store";
    private const string Shared = "Shared with Windows";
    private const string Backups = "Backups and Disabled Features";
    private const string Cache = "Cache and Temporary Data";
    private const string LastCleanup = "Date of Last Cleanup";
    private const string Reclaimable = "Number of Reclaimable Packages";
    private const string Recommended = "Component Store Cleanup Recommended";

    public static ComponentStoreRead Parse(string output)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in output.Split('\n'))
        {
            // Split on the first colon only: the cleanup date carries its own.
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var label = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            if (label.Length > 0 && value.Length > 0)
            {
                fields[label] = value;
            }
        }

        // The actual size is the anchor. Without it there is no analysis to report, and
        // the layers below it would be a fragment presented as a whole.
        if (!fields.TryGetValue(ActualSize, out var actual) || TryBytes(actual) is not { } actualBytes)
        {
            return ComponentStoreRead.Failed(
                "Sortie de l'analyse non reconnue : « " + ActualSize + " » absent ou illisible. "
                + "Format ou langue inattendus — aucune taille n'est déduite. Vérifier avec "
                + "« rempart diagnose-store ».");
        }

        return new ComponentStoreRead(
            ReadStatus.Found,
            actualBytes,
            Bytes(fields, Shared),
            Bytes(fields, Backups),
            Bytes(fields, Cache),
            fields.TryGetValue(LastCleanup, out var cleaned) ? cleaned : null,
            fields.TryGetValue(Reclaimable, out var packages)
                && int.TryParse(packages, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count)
                    ? count
                    : null,
            fields.TryGetValue(Recommended, out var recommended)
                ? recommended.Trim().Equals("Yes", StringComparison.OrdinalIgnoreCase)
                : null,
            Diagnostic: null);
    }

    private static long? Bytes(IReadOnlyDictionary<string, string> fields, string label) =>
        fields.TryGetValue(label, out var value) ? TryBytes(value) : null;

    /// <summary>
    /// Reads a size such as <c>6.94 GB</c>.
    ///
    /// Binary multiples: the servicing stack writes GB where it means GiB, as the rest
    /// of Windows does. Using decimal multiples here would understate a component store
    /// by roughly 7 % — small enough to go unnoticed, large enough to be wrong.
    /// </summary>
    internal static long? TryBytes(string value)
    {
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length == 0
            || !double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var size))
        {
            return null;
        }

        var unit = parts.Length > 1 ? parts[1].Trim().ToUpperInvariant() : "BYTES";

        var multiplier = unit switch
        {
            "BYTES" or "B" => 1L,
            "KB" or "KIB" => 1024L,
            "MB" or "MIB" => 1024L * 1024,
            "GB" or "GIB" => 1024L * 1024 * 1024,
            "TB" or "TIB" => 1024L * 1024 * 1024 * 1024,
            _ => 0L,
        };

        // An unknown unit is not a size. Returning the bare number would silently turn
        // gigabytes into bytes.
        return multiplier == 0 ? null : (long)(size * multiplier);
    }
}
