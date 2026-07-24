namespace Rempart.Core.Engine;

/// <summary>
/// Some fields cannot be compared naively from one scan to the next.
///
/// Distinguishing them serves two purposes: fixture tests (a reference output cannot
/// pin an uptime value) and <c>rempart diff</c> (M7), which would otherwise report a
/// difference between two machines on every volatile field.
/// </summary>
public static class FieldSemantics
{
    /// <summary>Changes on every run and carries no security-posture information.</summary>
    public static readonly IReadOnlySet<string> Volatile = new HashSet<string>(StringComparer.Ordinal)
    {
        "machine.uptimeSeconds",
    };

    /// <summary>Replaced by a hash in anonymised snapshots.</summary>
    public static readonly IReadOnlySet<string> Identifying = new HashSet<string>(StringComparer.Ordinal)
    {
        "machine.name",
    };

    public static bool IsComparable(string field) =>
        !Volatile.Contains(field) && !Identifying.Contains(field);
}
