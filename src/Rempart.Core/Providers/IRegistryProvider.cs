namespace Rempart.Core.Providers;

/// <summary>
/// Outcome of a read. Distinguishing <see cref="NotFound"/> from
/// <see cref="AccessDenied"/> is essential: a missing key is information, a denied
/// access is a gap in the audit. Conflating them would produce a report that misleads
/// by omission.
/// </summary>
public enum ReadStatus
{
    Found,
    NotFound,
    AccessDenied,
}

public sealed record RegistryValue(string Kind, string? Text, long? Number)
{
    public static RegistryValue OfText(string text) => new("String", text, null);

    public static RegistryValue OfNumber(long number) => new("DWord", null, number);

    public override string ToString() => Text ?? Number?.ToString() ?? string.Empty;
}

public sealed record RegistryRead(ReadStatus Status, RegistryValue? Value)
{
    public static readonly RegistryRead NotFound = new(ReadStatus.NotFound, null);
    public static readonly RegistryRead AccessDenied = new(ReadStatus.AccessDenied, null);

    public static RegistryRead Found(RegistryValue value) => new(ReadStatus.Found, value);
}

/// <summary>
/// Registry access. No collector calls Windows directly (ADR-001, D5): this is what
/// allows replaying a scan offline from a snapshot.
/// </summary>
public interface IRegistryProvider
{
    /// <param name="keyPath">Full path, e.g. <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</c>.</param>
    RegistryRead ReadValue(string keyPath, string valueName);

    /// <summary>Whether a key exists — useful when presence alone is the signal.</summary>
    ReadStatus KeyExists(string keyPath);

    /// <summary>
    /// All values of a key, by name.
    ///
    /// Rules query a value they already know; autostart enumeration instead discovers
    /// what is there. Entries whose names are unknown cannot be looked up by name.
    /// </summary>
    IReadOnlyDictionary<string, RegistryValue> ListValues(string keyPath);

    /// <summary>
    /// The names of a key's subkeys. Used to discover a tree whose entries are not
    /// known in advance — for example CLSIDs registered by a user, whose identifiers
    /// are unpredictable. Empty if the key is missing or access is denied.
    /// </summary>
    IReadOnlyList<string> ListSubKeys(string keyPath);
}
