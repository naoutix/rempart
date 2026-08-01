using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// Simulated registry. Exists because collectors only know
/// <see cref="IRegistryProvider"/> (ADR-001, D5) — without this abstraction, every test
/// would require a Windows machine in the desired state.
/// </summary>
internal sealed class FakeRegistryProvider : IRegistryProvider
{
    private readonly Dictionary<string, RegistryRead> values = [];
    private readonly Dictionary<string, ReadStatus> keys = [];
    private readonly Dictionary<string, List<string>> subKeys = [];
    private readonly HashSet<string> deniedEnumerations = new(StringComparer.OrdinalIgnoreCase);

    public FakeRegistryProvider WithText(string keyPath, string valueName, string text)
    {
        values[Key(keyPath, valueName)] = RegistryRead.Found(RegistryValue.OfText(text));
        return this;
    }

    public FakeRegistryProvider WithNumber(string keyPath, string valueName, long number)
    {
        values[Key(keyPath, valueName)] = RegistryRead.Found(RegistryValue.OfNumber(number));
        return this;
    }

    /// <summary>
    /// A <c>REG_MULTI_SZ</c>, in the shape the live provider hands one over: the entries joined
    /// with newlines, under the kind Windows names it by.
    ///
    /// <para>
    /// Staged rather than spelled as text at each call site so that a reader of a multi-string
    /// value is exercised against the separator <c>LiveRegistryProvider</c> really produces —
    /// a reader splitting on anything else finds one entry where Windows wrote several, and an
    /// NRPT rule claiming <c>corp.example</c> and <c>lab.example</c> would come back claiming
    /// one name space nobody configured.
    /// </para>
    /// </summary>
    public FakeRegistryProvider WithMultiString(
        string keyPath, string valueName, params string[] entries)
    {
        values[Key(keyPath, valueName)] =
            RegistryRead.Found(new RegistryValue("MultiString", string.Join("\n", entries), null));

        return this;
    }

    public FakeRegistryProvider WithAccessDenied(string keyPath, string valueName)
    {
        values[Key(keyPath, valueName)] = RegistryRead.AccessDenied;
        return this;
    }

    public FakeRegistryProvider WithKey(string keyPath, ReadStatus status)
    {
        keys[keyPath] = status;
        return this;
    }

    public RegistryRead ReadValue(string keyPath, string valueName) =>
        values.TryGetValue(Key(keyPath, valueName), out var read) ? read : RegistryRead.NotFound;

    public ReadStatus KeyExists(string keyPath) =>
        keys.TryGetValue(keyPath, out var status) ? status : ReadStatus.NotFound;

    public FakeRegistryProvider WithSubKeys(string keyPath, params string[] names)
    {
        subKeys[keyPath] = [.. names];
        return this;
    }

    /// <summary>
    /// A key whose <em>enumeration</em> is refused, values and subkeys alike — an ACL laid
    /// on the key itself, which is what an attacker does to a <c>Run</c> key or to the
    /// per-user CLSID hive.
    ///
    /// <para>
    /// Distinct from <see cref="WithAccessDenied"/>, which refuses one named value: a
    /// collector that discovers what is there never names anything, so that refusal is
    /// invisible to it.
    /// </para>
    /// </summary>
    public FakeRegistryProvider WithDeniedEnumeration(string keyPath)
    {
        deniedEnumerations.Add(keyPath);
        return this;
    }

    // Found rather than NotFound for a key this fake was told nothing about: every test
    // written before enumeration carried a status expects an empty listing to be an answer,
    // and it is one — an empty Run key is the ordinary state of four out of five.
    public RegistrySubKeyList ListSubKeys(string keyPath) =>
        deniedEnumerations.Contains(keyPath) ? RegistrySubKeyList.AccessDenied
        : subKeys.TryGetValue(keyPath, out var names) ? RegistrySubKeyList.Found(names)
        : RegistrySubKeyList.Found([]);

    public RegistryValueList ListValues(string keyPath)
    {
        if (deniedEnumerations.Contains(keyPath))
        {
            return RegistryValueList.AccessDenied;
        }

        var prefix = keyPath + "||";

        return RegistryValueList.Found(values
            .Where(v => v.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Where(v => v.Value.Value is not null)
            .ToDictionary(v => v.Key[prefix.Length..], v => v.Value.Value!,
                StringComparer.OrdinalIgnoreCase));
    }

    private static string Key(string keyPath, string valueName) => $"{keyPath}||{valueName}";
}

internal sealed class FakeSystemInfoProvider(SystemInfo? info = null) : ISystemInfoProvider
{
    public static readonly SystemInfo Default = new(
        MachineName: "POSTE-TEST",
        OsVersion: "10.0.26200.0",
        Is64BitOperatingSystem: true,
        IsElevated: true,
        ProcessorCount: 8,
        UptimeSeconds: 4242,
        FirmwareType: "uefi");

    public SystemInfo Read() => info ?? Default;
}
