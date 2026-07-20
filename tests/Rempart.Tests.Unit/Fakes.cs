using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// Registre simulé. Existe parce que les collecteurs ne connaissent que
/// <see cref="IRegistryProvider"/> (ADR-001, D5) — sans cette abstraction, chaque test
/// exigerait une machine Windows dans l'état voulu.
/// </summary>
internal sealed class FakeRegistryProvider : IRegistryProvider
{
    private readonly Dictionary<string, RegistryRead> values = [];
    private readonly Dictionary<string, ReadStatus> keys = [];

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

    public IReadOnlyDictionary<string, RegistryValue> ListValues(string keyPath)
    {
        var prefix = keyPath + "||";

        return values
            .Where(v => v.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Where(v => v.Value.Value is not null)
            .ToDictionary(v => v.Key[prefix.Length..], v => v.Value.Value!,
                StringComparer.OrdinalIgnoreCase);
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
