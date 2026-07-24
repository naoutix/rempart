using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads the proxy configuration from the registry — per-user (WinINET), imposed by
/// Group Policy, and machine-wide (WinHTTP).
///
/// <para>
/// Everything goes through <see cref="IRegistryProvider"/>, including the WinHTTP
/// binary blob: <c>LiveRegistryProvider</c> surfaces a <c>REG_BINARY</c> as a
/// hexadecimal string, which is converted back to bytes for the decoder. No direct
/// registry access, so the read is replayable and has no OS coupling beyond this read.
/// </para>
/// </summary>
public sealed class LiveProxyProvider : IProxyProvider
{
    private const string WinInetKey =
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private const string WinHttpKey =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    private static readonly string[] PolicyKeys =
    [
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
        @"HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    ];

    private readonly IRegistryProvider registry;

    public LiveProxyProvider()
        : this(new LiveRegistryProvider())
    {
    }

    public LiveProxyProvider(IRegistryProvider registry) => this.registry = registry;

    public ProxyConfiguration Read() =>
        new(ReadWinInet(), ReadWinHttp(), ReadPolicyImposed());

    private ProxyScope ReadWinInet()
    {
        var enabled = registry.ReadValue(WinInetKey, "ProxyEnable").Value?.Number == 1;
        var server = Text(registry.ReadValue(WinInetKey, "ProxyServer"));
        var pac = Text(registry.ReadValue(WinInetKey, "AutoConfigURL"));
        var bypass = Split(Text(registry.ReadValue(WinInetKey, "ProxyOverride")));
        return new ProxyScope(enabled, server, pac, bypass);
    }

    private ProxyScope ReadWinHttp()
    {
        if (Text(registry.ReadValue(WinHttpKey, "WinHttpSettings")) is not { Length: > 0 } hex)
        {
            return ProxyScope.Disabled;
        }

        byte[] blob;
        try
        {
            blob = Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return ProxyScope.Disabled;
        }

        return WinHttpSettingsDecoder.Decode(blob);
    }

    private bool ReadPolicyImposed() =>
        PolicyKeys.Any(key =>
            Text(registry.ReadValue(key, "ProxyServer")) is { Length: > 0 }
            || Text(registry.ReadValue(key, "AutoConfigURL")) is { Length: > 0 });

    private static string? Text(RegistryRead read) =>
        read.Status == ReadStatus.Found ? read.Value?.Text : null;

    private static IReadOnlyList<string> Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
