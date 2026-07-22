using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Lit la configuration proxy depuis le registre — par utilisateur (WinINET), imposée par
/// stratégie de groupe, et machine (WinHTTP).
///
/// <para>
/// Tout passe par <see cref="IRegistryProvider"/>, y compris le blob binaire WinHTTP :
/// <c>LiveRegistryProvider</c> surface un <c>REG_BINARY</c> en chaîne hexadécimale, qu'on
/// reconvertit en octets pour le décodeur. Aucun accès direct au registre, donc rejouable
/// et sans couplage à l'OS au-delà de cette lecture.
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
