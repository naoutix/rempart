using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Saved Wi-Fi profiles, judged on the strength of their encryption.
///
/// <para>
/// An open network offers no encryption; WEP has been cryptographically broken for
/// twenty years. The danger goes up a notch when the connection is <b>automatic</b>:
/// the machine then silently joins any access point broadcasting the known SSID — an
/// attacker merely has to stand up an "evil twin" of the same name. An open manual
/// profile is notable; with automatic connection, it is suspicious.
/// </para>
/// </summary>
public sealed class WifiProfileCollector : IFindingCollector
{
    public string Name => "wifi-profile";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var profile in providers.Wifi.Read())
        {
            findings.Add(Judge(profile));
        }

        return findings;
    }

    private static Finding Judge(WifiProfile profile)
    {
        var auth = profile.Authentication.ToUpperInvariant();
        var encryption = profile.Encryption.ToUpperInvariant();
        var connection = profile.AutoConnect ? "automatique" : "manuelle";

        var (severity, reasons) = Assess(auth, encryption, profile.AutoConnect);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["ssid"] = profile.Name,
            ["authentification"] = profile.Authentication,
            ["chiffrement"] = profile.Encryption,
            ["connexion"] = connection,
        };

        return new Finding("wifi-profile", profile.Name, profile.Name, severity, reasons, details);
    }

    private static (FindingSeverity, IReadOnlyList<string>) Assess(
        string auth, string encryption, bool autoConnect)
    {
        // WEP: broken encryption, whatever the connection mode.
        if (auth.Contains("WEP", StringComparison.Ordinal)
            || encryption == "WEP")
        {
            return (FindingSeverity.Suspicious,
                ["Chiffrement WEP — cassé depuis des années, une capture suffit à le lire."]);
        }

        // Open network: no encryption. The connection mode makes the difference between
        // "worth watching" and "silently exploitable".
        if (auth is "OPEN" or "")
        {
            return autoConnect
                ? (FindingSeverity.Suspicious,
                    ["Réseau ouvert en connexion automatique — la machine rejoint sans "
                     + "chiffrement tout point d'accès qui diffuse ce SSID (evil twin)."])
                : (FindingSeverity.Notable,
                    ["Réseau ouvert — le trafic n'est pas chiffré sur ce profil."]);
        }

        // First-generation WPA or TKIP: deprecated, to be replaced by WPA2/WPA3 + AES.
        if (auth == "WPAPSK" || encryption == "TKIP")
        {
            return (FindingSeverity.Notable,
                ["Chiffrement WPA/TKIP déprécié — préférer WPA2 ou WPA3 avec AES."]);
        }

        return (FindingSeverity.Benign, []);
    }
}
