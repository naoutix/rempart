using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Profils Wi-Fi enregistrés, jugés sur la robustesse de leur chiffrement.
///
/// <para>
/// Un réseau ouvert n'offre aucun chiffrement ; WEP est cryptographiquement cassé depuis
/// vingt ans. Le danger monte d'un cran quand la connexion est <b>automatique</b> : la
/// machine rejoint alors en silence tout point d'accès qui diffuse le SSID connu — un
/// attaquant n'a qu'à monter un « evil twin » du même nom. Un profil ouvert manuel est
/// notable ; en connexion automatique, il est suspect.
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
        // WEP : chiffrement cassé, quel que soit le mode de connexion.
        if (auth.Contains("WEP", StringComparison.Ordinal)
            || encryption == "WEP")
        {
            return (FindingSeverity.Suspicious,
                ["Chiffrement WEP — cassé depuis des années, une capture suffit à le lire."]);
        }

        // Réseau ouvert : aucun chiffrement. Le mode de connexion fait la différence entre
        // « à surveiller » et « exploitable en silence ».
        if (auth is "OPEN" or "")
        {
            return autoConnect
                ? (FindingSeverity.Suspicious,
                    ["Réseau ouvert en connexion automatique — la machine rejoint sans "
                     + "chiffrement tout point d'accès qui diffuse ce SSID (evil twin)."])
                : (FindingSeverity.Notable,
                    ["Réseau ouvert — le trafic n'est pas chiffré sur ce profil."]);
        }

        // WPA de première génération ou TKIP : déprécié, à remplacer par WPA2/WPA3 + AES.
        if (auth == "WPAPSK" || encryption == "TKIP")
        {
            return (FindingSeverity.Notable,
                ["Chiffrement WPA/TKIP déprécié — préférer WPA2 ou WPA3 avec AES."]);
        }

        return (FindingSeverity.Benign, []);
    }
}
