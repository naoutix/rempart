namespace Rempart.Core.Providers;

/// <summary>
/// Une règle de pare-feu Windows, réduite à ce qui décide de l'atteignabilité d'un port.
///
/// <para>
/// Les règles sont stockées sous forme de chaînes <c>Clé=Valeur</c> séparées par des
/// barres verticales. On n'en retient que les champs qui pèsent sur la question : cette
/// règle laisse-t-elle entrer une connexion vers ce port, sur ce profil ? Le nom affiché,
/// la description, le contexte d'intégration n'y changent rien.
/// </para>
/// </summary>
public sealed record FirewallRule(
    bool Active,

    /// <summary>« In » ou « Out ». Seul l'entrant expose.</summary>
    string Direction,

    /// <summary>« Allow » ou « Block ». Un blocage l'emporte sur une autorisation.</summary>
    string Action,

    /// <summary>Numéro de protocole IANA — 6 pour TCP, 17 pour UDP. Nul = tout protocole.</summary>
    int? Protocol,

    /// <summary>Spécification de port local brute — « 445 », « 80,443 », « 1000-2000 »,
    /// ou un mot-clé (« RPC »). Nul = tout port.</summary>
    string? LocalPorts,

    /// <summary>Profils où la règle s'applique. Vide = tous les profils.</summary>
    IReadOnlyList<string> Profiles,

    /// <summary>Chemin de l'application concernée, variables d'environnement comprises.
    /// Nul = toute application.</summary>
    string? App)
{
    /// <summary>
    /// Analyse une chaîne de règle du registre. Rend null quand la chaîne n'est pas une
    /// règle exploitable — en-tête de version seul, champ direction absent.
    /// </summary>
    public static FirewallRule? Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Le champ Profile se répète — « Profile=Domain|Profile=Private|Profile=Public » —
        // au lieu de se combiner en une seule valeur. Un dictionnaire n'en garderait que le
        // dernier et perdrait les autres : on accumule à part.
        var profiles = new List<string>();

        foreach (var part in raw.Split('|'))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            var key = part[..eq];
            var value = part[(eq + 1)..];

            if (key.Equals("Profile", StringComparison.OrdinalIgnoreCase))
            {
                profiles.AddRange(value.Split(
                    ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
            else
            {
                fields[key] = value;
            }
        }

        if (!fields.TryGetValue("Dir", out var direction))
        {
            return null;
        }

        return new FirewallRule(
            Active: fields.TryGetValue("Active", out var active)
                && active.Equals("TRUE", StringComparison.OrdinalIgnoreCase),
            Direction: direction,
            Action: fields.TryGetValue("Action", out var action) ? action : "Allow",
            Protocol: fields.TryGetValue("Protocol", out var proto)
                && int.TryParse(proto, out var protoNum) ? protoNum : null,
            LocalPorts: fields.TryGetValue("LPort", out var lport) ? lport : null,
            Profiles: profiles,
            App: fields.TryGetValue("App", out var app) ? app : null);
    }
}
