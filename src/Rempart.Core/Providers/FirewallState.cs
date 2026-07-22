namespace Rempart.Core.Providers;

/// <summary>
/// Verdict d'atteignabilité d'un port entrant à travers le pare-feu.
/// </summary>
public enum FirewallReachability
{
    /// <summary>Le pare-feu n'a pas pu être lu : on ne tranche pas à sa place.</summary>
    Unknown,

    /// <summary>Une règle active laisse entrer, ou le pare-feu est éteint.</summary>
    Reachable,

    /// <summary>Aucune règle ne laisse entrer, ou un blocage l'emporte.</summary>
    Blocked,
}

/// <summary>
/// L'état du pare-feu qui décide si un port en écoute est réellement joignable.
///
/// <para>
/// La question du lot M4 : un port ouvert mais que le pare-feu bloque n'est pas exposé
/// comme un port que le pare-feu laisse entrer. Le profil <b>Public</b> est celui qui
/// compte — le cas du réseau non maîtrisé, où la machine se retrouve dès qu'elle rejoint
/// un Wi-Fi ouvert. Un port autorisé en Public est exposé quoi qu'il arrive.
/// </para>
///
/// <para>
/// Le défaut entrant de Windows est le blocage : sans règle d'autorisation qui corresponde,
/// un port n'est pas joignable. C'est ce qui rend le signal exploitable — la plupart des
/// ports système en écoute ne portent aucune règle et retombent en « bloqué ».
/// </para>
/// </summary>
public sealed record FirewallState(
    IReadOnlyList<FirewallRule> Rules,
    bool PublicFirewallEnabled,
    bool PublicDefaultInboundAllow)
{
    /// <summary>État vide : le pare-feu n'a pas été lu. Toute question rend « inconnu ».</summary>
    public static readonly FirewallState Unread = new([], PublicFirewallEnabled: false, false)
    {
        Readable = false,
    };

    /// <summary>Faux quand l'état provient de <see cref="Unread"/> : aucune conclusion.</summary>
    public bool Readable { get; init; } = true;

    /// <summary>
    /// Un port en écoute est-il joignable en entrée sur le profil Public ?
    ///
    /// <para>
    /// Le pare-feu éteint laisse tout passer. Sinon, parmi les règles qui s'appliquent
    /// vraiment à ce port — bon sens de circulation, bon profil, bon protocole, bon port,
    /// bonne application — un blocage l'emporte sur une autorisation, et l'absence de toute
    /// règle retombe sur le défaut entrant, le blocage.
    /// </para>
    /// </summary>
    public FirewallReachability InboundReachability(string protocol, int port, string? appPath)
    {
        if (!Readable)
        {
            return FirewallReachability.Unknown;
        }

        if (!PublicFirewallEnabled)
        {
            return FirewallReachability.Reachable;
        }

        var protocolNumber = protocol switch
        {
            "TCP" => 6,
            "UDP" => 17,
            _ => -1,
        };

        var applicable = Rules.Where(rule => Applies(rule, protocolNumber, port, appPath)).ToList();

        if (applicable.Any(rule => rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase)))
        {
            return FirewallReachability.Blocked;
        }

        if (applicable.Any(rule => rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)))
        {
            return FirewallReachability.Reachable;
        }

        return PublicDefaultInboundAllow
            ? FirewallReachability.Reachable
            : FirewallReachability.Blocked;
    }

    private static bool Applies(FirewallRule rule, int protocolNumber, int port, string? appPath)
    {
        if (!rule.Active || !rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Profil vide = tous les profils, Public compris.
        if (rule.Profiles.Count > 0
            && !rule.Profiles.Contains("Public", StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        // Protocole nul = tout protocole.
        if (rule.Protocol is { } ruleProtocol && ruleProtocol != protocolNumber)
        {
            return false;
        }

        // Règle sans port : elle vaut pour tout port, mais seulement liée à une application
        // précise. Une règle sans port ni application est en pratique une règle d'app
        // empaquetée — portée par un identifiant de paquet qu'on ne sait pas rapprocher d'un
        // chemin — et la compter ouvrirait à tort tous les ports. On ne la retient donc que
        // si son application correspond au propriétaire connu du port.
        if (rule.LocalPorts is null)
        {
            return rule.App is not null && AppMatches(rule.App, appPath);
        }

        if (!PortMatches(rule.LocalPorts, port))
        {
            return false;
        }

        return AppMatches(rule.App, appPath);
    }

    /// <summary>
    /// Le port tombe-t-il dans la spécification de la règle ? Une spécification nulle vaut
    /// « tout port ». Les mots-clés — « RPC », « RPC-EPMap » — désignent des ports
    /// dynamiques qu'on ne sait pas résoudre ici : on ne prétend pas qu'ils correspondent,
    /// pour ne pas inventer une autorisation. Le port réel reste alors jugé sur les autres
    /// règles, à défaut sur le blocage par défaut.
    /// </summary>
    private static bool PortMatches(string? spec, int port)
    {
        if (spec is null)
        {
            return true;
        }

        foreach (var token in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = token.IndexOf('-');
            if (dash > 0)
            {
                if (int.TryParse(token[..dash], out var low)
                    && int.TryParse(token[(dash + 1)..], out var high)
                    && port >= low && port <= high)
                {
                    return true;
                }
            }
            else if (int.TryParse(token, out var single) && single == port)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// La règle vise-t-elle l'application propriétaire du port ? Une règle sans champ
    /// application vaut « toute application ». Une règle qui en porte un ne s'applique qu'à
    /// lui : si l'on ne connaît pas le propriétaire — un port système hors de portée sans
    /// élévation — on ne peut pas confirmer qu'elle s'applique, et on ne le suppose pas.
    /// </summary>
    private static bool AppMatches(string? ruleApp, string? appPath)
    {
        if (ruleApp is null)
        {
            return true;
        }

        if (appPath is null)
        {
            return false;
        }

        return string.Equals(Expand(ruleApp), appPath, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Développe les variables d'environnement d'un chemin de règle vers leur valeur fixe.
    /// Fait à la main, sans lire l'environnement de la machine : le rejeu d'une capture doit
    /// donner le même verdict partout, pas dépendre de l'hôte qui le relit.
    /// </summary>
    private static string Expand(string path)
    {
        ReadOnlySpan<(string Var, string Value)> table =
        [
            ("%SystemRoot%", @"C:\Windows"),
            ("%windir%", @"C:\Windows"),
            ("%SystemDrive%", "C:"),
            ("%ProgramFiles%", @"C:\Program Files"),
            ("%ProgramFiles(x86)%", @"C:\Program Files (x86)"),
        ];

        foreach (var (name, value) in table)
        {
            if (path.StartsWith(name, StringComparison.OrdinalIgnoreCase))
            {
                return value + path[name.Length..];
            }
        }

        return path;
    }
}

/// <summary>
/// Lit l'état du pare-feu. Abstrait comme le reste (ADR-001, D5) : la règle croisée — un
/// port exposé et autorisé en entrée sur Public — se teste sur un état donné, sans toucher
/// au pare-feu de la machine.
/// </summary>
public interface IFirewallProvider
{
    FirewallState Read();
}
