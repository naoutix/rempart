using System.Security.Cryptography;
using System.Text;
using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Remplace les identifiants machine par des empreintes stables.
///
/// Actif par défaut à la capture : les fixtures finissent versionnées, et un instantané
/// brut porte hostname, numéro de série et propriétaire enregistré. Le hachage reste
/// stable, donc deux captures de la même machine restent comparables.
/// </summary>
public static class Anonymiser
{
    private const string Prefix = "anon:";

    /// <summary>Noms de valeurs dont le contenu identifie la machine ou son détenteur.</summary>
    private static readonly string[] SensitiveValueFragments =
    [
        "serial",
        "owner",
        "organization",
        "username",
        "uuid",
        "productid",
    ];

    public static MachineSnapshot Apply(MachineSnapshot snapshot)
    {
        foreach (var (key, read) in snapshot.Registry)
        {
            if (read.Value?.Text is not { Length: > 0 } text)
            {
                continue;
            }

            var valueName = key[(key.LastIndexOf("||", StringComparison.Ordinal) + 2)..];

            // Le nom de compte se glisse aussi dans des valeurs parfaitement anodines :
            // une entrée Run qui pointe vers %LOCALAPPDATA% s'enregistre en chemin
            // complet, donc avec le prénom de quelqu'un.
            var scrubbed = IsSensitive(valueName) ? Hash(text) : ScrubProfile(text);

            if (!string.Equals(scrubbed, text, StringComparison.Ordinal))
            {
                snapshot.Registry[key] = read with { Value = read.Value with { Text = scrubbed } };
            }
        }

        snapshot.Signatures = snapshot.Signatures
            .ToDictionary(entry => ScrubProfile(entry.Key), entry => entry.Value);

        // Les valeurs WMI portent des chemins : Win32_Service rend le chemin de chaque
        // service, et un service installé sous un profil y nomme un compte. L'anonymiseur
        // les ignorait, et ces chemins fuyaient donc dans les fixtures versionnées.
        snapshot.Wmi = snapshot.Wmi.ToDictionary(
            entry => entry.Key,
            entry => entry.Value with
            {
                Instances =
                [
                    .. entry.Value.Instances.Select(instance => new WmiInstance(
                        instance.Properties.ToDictionary(
                            property => property.Key,
                            property => ScrubProfile(property.Value),
                            StringComparer.OrdinalIgnoreCase))),
                ],
            });

        snapshot.Directories = snapshot.Directories.ToDictionary(
            entry => ScrubProfile(entry.Key),
            entry => entry.Value.Select(ScrubProfile).ToList());

        if (snapshot.SystemInfo is { } info)
        {
            snapshot.SystemInfo = info with { MachineName = Hash(info.MachineName) };
        }

        if (snapshot.ScheduledTasks is { } tasks && tasks.Tasks.Count > 0)
        {
            snapshot.ScheduledTasks = tasks with
            {
                Tasks =
                [
                    .. tasks.Tasks.Select(task => task with
                    {
                        Path = ScrubSegments(task.Path),
                        Name = ScrubSegments(task.Name),
                        Author = Depersonalise(task.Author),
                        UserId = Depersonalise(task.UserId),
                        Actions =
                        [
                            .. task.Actions.Select(action => action with
                            {
                                Path = ScrubProfile(action.Path),
                                Arguments = ScrubProfile(action.Arguments),
                            }),
                        ],
                    }),
                ],
            };
        }

        if (snapshot.Drivers is { Count: > 0 } drivers)
        {
            // Les chemins de pilotes sont des chemins systeme, mais un pilote tiers peut
            // se loger sous un profil utilisateur : on scrube par prudence, comme partout.
            snapshot.Drivers =
            [
                .. drivers.Select(d => d with { Path = ScrubProfile(d.Path) }),
            ];
        }

        if (snapshot.Processes is { Count: > 0 } processes)
        {
            // Chemin ET ligne de commande : un processus lance depuis un profil porte le
            // nom du compte dans les deux, et une ligne de commande peut en contenir bien
            // plus. Le nom de compte est haché ; le reste, qui dit quelle application
            // tourne, est conservé.
            snapshot.Processes =
            [
                .. processes.Select(p => p with
                {
                    Path = ScrubProfile(p.Path),
                    CommandLine = ScrubProfile(p.CommandLine),
                }),
            ];
        }

        snapshot.Anonymised = true;
        return snapshot;
    }

    /// <summary>
    /// Hache ce qui désigne une personne, laisse le reste lisible.
    ///
    /// Une tâche planifiée nomme son auteur et le compte sous lequel elle tourne. Les
    /// deux sont tantôt anodins — « Microsoft Corporation », <c>S-1-5-18</c> qui est le
    /// compte système — tantôt directement identifiants : la forme
    /// <c>MACHINE\utilisateur</c>, ou un SID de compte local.
    ///
    /// Tout hacher protégerait autant et coûterait la lisibilité des fixtures : on ne
    /// distinguerait plus une tâche du système d'une tâche d'utilisateur, ce qui est
    /// justement ce qu'on veut pouvoir juger. La distinction est donc explicite.
    /// </summary>
    /// <summary>
    /// Comptes de profil qui ne désignent personne : ils existent à l'identique sur
    /// toute installation de Windows.
    /// </summary>
    private static readonly string[] ImpersonalProfiles =
        ["public", "default", "default user", "all users"];

    /// <summary>
    /// Remplace le nom de compte dans un chemin de profil.
    ///
    /// <c>C:\Users\prénom\AppData\...</c> nomme quelqu'un. Ces chemins servent de clés
    /// dans l'instantané — signatures vérifiées, répertoires énumérés — et se
    /// retrouvent aussi dans les valeurs de registre <c>Run</c>.
    ///
    /// Seul le segment du compte est haché : le reste du chemin dit quelle application
    /// se lance au démarrage, et c'est exactement ce qu'une fixture doit conserver.
    /// </summary>
    internal static string ScrubProfile(string path)
    {
        const string Marker = @"\Users\";

        // Toutes les occurrences, pas seulement la première : une ligne de commande peut
        // porter plusieurs fois le même chemin de profil — l'entrée et la sortie, par
        // exemple — et n'en hacher qu'une laisserait le nom de compte lisible ailleurs.
        var index = path.IndexOf(Marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return path;
        }

        var builder = new StringBuilder(path.Length);
        var cursor = 0;

        while (index >= 0)
        {
            var start = index + Marker.Length;
            var end = path.IndexOf('\\', start);
            if (end < 0)
            {
                end = path.Length;
            }

            var account = path[start..end];
            builder.Append(path, cursor, start - cursor);

            builder.Append(
                account.Length == 0
                    || account.StartsWith(Prefix, StringComparison.Ordinal)
                    || ImpersonalProfiles.Contains(account, StringComparer.OrdinalIgnoreCase)
                    ? account
                    : Hash(account));

            cursor = end;
            index = path.IndexOf(Marker, end, StringComparison.OrdinalIgnoreCase);
        }

        builder.Append(path, cursor, path.Length - cursor);
        return builder.ToString();
    }

    /// <summary>
    /// Remplace les SID de compte enfouis dans un chemin, sans toucher au reste.
    ///
    /// Certaines applications créent un dossier de tâches par utilisateur et le
    /// nomment par son SID : <c>\SoftLanding\S-1-5-21-…-1002\…</c>. Hacher le chemin
    /// entier rendrait la fixture illisible — on ne saurait plus quelle application a
    /// posé quoi — alors que seul le segment identifiant pose problème.
    /// </summary>
    private static string ScrubSegments(string path) =>
        path.Contains("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
            ? string.Join('\\', path.Split('\\').Select(segment =>
                segment.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                    ? Hash(segment)
                    : segment))
            : path;

    private static string? Depersonalise(string? value) => value switch
    {
        null or "" => value,

        // S-1-5-21 précède les SID des comptes créés sur la machine ou le domaine :
        // derrière chacun il y a quelqu'un. Les autorités bien connues — S-1-5-18
        // pour le système, S-1-5-19 et S-1-5-20 pour les services — ne désignent
        // personne et restent lisibles.
        _ when value.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) => Hash(value),

        // Forme DOMAINE\utilisateur : porte à la fois le nom de la machine et celui du
        // compte.
        _ when value.Contains('\\') => Hash(value),

        _ => value,
    };

    private static bool IsSensitive(string valueName) =>
        SensitiveValueFragments.Any(fragment =>
            valueName.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    /// <summary>Empreinte tronquée : suffisante pour comparer, insuffisante pour identifier.</summary>
    public static string Hash(string input)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Prefix + Convert.ToHexStringLower(digest)[..12];
    }
}
