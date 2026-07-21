using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Services dont le chemin d'exécutable n'est pas entre guillemets et contient un espace.
///
/// <para>
/// Quand un service déclare <c>C:\Program Files\Éditeur\svc.exe</c> sans guillemets,
/// Windows essaie d'abord <c>C:\Program.exe</c>, puis <c>C:\Program Files\Éditeur.exe</c>,
/// avant le vrai fichier. Un tiers qui peut écrire à l'un de ces emplacements
/// intermédiaires y dépose son binaire, qui s'exécute avec le compte du service —
/// souvent <c>SYSTEM</c>. C'est une élévation de privilèges classique, et corriger
/// tient à ajouter des guillemets.
/// </para>
///
/// <para>
/// Le constat est <see cref="FindingSeverity.Notable"/>, pas suspect : l'exploitabilité
/// dépend de la possibilité d'écrire dans un dossier intermédiaire, que ce collecteur ne
/// vérifie pas encore. Il signale la faiblesse — un durcissement recommandé — sans
/// affirmer une exploitation qu'il n'a pas établie.
/// </para>
/// </summary>
public sealed class UnquotedServicePathCollector : IFindingCollector
{
    private const string Namespace = @"root\CIMV2";

    public string Name => "unquoted-service-path";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var read = providers.Wmi.Query(Namespace, "Win32_Service", ["Name", "PathName"]);

        if (read.Status == ReadStatus.AccessDenied)
        {
            return
            [
                new Finding("unquoted-service-path", "Win32_Service", "—",
                    FindingSeverity.Notable,
                    [read.Diagnostic ?? "Énumération des services refusée. Relancer en " +
                        "administrateur : un chemin non quoté resterait invisible."],
                    new Dictionary<string, string>()),
            ];
        }

        var findings = new List<Finding>();

        foreach (var instance in read.Instances)
        {
            var pathName = instance.Find("PathName");
            if (pathName is null || !IsUnquotedWithSpace(pathName))
            {
                continue;
            }

            var name = instance.Find("Name") ?? "?";

            findings.Add(new Finding(
                "unquoted-service-path", name, pathName, FindingSeverity.Notable,
                ["Chemin d'exécutable non quoté contenant un espace. Windows résout les "
                 + "préfixes avant le vrai fichier ; un tiers qui peut écrire à un "
                 + "emplacement intermédiaire s'exécute avec le compte du service. "
                 + "Correction : entourer le chemin de guillemets."],
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["chemin"] = pathName,
                }));
        }

        return findings;
    }

    /// <summary>
    /// Vrai si le chemin de l'exécutable — la partie avant les arguments — n'est pas
    /// entre guillemets et contient un espace.
    ///
    /// <para>
    /// Le chemin est délimité par le premier <c>.exe</c> : ce qui suit sont des arguments,
    /// et un espace dans les arguments ne rend pas le service vulnérable. Un chemin déjà
    /// entre guillemets, ou sans exécutable <c>.exe</c> (pilote, forme inhabituelle), ne
    /// l'est pas non plus.
    /// </para>
    /// </summary>
    internal static bool IsUnquotedWithSpace(string pathName)
    {
        var trimmed = pathName.Trim();

        if (trimmed.Length == 0 || trimmed[0] == '"')
        {
            return false;
        }

        var exe = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe < 0)
        {
            return false;
        }

        return trimmed[..(exe + 4)].Contains(' ');
    }
}
