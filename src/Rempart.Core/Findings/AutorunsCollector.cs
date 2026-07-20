using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Un collecteur de constats énumère ce qui est présent ; un collecteur classique
/// décrit des champs connus d'avance. La différence tient à ce qu'on cherche : une
/// configuration se lit par son nom, une persistance se découvre.
/// </summary>
public interface IFindingCollector
{
    string Name { get; }

    IReadOnlyList<Finding> Collect(ProviderSet providers);
}

/// <summary>
/// Programmes lancés au démarrage.
///
/// C'est le premier endroit qu'on regarde sur une machine suspecte, et le premier
/// qu'un attaquant utilise : y déposer une entrée survit au redémarrage sans exiger
/// de droits particuliers.
///
/// Le jugement porte sur la signature, pas sur le nom ni le chemin — les deux
/// s'imitent trivialement, un binaire nommé « OneDriveSetup.exe » dans un dossier
/// utilisateur n'a rien de Microsoft.
/// </summary>
public sealed class AutorunsCollector : IFindingCollector
{
    private static readonly string[] RunKeys =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",

        // Vue 32 bits sur un système 64 bits : emplacement distinct, souvent oublié
        // des outils qui n'énumèrent que la vue native.
        @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ];

    public string Name => "autoruns";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var key in RunKeys)
        {
            foreach (var (name, value) in providers.Registry.ListValues(key))
            {
                if (value.ToString() is { Length: > 0 } command)
                {
                    findings.Add(Examine($"{key}\\{name}", command, providers.Signatures));
                }
            }
        }

        foreach (var folder in StartupFolders())
        {
            foreach (var file in providers.Files.ListFiles(folder))
            {
                if (IsIgnored(file))
                {
                    continue;
                }

                findings.Add(ExamineStartupFile(folder, file, providers.Signatures));
            }
        }

        return findings;
    }

    /// <summary>
    /// Dossiers de démarrage, machine puis utilisateur. Leur contenu s'exécute à
    /// l'ouverture de session sans qu'aucune clé de registre ne le mentionne — un
    /// audit qui n'inspecterait que le registre les manquerait entièrement.
    /// </summary>
    private static IEnumerable<string> StartupFolders()
    {
        yield return Environment.ExpandEnvironmentVariables(
            @"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp");

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrEmpty(appData))
        {
            yield return Path.Combine(appData, @"Microsoft\Windows\Start Menu\Programs\Startup");
        }
    }

    /// <summary>
    /// <c>desktop.ini</c> décrit l'apparence du dossier ; il ne s'exécute pas. Le
    /// signaler ajouterait du bruit sur toute machine, ce qui est la manière la plus
    /// sûre de faire cesser la lecture d'un rapport.
    /// </summary>
    private static bool IsIgnored(string path) =>
        Path.GetFileName(path).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Un raccourci ne s'exécute pas lui-même : il désigne autre chose. Le juger sur
    /// sa propre signature serait faux — c'est sa cible qui compte, et la résoudre
    /// demande de lire le format .lnk. Il est donc énuméré sans être jugé, et le
    /// rapport dit pourquoi plutôt que de laisser croire à une vérification.
    /// </summary>
    private static Finding ExamineStartupFile(
        string folder, string path, ISignatureProvider signatures)
    {
        if (path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return new Finding("autorun", folder, path, FindingSeverity.Benign, [],
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["type"] = "raccourci",
                    ["note"] = "Cible non résolue : le format .lnk n'est pas encore lu, "
                               + "la signature porte donc sur le raccourci et non sur ce "
                               + "qu'il lance.",
                });
        }

        return Examine(folder, path, signatures);
    }

    private static Finding Examine(string source, string command, ISignatureProvider signatures)
    {
        var path = ExtractExecutablePath(command);
        var judgement = SignatureLadder.Judge(path, signatures);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["commande"] = command,
        };

        SignatureLadder.Describe(judgement.Signature, details);

        return new Finding(
            "autorun", source, path, judgement.Severity, judgement.Reasons, details);
    }

    /// <summary>
    /// Extrait le chemin de l'exécutable d'une ligne de commande.
    ///
    /// Un chemin non entouré de guillemets et contenant des espaces est ambigu :
    /// <c>C:\Program Files\App\a.exe</c> peut se lire comme <c>C:\Program.exe</c>.
    /// C'est la faille du « chemin de service non-quoté », et elle vaut ici aussi.
    /// On retient le préfixe le plus long qui désigne un fichier existant.
    /// </summary>
    internal static string ExtractExecutablePath(string command)
    {
        var trimmed = command.Trim();

        if (trimmed.StartsWith('"'))
        {
            var closing = trimmed.IndexOf('"', 1);
            return closing > 0 ? trimmed[1..closing] : trimmed[1..];
        }

        // Sans guillemets, on avance espace par espace jusqu'à trouver un fichier.
        var parts = trimmed.Split(' ');
        for (var take = parts.Length; take >= 1; take--)
        {
            var candidate = string.Join(' ', parts[..take]);
            if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        return parts[0];
    }
}
