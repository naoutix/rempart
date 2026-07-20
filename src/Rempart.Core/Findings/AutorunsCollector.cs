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

    /// <summary>
    /// Emplacements d'où un binaire légitime se lance rarement. Un exécutable qui
    /// démarre depuis un dossier temporaire ou un profil utilisateur mérite un
    /// regard — sans être coupable pour autant, beaucoup d'outils s'y installent.
    /// </summary>
    private static readonly string[] UnusualLocations =
    [
        @"\appdata\local\temp\",
        @"\windows\temp\",
        @"\downloads\",
        @"\public\",
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

        return findings;
    }

    private static Finding Examine(string source, string command, ISignatureProvider signatures)
    {
        var path = ExtractExecutablePath(command);
        var signature = signatures.Verify(path);

        var reasons = new List<string>();
        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["commande"] = command,
            ["signature"] = signature.Status.ToString(),
        };

        if (signature.Publisher is { } publisher)
        {
            details["éditeur"] = publisher;
        }

        if (signature.Sha256 is { } hash)
        {
            details["sha256"] = hash;
        }

        var severity = signature.Status switch
        {
            SignatureStatus.Valid => FindingSeverity.Benign,

            SignatureStatus.Unsigned => Add(reasons,
                "Binaire non signé : rien n'atteste de son origine ni de son intégrité.",
                FindingSeverity.Suspicious),

            SignatureStatus.Invalid => Add(reasons,
                "Signature présente mais invalide — expirée, révoquée, ou fichier altéré.",
                FindingSeverity.Suspicious),

            SignatureStatus.FileNotFound => Add(reasons,
                "Le fichier visé n'existe pas : reste d'une désinstallation, ou emplacement " +
                "qu'un tiers pourrait occuper pour être lancé au démarrage.",
                FindingSeverity.Notable),

            // Ni valide ni invalide : ne pas transformer une lacune en accusation.
            _ => Add(reasons,
                "Signature non vérifiable. Ce n'est pas un défaut du binaire.",
                FindingSeverity.Notable),
        };

        if (UnusualLocations.Any(l => path.Contains(l, StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add("Lancé depuis un emplacement inhabituel pour un programme installé.");
            severity = severity == FindingSeverity.Benign ? FindingSeverity.Notable : severity;
        }

        return new Finding("autorun", source, path, severity, reasons, details);
    }

    private static FindingSeverity Add(
        List<string> reasons, string reason, FindingSeverity severity)
    {
        reasons.Add(reason);
        return severity;
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
