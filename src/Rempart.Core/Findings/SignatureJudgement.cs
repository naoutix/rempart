using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Le verdict porté sur un exécutable et les raisons qui le motivent.
/// </summary>
public sealed record SignatureJudgement(
    FindingSeverity Severity,
    IReadOnlyList<string> Reasons,
    FileSignature Signature);

/// <summary>
/// L'échelle commune à tous les collecteurs de persistance.
///
/// Démarrage automatique et tâches planifiées posent la même question — ce programme
/// se lance tout seul, qu'est-ce qui atteste de son origine ? — et doivent y répondre
/// pareil. Deux échelles séparées divergeraient : la même absence de signature
/// deviendrait suspecte ici et notable là, sans que rien ne le justifie.
///
/// Le jugement porte sur la signature, pas sur le nom ni le chemin : les deux
/// s'imitent trivialement, un binaire nommé « OneDriveSetup.exe » dans un dossier
/// utilisateur n'a rien de Microsoft.
/// </summary>
public static class SignatureLadder
{
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

    public static SignatureJudgement Judge(string path, ISignatureProvider signatures)
    {
        var signature = signatures.Verify(path);
        var reasons = new List<string>();

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

        return new SignatureJudgement(severity, reasons, signature);
    }

    /// <summary>Verse la signature dans les détails d'un constat, sans les champs vides.</summary>
    public static void Describe(FileSignature signature, IDictionary<string, string> details)
    {
        details["signature"] = signature.Status.ToString();

        if (signature.Publisher is { } publisher)
        {
            details["éditeur"] = publisher;
        }

        if (signature.Sha256 is { } hash)
        {
            details["sha256"] = hash;
        }
    }

    private static FindingSeverity Add(
        List<string> reasons, string reason, FindingSeverity severity)
    {
        reasons.Add(reason);
        return severity;
    }
}
