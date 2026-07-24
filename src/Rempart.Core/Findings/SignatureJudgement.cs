using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// The verdict passed on an executable and the reasons behind it.
/// </summary>
public sealed record SignatureJudgement(
    FindingSeverity Severity,
    IReadOnlyList<string> Reasons,
    FileSignature Signature);

/// <summary>
/// The ladder shared by all persistence collectors.
///
/// Autoruns and scheduled tasks ask the same question — this program starts on its
/// own, what attests to its origin? — and must answer it the same way. Two separate
/// ladders would drift apart: the same missing signature would become suspicious here
/// and notable there, with nothing to justify it.
///
/// The judgement rests on the signature, not on the name or the path: both are
/// trivially imitated, and a binary named "OneDriveSetup.exe" in a user folder has
/// nothing of Microsoft.
/// </summary>
public static class SignatureLadder
{
    /// <summary>
    /// Locations a legitimate binary rarely launches from. An executable starting
    /// from a temporary folder or a user profile deserves a look — without being
    /// guilty for that alone, plenty of tools install there.
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

        // A binary under WindowsApps is deployed by MSIX: Windows only writes packages
        // there whose signature it has verified, and the file itself carries none at
        // the Authenticode level. "Unsigned" is therefore the rule there, not a signal —
        // marking it suspicious would wrongly accuse every Store application.
        if (signature.Status == SignatureStatus.Unsigned
            && path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase))
        {
            return new SignatureJudgement(FindingSeverity.Benign,
                ["Signé par son paquet MSIX, non au niveau fichier — la confiance vient "
                 + "du paquet, que Windows vérifie au déploiement."],
                signature);
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

            // Neither valid nor invalid: do not turn a gap into an accusation.
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

    /// <summary>Writes the signature into a finding's details, omitting empty fields.</summary>
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
