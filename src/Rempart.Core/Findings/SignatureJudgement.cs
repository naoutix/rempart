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

        // A binary in a package store is deployed by MSIX: Windows only writes packages
        // there whose signature it has verified, and the file itself carries none at
        // the Authenticode level. "Unsigned" is therefore the rule there, not a signal —
        // marking it suspicious would wrongly accuse every Store application.
        if (signature.Status == SignatureStatus.Unsigned && IsInPackageStore(path))
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

    /// <summary>
    /// Directories that hold a package store when it is not at the root of its volume.
    /// A volume declares its own store path — <c>Get-AppxVolume</c> reports one per
    /// volume — so a machine with Store applications installed to another drive carries
    /// a second store at that drive's root, hence both shapes below rather than
    /// <c>%ProgramFiles%</c> alone.
    /// </summary>
    private static readonly string[] StoreParents = ["Program Files", "Program Files (x86)"];

    /// <summary>
    /// Whether the path sits in a package store Windows itself deploys to.
    ///
    /// <para>
    /// The segment has to be <em>anchored</em>, not merely present somewhere. This was a
    /// substring search, and a directory named <c>WindowsApps</c> created inside a profile
    /// — which needs no privilege — made an unsigned binary benign on all eight collectors
    /// that share this ladder, and skipped the unusual-location escalation on the way out.
    /// </para>
    ///
    /// <para>
    /// Both separators are split by hand. <c>Rempart.Core</c> targets <c>net10.0</c> and its
    /// tests run on the Linux job, where <c>System.IO.Path</c> does not treat <c>\</c> as a
    /// separator at all: a replayed fixture would see every Windows path as one segment.
    /// </para>
    ///
    /// <para>
    /// What this still accepts, said rather than hidden: a drive root the auditing user can
    /// write to — removable media, in practice — allows the same trick at
    /// <c>E:\WindowsApps\</c>. Closing that needs to know which volumes are package stores,
    /// a read no collector on this ladder has.
    /// </para>
    /// </summary>
    private static bool IsInPackageStore(string path)
    {
        var segments = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);

        var index = Array.FindIndex(segments,
            s => s.Equals("WindowsApps", StringComparison.OrdinalIgnoreCase));

        // Index 0 means a relative path: there is no drive to anchor it to.
        if (index < 1 || !IsDriveLetter(segments[0]))
        {
            return false;
        }

        return index == 1
            || (index == 2 && StoreParents.Contains(segments[1], StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsDriveLetter(string segment) =>
        segment.Length == 2 && segment[1] == ':' && char.IsAsciiLetter(segment[0]);

    private static FindingSeverity Add(
        List<string> reasons, string reason, FindingSeverity severity)
    {
        reasons.Add(reason);
        return severity;
    }
}
