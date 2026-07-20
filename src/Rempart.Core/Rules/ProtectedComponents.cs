namespace Rempart.Core.Rules;

/// <summary>
/// Composants qu'aucune règle ne peut cibler pour remédiation (ADR-001, D7).
///
/// L'état de l'art du dé-bloatware Windows recense cinq modes d'échec récurrents ; la
/// suppression de ces composants en cause quatre. Le runtime WebView2 fait le rendu de
/// nombreuses applications natives et surfaces système — le retirer casse des programmes
/// sans rapport apparent. Sans le Store ni App Installer, plus de chemin de réinstallation.
/// Sans Windows Update, plus de correctifs, ce qui contredit frontalement l'objectif.
///
/// La liste est en dur, et non dans un YAML, précisément pour qu'une modification de
/// fichier de règles ne puisse pas la contourner. Un test parcourt toutes les règles
/// livrées et échoue si l'une d'elles y touche.
///
/// Sans effet en v1 : aucun provider en écriture n'existe avant M9. La garantie est
/// posée maintenant pour qu'aucune règle ne s'écrive entre-temps en la supposant absente.
/// </summary>
public static class ProtectedComponents
{
    /// <summary>
    /// Fragments recherchés dans les chemins de remédiation, en insensible à la casse.
    /// </summary>
    public static readonly IReadOnlyList<string> Fragments =
    [
        // Moteur de rendu de nombreuses applications natives et surfaces système.
        "microsoft-windows-webview",
        "microsoftedgewebview",
        "microsoft.microsoftedge",
        "msedgewebview",

        // Chemin de réinstallation des composants livrés par le Store.
        "microsoft.windowsstore",
        "microsoft.desktopappinstaller",
        "microsoft.storepurchaseapp",

        // Servicing : sans lui, plus de correctifs de sécurité. Le service ne suffit
        // pas — la configuration de Windows Update est tout aussi désactivable.
        @"currentversion\windowsupdate",
        @"policies\microsoft\windows\windowsupdate",
        @"currentcontrolset\services\wuauserv",
        @"currentcontrolset\services\bits",
        @"currentcontrolset\services\trustedinstaller",
        @"currentcontrolset\services\msiserver",

        // Sécurité de base : un durcissement qui les désactive n'en est pas un.
        @"currentcontrolset\services\windefend",
        @"currentcontrolset\services\mpssvc",
        @"currentcontrolset\services\securityhealthservice",

        // Amorçage et session : une erreur ici rend la machine inutilisable.
        @"currentcontrolset\services\rpcss",
        @"currentcontrolset\services\dcomlaunch",
        @"currentcontrolset\services\lsm",
    ];

    public static bool IsProtected(string path) =>
        Fragments.Any(fragment => path.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Retourne les règles dont la remédiation viserait un composant protégé.
    /// Vide en v1 — aucune règle livrée ne porte de cible de remédiation.
    /// </summary>
    public static IReadOnlyList<Rule> FindViolations(IEnumerable<Rule> rules) =>
        [.. rules.Where(rule => rule.Remediation is not null && IsProtected(rule.Check.Path))];
}
