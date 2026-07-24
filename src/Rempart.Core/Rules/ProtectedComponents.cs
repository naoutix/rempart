namespace Rempart.Core.Rules;

/// <summary>
/// Components no rule may target for remediation (ADR-001, D7).
///
/// The state of the art in Windows debloating shows five recurring failure modes; removing
/// these components causes four of them. The WebView2 runtime renders many native
/// applications and system surfaces — removing it breaks seemingly unrelated programs.
/// Without the Store and App Installer there is no reinstallation path. Without Windows
/// Update there are no more patches, which directly contradicts the goal.
///
/// The list is hardcoded, not kept in a YAML file, precisely so that editing a rules file
/// cannot bypass it. A test walks every shipped rule and fails if one of them touches
/// these components.
///
/// No effect in v1: no write provider exists before M9. The guarantee is put in place now
/// so that no rule gets written in the meantime assuming it is absent.
/// </summary>
public static class ProtectedComponents
{
    /// <summary>
    /// Fragments searched for in remediation paths, case-insensitively.
    /// </summary>
    public static readonly IReadOnlyList<string> Fragments =
    [
        // Rendering engine for many native applications and system surfaces.
        "microsoft-windows-webview",
        "microsoftedgewebview",
        "microsoft.microsoftedge",
        "msedgewebview",

        // Reinstallation path for components delivered through the Store.
        "microsoft.windowsstore",
        "microsoft.desktopappinstaller",
        "microsoft.storepurchaseapp",

        // Servicing: without it, no more security patches. Protecting the service alone
        // is not enough — the Windows Update configuration can be disabled just as well.
        @"currentversion\windowsupdate",
        @"policies\microsoft\windows\windowsupdate",
        @"currentcontrolset\services\wuauserv",
        @"currentcontrolset\services\bits",
        @"currentcontrolset\services\trustedinstaller",
        @"currentcontrolset\services\msiserver",

        // Baseline security: hardening that disables these is not hardening.
        @"currentcontrolset\services\windefend",
        @"currentcontrolset\services\mpssvc",
        @"currentcontrolset\services\securityhealthservice",

        // Boot and session: a mistake here makes the machine unusable.
        @"currentcontrolset\services\rpcss",
        @"currentcontrolset\services\dcomlaunch",
        @"currentcontrolset\services\lsm",
    ];

    public static bool IsProtected(string path) =>
        Fragments.Any(fragment => path.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Returns the rules whose remediation would target a protected component.
    /// Empty in v1 — no shipped rule carries a remediation target.
    /// </summary>
    public static IReadOnlyList<Rule> FindViolations(IEnumerable<Rule> rules) =>
        [.. rules.Where(rule => rule.Remediation is not null && IsProtected(rule.Check.Path))];
}
