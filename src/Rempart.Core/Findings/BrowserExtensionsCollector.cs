using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Browser extensions, judged on provenance first and permissions second.
///
/// <para>
/// Provenance decides the tier: a sideloaded extension (external pref or registry,
/// unpacked, unsigned) is the classic malicious vector, whatever it declares. On
/// permissions alone a store install never rises above Notable — a legitimate
/// password manager combines <c>&lt;all_urls&gt;</c> with <c>nativeMessaging</c>, and
/// flagging it Suspicious on half the machines would get the report ignored.
/// </para>
/// </summary>
public sealed class BrowserExtensionsCollector : IFindingCollector
{
    private static readonly string[] StrongPermissions = ["debugger", "nativeMessaging", "proxy"];

    public string Name => "browser-extension";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var extension in providers.BrowserExtensions.Read())
        {
            findings.Add(Judge(extension));
        }

        return findings;
    }

    private static Finding Judge(BrowserExtension extension)
    {
        var (severity, reasons) = Assess(extension);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["navigateur"] = extension.Browser,
            ["profil"] = extension.Profile,
            ["id"] = extension.Id,
            ["version"] = extension.Version,
            ["permissions"] = string.Join(", ", extension.Permissions),
            ["accès"] = string.Join(", ", extension.HostAccess),
            // Disabled does not soften the verdict — one click re-enables it — but
            // the state belongs in the report.
            ["état"] = extension.Enabled ? "activée" : "désactivée",
            ["magasin"] = extension.FromStore ? "oui" : "non",
        };

        return new Finding(
            "browser-extension",
            $"{extension.Browser}/{extension.Profile}",
            extension.Name,
            severity,
            reasons,
            details);
    }

    private static (FindingSeverity, IReadOnlyList<string>) Assess(BrowserExtension extension)
    {
        if (!extension.FromStore)
        {
            return (FindingSeverity.Suspicious,
                ["Installée hors du magasin d'extensions (sideload) — le vecteur "
                 + "classique d'extension malveillante."]);
        }

        var reasons = new List<string>();

        if (extension.HostAccess.Any(IsBroadHost))
        {
            reasons.Add(
                "Accès à toutes les pages web : peut lire et modifier tout ce qui s'affiche.");
        }

        var strong = extension.Permissions
            .Where(p => StrongPermissions.Contains(p, StringComparer.OrdinalIgnoreCase))
            .ToList();

        if (strong.Count > 0)
        {
            reasons.Add($"Permission sensible : {string.Join(", ", strong)}.");
        }

        return reasons.Count > 0
            ? (FindingSeverity.Notable, reasons)
            : (FindingSeverity.Benign, []);
    }

    private static bool IsBroadHost(string pattern) =>
        pattern is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*" or "file:///*";
}
