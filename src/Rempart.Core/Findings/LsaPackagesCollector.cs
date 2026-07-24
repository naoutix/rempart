using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Packages loaded by the Local Security Authority (LSA).
///
/// <para>
/// LSA loads DLLs named in the registry: authentication providers, security packages
/// (SSP), password notification packages. A DLL added to these lists executes inside
/// the process that handles credentials — the technique of persistent credential theft
/// (mimikatz's <c>mimilib</c> registers there). No consumer-grade tool looks there.
/// </para>
///
/// <para>
/// On a healthy machine, these packages are all signed by Microsoft. The signal is
/// therefore an unsigned DLL, or one whose signature does not verify — judged on the
/// same scale as everything else (<see cref="SignatureLadder"/>). A legitimately
/// signed third-party package (smart card, for example) stays benign: the missing
/// signature is the alert, not the mere presence.
/// </para>
/// </summary>
public sealed class LsaPackagesCollector : IFindingCollector
{
    private const string Lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

    // Newer Windows builds moved the security packages under this subkey: both
    // locations are read, otherwise the surface would be missed on recent builds.
    private const string LsaOsConfig = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig";

    private static readonly (string Key, string Value)[] Sources =
    [
        (Lsa, "Authentication Packages"),
        (Lsa, "Notification Packages"),
        (Lsa, "Security Packages"),
        (LsaOsConfig, "Security Packages"),
    ];

    public string Name => "lsa-packages";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (key, value) in Sources)
        {
            var read = providers.Registry.ReadValue(key, value);

            if (read.Status == ReadStatus.AccessDenied)
            {
                // Report the failure: an unreadable list is not an empty list, and it
                // is exactly where a malicious package would sit.
                findings.Add(new Finding("lsa-package", $"Lsa\\{value}", "—",
                    FindingSeverity.Notable,
                    ["Liste refusée à la lecture. Relancer en administrateur : un paquet " +
                     "LSA ajouté resterait invisible."],
                    new Dictionary<string, string>()));
                continue;
            }

            if (read.Value?.Text is not { Length: > 0 } text)
            {
                continue;
            }

            // The provider returns REG_MULTI_SZ joined with newlines; some packages
            // can also appear separated by spaces.
            foreach (var raw in text.Split(['\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // Windows records an empty list as a literal « "" » value: once the
                // quotes are stripped, nothing remains. That is not a package, and
                // resolving it to « "".dll » used to surface an invented not-found.
                var package = raw.Trim('"');
                if (package.Length == 0 || !seen.Add(package))
                {
                    // Empty-list marker, or a package already judged at another location.
                    continue;
                }

                var path = Resolve(package);
                var judgement = SignatureLadder.Judge(path, providers.Signatures);

                var details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["paquet"] = package,
                    ["liste"] = value,
                };
                SignatureLadder.Describe(judgement.Signature, details);

                findings.Add(new Finding(
                    "lsa-package", $"Lsa\\{value}", path,
                    judgement.Severity, judgement.Reasons, details));
            }
        }

        return findings;
    }

    /// <summary>
    /// An LSA package name is a System32 DLL, with no path and not always an extension.
    /// Resolved hardcoded — <c>C:\Windows\System32\&lt;name&gt;.dll</c> — without touching
    /// the disk or <c>System.IO.Path</c>, so that capture and replay produce the same
    /// path whatever the machine.
    /// </summary>
    private static string Resolve(string package)
    {
        if (package.Contains('\\') || package.Contains('/'))
        {
            return package;
        }

        var name = package.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? package
            : package + ".dll";

        return @"C:\Windows\System32\" + name;
    }
}
