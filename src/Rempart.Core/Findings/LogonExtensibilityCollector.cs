using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Extension points loaded at logon or injected into every process.
///
/// <para>
/// Neither <c>Run</c> keys nor tasks: these locations execute code without appearing
/// in the surfaces a consumer-grade tool inspects. Each has a known default value —
/// <c>userinit.exe</c>, <c>explorer.exe</c>, an empty list — and the signal is the
/// deviation from that default, or a referenced binary that is not signed.
/// </para>
///
/// <para>
/// Three locations, all under <c>HKLM</c>, readable without elevation:
/// </para>
/// <list type="bullet">
///   <item><c>Winlogon\Userinit</c> — programs launched right after logon.</item>
///   <item><c>Winlogon\Shell</c> — the graphical shell, <c>explorer.exe</c> by default.</item>
///   <item><c>AppInit_DLLs</c> — DLLs loaded into every GUI process. Empty by default,
///     and its mere presence deserves review: it is a universal injection point.</item>
/// </list>
/// </summary>
public sealed class LogonExtensibilityCollector : IFindingCollector
{
    private const string Winlogon =
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static readonly string[] WindowsKeys =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ];

    public string Name => "logon-extension";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        CollectWinlogon(providers, findings, "Userinit", "userinit.exe");
        CollectWinlogon(providers, findings, "Shell", "explorer.exe");
        CollectAppInit(providers, findings);

        return findings;
    }

    /// <summary>
    /// A Winlogon value can list several executables separated by commas —
    /// <c>Userinit</c> has a trailing comma in its default value. Each is judged; an
    /// entry that is not the expected program for the location is reported even when
    /// signed, because the addition matters, not only the origin.
    /// </summary>
    private static void CollectWinlogon(
        ProviderSet providers, List<Finding> findings, string valueName, string expected)
    {
        var read = providers.Registry.ReadValue(Winlogon, valueName);
        if (read.Status != ReadStatus.Found || read.Value?.Text is not { Length: > 0 } text)
        {
            return;
        }

        foreach (var entry in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var path = ExtractExecutable(entry);
            if (path.Length == 0)
            {
                continue;
            }

            var expectedHere = string.Equals(
                FileName(path), expected, StringComparison.OrdinalIgnoreCase);

            var finding = Judge(providers, $"Winlogon\\{valueName}", path, providers.Signatures);

            findings.Add(expectedHere
                ? finding
                : Escalate(finding, FindingSeverity.Notable,
                    $"Entrée inattendue dans {valueName} : « {expected} » est le programme " +
                    "par défaut à cet emplacement, celui-ci s'y ajoute."));
        }
    }

    /// <summary>
    /// <c>AppInit_DLLs</c> injects its DLLs into every GUI process. On a modern
    /// machine the value is empty; a DLL present there is notable whatever its
    /// signature — the mechanism itself is an injection lever, largely abandoned
    /// outside legacy software.
    /// </summary>
    private static void CollectAppInit(ProviderSet providers, List<Finding> findings)
    {
        foreach (var key in WindowsKeys)
        {
            var read = providers.Registry.ReadValue(key, "AppInit_DLLs");
            if (read.Status != ReadStatus.Found || read.Value?.Text is not { Length: > 0 } text)
            {
                continue;
            }

            foreach (var entry in text.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var finding = Judge(providers, "AppInit_DLLs", entry, providers.Signatures);
                findings.Add(Escalate(finding, FindingSeverity.Notable,
                    "DLL injectée dans chaque processus graphique via AppInit_DLLs — un "
                    + "point d'injection universel, inhabituel sur une machine moderne."));
            }
        }
    }

    private static Finding Judge(
        ProviderSet providers, string source, string reference, ISignatureProvider signatures)
    {
        var path = Resolve(reference);
        var judgement = SignatureLadder.Judge(path, signatures);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["référence"] = reference,
        };
        SignatureLadder.Describe(judgement.Signature, details);

        return new Finding(
            "logon-extension", source, path, judgement.Severity, judgement.Reasons, details);
    }

    /// <summary>
    /// Raises a finding to a severity floor and adds a reason, without ever lowering
    /// it: a binary already suspicious because of its signature stays suspicious.
    /// </summary>
    private static Finding Escalate(Finding finding, FindingSeverity floor, string reason) =>
        finding with
        {
            Severity = finding.Severity < floor ? floor : finding.Severity,
            Reasons = [reason, .. finding.Reasons],
        };

    /// <summary>
    /// File name of a path, splitting on both separators by hand.
    /// <c>Path.GetFileName</c> uses the host's separator: on Linux it does not
    /// recognize the <c>\</c> of a Windows path and returns the whole path — which
    /// made the CI replay diverge from the golden captured on Windows.
    /// </summary>
    private static string FileName(string path)
    {
        var separator = path.LastIndexOfAny(['\\', '/']);
        return separator >= 0 ? path[(separator + 1)..] : path;
    }

    /// <summary>Strips quotes and keeps only the executable path of an entry.</summary>
    private static string ExtractExecutable(string entry)
    {
        var trimmed = entry.Trim().Trim('"');
        var exe = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe >= 0 ? trimmed[..(exe + 4)] : trimmed;
    }

    /// <summary>
    /// Resolves a bare name to its canonical Windows location. An already complete
    /// path is returned as-is.
    ///
    /// <para>
    /// <c>explorer.exe</c> lives in the Windows folder, not System32: assuming
    /// System32 made the shell come out as "file not found". But resolution cannot
    /// <b>query the file system</b> — <c>File.Exists</c> and the actual Windows folder
    /// depend on the host, and a snapshot captured on Windows is replayed in CI on
    /// Linux, where the same value would resolve differently. This was exactly the
    /// separator trap hit with the drivers.
    /// </para>
    ///
    /// <para>
    /// The convention is therefore hard-coded — <c>explorer.exe</c> in the Windows
    /// folder, everything else in System32 — with no disk access, so capture and
    /// replay produce the same path whatever machine runs them.
    /// </para>
    /// </summary>
    private static string Resolve(string reference)
    {
        var trimmed = reference.Trim().Trim('"');

        if (trimmed.Length == 0 || trimmed.Contains('\\') || trimmed.Contains('/'))
        {
            return trimmed;
        }

        return string.Equals(trimmed, "explorer.exe", StringComparison.OrdinalIgnoreCase)
            ? @"C:\Windows\" + trimmed
            : @"C:\Windows\System32\" + trimmed;
    }
}
