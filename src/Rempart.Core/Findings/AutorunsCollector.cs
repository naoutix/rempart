using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// A finding collector enumerates whatever is present; a regular collector describes
/// fields known in advance. The difference lies in what is being looked for: a
/// configuration is read by its name, a persistence has to be discovered.
/// </summary>
public interface IFindingCollector
{
    string Name { get; }

    IReadOnlyList<Finding> Collect(ProviderSet providers);
}

/// <summary>
/// Programs launched at startup.
///
/// This is the first place to look on a suspicious machine, and the first one an
/// attacker uses: an entry dropped there survives a reboot without requiring any
/// particular privilege.
///
/// The judgement rests on the signature, not on the name or the path — both are
/// trivially imitated, and a binary named "OneDriveSetup.exe" in a user folder has
/// nothing of Microsoft.
/// </summary>
public sealed class AutorunsCollector : IFindingCollector
{
    private static readonly string[] RunKeys =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",

        // 32-bit view on a 64-bit system: a distinct location, often missed by tools
        // that only enumerate the native view.
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
                    findings.Add(Examine(
                        $"{key}\\{name}", command, providers.Signatures, TransientReason(key)));
                }
            }
        }

        foreach (var folder in StartupFolders(providers.Registry))
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
    /// Startup folders, machine then user. Their content runs at logon without any
    /// registry key mentioning it — an audit that only inspected the registry would
    /// miss them entirely.
    ///
    /// <para>
    /// The paths are read from the registry (<c>Shell Folders</c>) rather than computed
    /// via <c>Environment</c>: the user folder carries the account name, specific to the
    /// machine, and <c>Environment.GetFolderPath</c> would resolve it on the replay host —
    /// on Linux in CI, a POSIX path that no longer matches the captured key. Read from the
    /// registry, the value is captured then replayed identically, like everything else.
    /// </para>
    /// </summary>
    private static IEnumerable<string> StartupFolders(IRegistryProvider registry)
    {
        // Read via ListValues rather than ReadValue: on a snapshot taken before this
        // collection existed, ReadValue throws "unrecorded read" and would abort the
        // collector, whereas ListValues returns an empty list — the old fixture stays
        // replayable, it simply yields fewer findings.
        if (Value(registry,
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                "Common Startup") is { Length: > 0 } machine)
        {
            yield return machine;
        }

        if (Value(registry,
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                "Startup") is { Length: > 0 } user)
        {
            yield return user;
        }
    }

    private static string? Value(IRegistryProvider registry, string keyPath, string valueName) =>
        registry.ListValues(keyPath).TryGetValue(valueName, out var value) ? value.Text : null;

    /// <summary>
    /// <c>desktop.ini</c> describes the folder's appearance; it does not execute.
    /// Reporting it would add noise on every machine, which is the surest way to make
    /// people stop reading a report.
    ///
    /// The file name is split by hand on both Windows separators rather than through
    /// <c>Path.GetFileName</c>: on Linux, the latter does not recognise the backslash
    /// and would return the whole path, letting the <c>desktop.ini</c> of a Windows
    /// capture slip through on replay.
    /// </summary>
    private static bool IsIgnored(string path) =>
        FileName(path).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);

    private static string FileName(string path)
    {
        var separator = path.LastIndexOfAny(['\\', '/']);
        return separator >= 0 ? path[(separator + 1)..] : path;
    }

    /// <summary>
    /// A shortcut does not execute by itself: it points at something else. Judging it
    /// on its own signature would be wrong — its target is what matters, and resolving
    /// it requires reading the .lnk format. It is therefore enumerated without being
    /// judged, and the report says why rather than implying a verification took place.
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

    /// <summary>
    /// Why a <c>RunOnce</c> entry is expected to vanish on its own.
    ///
    /// Windows runs these at the next boot and deletes them. Two scans on either side of
    /// a restart therefore differ without anything having happened, and <c>rempart
    /// diff</c> must not present that as a change of posture. Decided here, where the
    /// mechanism is known, rather than by the diff reading source paths.
    /// </summary>
    private static string? TransientReason(string key) =>
        key.EndsWith(@"\RunOnce", StringComparison.OrdinalIgnoreCase)
            ? "Entrée RunOnce : Windows l'exécute au prochain démarrage puis la supprime."
            : null;

    private static Finding Examine(
        string source, string command, ISignatureProvider signatures, string? transient = null)
    {
        var path = ExtractExecutablePath(command);
        var judgement = SignatureLadder.Judge(path, signatures);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["commande"] = command,
        };

        if (transient is not null)
        {
            details[FindingDetails.Transient] = transient;
        }

        SignatureLadder.Describe(judgement.Signature, details);

        return new Finding(
            "autorun", source, path, judgement.Severity, judgement.Reasons, details);
    }

    /// <summary>
    /// Extracts the executable path from a command line.
    ///
    /// An unquoted path containing spaces is ambiguous:
    /// <c>C:\Program Files\App\a.exe</c> can be read as <c>C:\Program.exe</c>.
    /// This is the "unquoted service path" flaw, and it applies here as well.
    /// We keep the longest prefix that names an existing file.
    /// </summary>
    internal static string ExtractExecutablePath(string command)
    {
        var trimmed = command.Trim();

        if (trimmed.StartsWith('"'))
        {
            var closing = trimmed.IndexOf('"', 1);
            return closing > 0 ? trimmed[1..closing] : trimmed[1..];
        }

        // Without quotes, advance space by space until a file is found.
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
