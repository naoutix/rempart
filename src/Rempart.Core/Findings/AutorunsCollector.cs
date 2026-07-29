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
            var read = providers.Registry.ListValues(key);

            // AccessDenied, and not "anything other than Found": four of these five keys hold
            // nothing on an ordinary machine and several are not there at all, so only a
            // refusal is a hole in what the scan saw. The same line the startup folders draw
            // below, one surface over — and the reason it can be drawn at all is that the
            // enumeration finally answers something other than an empty listing (REV-11).
            if (read.Status == ReadStatus.AccessDenied)
            {
                findings.Add(Unreadable(key,
                    "Clé de démarrage automatique illisible : accès refusé. Une entrée "
                    + "déposée là s'exécuterait au démarrage sans apparaître ici."));
            }

            // Added, not returned: a refused key must not cost the entries of the four that
            // answered — the rule ScheduledTaskRead.Partial settled one issue ago.
            foreach (var (name, value) in read.Values)
            {
                if (value.ToString() is { Length: > 0 } command)
                {
                    findings.Add(Examine(
                        $"{key}\\{name}", command, providers.Signatures, TransientReason(key)));
                }
            }
        }

        foreach (var key in ShellFolderKeys)
        {
            // The refusal that hides a refusal. Without a Shell Folders value no path is
            // produced, so the startup folders are never walked and the AccessDenied finding
            // below cannot fire either: the report loses the surface and the reason at once.
            if (providers.Registry.ListValues(key).Status == ReadStatus.AccessDenied)
            {
                findings.Add(Unreadable(key,
                    "Emplacement des dossiers de démarrage illisible : accès refusé. Leur "
                    + "contenu n'a donc pas été énuméré, et un programme déposé là "
                    + "s'exécuterait à l'ouverture de session sans apparaître ici."));
            }
        }

        foreach (var folder in StartupFolders(providers.Registry))
        {
            var read = providers.Files.ListFiles(folder);

            // AccessDenied, and not "anything other than Found" as the four sibling
            // collectors test: here a third state is a genuine answer. A startup folder that
            // is not on disk (NotFound) runs nothing, and most machines have one missing —
            // reporting it would put a Notable on nearly every scan, which is how a report
            // stops being read. An empty folder that WAS listed is the same: an answer.
            // Only a refusal is a hole in what the scan saw.
            if (read.Status == ReadStatus.AccessDenied)
            {
                // Added, not returned: the loop continues so a refused machine folder does
                // not cost the files of the user folder that answered. Same shape as the
                // partial port read, one level up — see DirectoryRead on why the shape is
                // here rather than in the read.
                findings.Add(Unreadable(folder,
                    read.Diagnostic ?? "Contenu du dossier de démarrage illisible. Un "
                    + "programme déposé là s'exécuterait à l'ouverture de session sans "
                    + "apparaître ici."));
            }

            foreach (var file in read.Files)
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
    /// Where the startup folder paths are kept, machine then user — the order
    /// <see cref="StartupFolders"/> reads them in, and the list the refusal loop walks, so a
    /// location added gains its « illisible » case without anyone remembering to write one.
    /// </summary>
    private static readonly string[] ShellFolderKeys =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    ];

    /// <summary>The value each of those keys holds the startup folder under.</summary>
    private static readonly string[] ShellFolderValues = ["Common Startup", "Startup"];

    /// <summary>
    /// A surface the scan could not read. Reported rather than skipped, and asked of
    /// <see cref="Finding.Refused"/> rather than spelled out here: the severity and the
    /// missing target were already its answer, and what the shared door adds is the marker
    /// that carries « on m'a refusé » as far as the exit code.
    /// </summary>
    private static Finding Unreadable(string source, string reason) =>
        Finding.Refused("autorun", source, [reason]);

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
        for (var i = 0; i < ShellFolderKeys.Length; i++)
        {
            if (Value(registry, ShellFolderKeys[i], ShellFolderValues[i])
                is { Length: > 0 } folder)
            {
                yield return folder;
            }
        }
    }

    // Read via ListValues rather than ReadValue: on a snapshot taken before this collection
    // existed, ReadValue throws "unrecorded read" and would abort the collector, whereas
    // ListValues degrades to NotFound — the old fixture stays replayable, it simply yields
    // fewer findings. That degradation still covers only the *absence*; the refusal it used
    // to be folded into is reported by the caller above.
    private static string? Value(IRegistryProvider registry, string keyPath, string valueName) =>
        registry.ListValues(keyPath).Values.TryGetValue(valueName, out var value)
            ? value.Text
            : null;

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

        // The second half of the same question. The ladder above answers "what attests to
        // the origin of this file", which is exact and, for an interpreter, empty: a Run
        // value launching the signed powershell.exe of the machine came out benign with no
        // reason at all, and the console, the HTML and the Markdown all print only what is
        // not benign — so the entry was not merely unjudged, it was invisible.
        var payload = InterpreterPayload.Inspect(path, ArgumentsOf(command, path));

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
            "autorun", source, path, payload.Over(judgement.Severity),
            [.. judgement.Reasons, .. payload.Reasons], details);
    }

    /// <summary>
    /// Everything the command line holds beyond the executable itself.
    ///
    /// <para>
    /// Taken back out of the original string rather than rebuilt from the split above:
    /// <see cref="ExtractExecutablePath"/> normalises what it returns — it drops the
    /// opening quote and rejoins on single spaces — and an argument list rebuilt from that
    /// would no longer be the one Windows will hand to the interpreter.
    /// </para>
    /// </summary>
    private static string ArgumentsOf(string command, string path)
    {
        var trimmed = command.Trim();
        var start = trimmed.IndexOf(path, StringComparison.OrdinalIgnoreCase);

        if (start < 0)
        {
            return string.Empty;
        }

        var rest = trimmed[(start + path.Length)..];

        // The closing quote of a quoted path belongs to the path, not to the arguments.
        return rest.StartsWith('"') ? rest[1..] : rest;
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
