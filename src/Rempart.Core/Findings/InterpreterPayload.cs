using System.Text;

namespace Rempart.Core.Findings;

/// <summary>
/// What a command line asks of the program it launches, and the reasons that come of it.
/// </summary>
public sealed record PayloadJudgement(FindingSeverity Severity, IReadOnlyList<string> Reasons)
{
    /// <summary>Nothing in the command line asks for a look.</summary>
    public static readonly PayloadJudgement Silent = new(FindingSeverity.Benign, []);

    /// <summary>
    /// Folds this judgement into the one the signature produced, keeping the higher of the
    /// two. Written here rather than at each call site: two collectors deciding on their
    /// own how the two axes combine is how the same command line comes out notable in one
    /// report and benign in the next — the drift <see cref="SignatureLadder"/> exists to
    /// prevent on its own axis.
    /// </summary>
    public FindingSeverity Over(FindingSeverity signature) =>
        Severity > signature ? Severity : signature;
}

/// <summary>
/// The command line of a script host, judged where the host itself cannot be.
///
/// <para>
/// Persistence collectors judged the executable and stopped there. That answer is exact
/// for a program and empty for an interpreter: <c>powershell.exe</c> is validly signed by
/// Microsoft on every machine in the world, so a <c>Run</c> entry launching it with
/// <c>-enc &lt;base64&gt;</c> came out benign carrying no reason at all — and the console,
/// the HTML and the Markdown print only what is not benign. The entry was not merely
/// unjudged, it was invisible. The signature was never wrong; it simply says nothing about
/// what runs.
/// </para>
///
/// <para>
/// <b>This is coverage by enumeration, and it is worth saying so.</b> Nothing in a captured
/// snapshot states that a binary interprets its arguments — that fact lives in the program,
/// not on the machine — so the hosts below are a list, kept short and justified entry by
/// entry, and persistence through a host absent from it is not covered. What could be built
/// rather than listed, was: the abbreviations come from PowerShell's own prefix rule instead
/// of a table of spellings, matching is done on argument tokens and path segments rather
/// than on substrings, and the absence of false positives is held by a guard that replays
/// every versioned capture rather than by a second list written by the same hand.
/// </para>
///
/// <para>
/// The verdict stops at <see cref="FindingSeverity.Notable"/> and never climbs to
/// <see cref="FindingSeverity.Suspicious"/> on its own. An administrator does hide a
/// maintenance window and a legitimate installer does bypass an execution policy; what is
/// established here is that the reader has to see the line, not that the line is malicious.
/// </para>
/// </summary>
public static class InterpreterPayload
{
    /// <summary>
    /// The hosts whose entire behaviour is dictated by an argument, so that judging the file
    /// judges nothing.
    ///
    /// <para>
    /// <c>powershell</c> and <c>pwsh</c> run a script, a command or a base64 blob;
    /// <c>cmd</c> runs whatever follows <c>/c</c>; <c>wscript</c> and <c>cscript</c> run the
    /// script named after them; <c>mshta</c> runs an HTML application it will fetch over the
    /// network if told to; <c>rundll32</c> calls an exported entry point of a DLL the caller
    /// chooses; <c>regsvr32</c> registers a scriptlet it can likewise fetch. Every one of
    /// them is validly signed by Microsoft on the machine it runs on, which is exactly why
    /// the signature ladder has nothing to say about any of them.
    /// </para>
    ///
    /// <para>
    /// Where the list stops is deliberate. <c>certutil</c>, <c>bitsadmin</c> and
    /// <c>msiexec</c> can also bring a file down from the network, but they are ordinary
    /// programs doing one job, and pulling that thread turns this into "every tool that can
    /// download" — a list nobody keeps current, which is worse than a short one that says
    /// where it ends.
    /// </para>
    /// </summary>
    private static readonly string[] Hosts =
    [
        "powershell",
        "pwsh",
        "cmd",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
    ];

    private const string Preamble =
        "Interpréteur : ce qui s'exécute est décidé par ses arguments, et la signature ne "
        + "porte que sur l'interpréteur lui-même.";

    private const string EncodedReason =
        "Commande encodée en base64 (-EncodedCommand) : ce qui sera exécuté n'apparaît "
        + "nulle part en clair, ni ici ni dans un journal.";

    private const string HiddenReason =
        "Fenêtre masquée (hidden) : l'exécution ne laisse rien voir à qui est devant "
        + "l'écran.";

    private const string BypassReason =
        "Stratégie d'exécution contournée (bypass) : le script s'exécute quelle que soit "
        + "la politique de la machine.";

    private const string RemoteReason =
        "Argument distant (http, https ou ftp) : la charge utile est téléchargée au "
        + "lancement, elle n'est donc pas sur la machine et peut changer sans que rien "
        + "d'observable ici ne bouge.";

    private const string TemporaryReason =
        "Argument dans un dossier temporaire : n'importe quel programme peut y écrire, et "
        + "rien n'y est censé persister d'un démarrage à l'autre.";

    private const string NoProfileReason =
        "Profil PowerShell ignoré (-NoProfile) : l'exécution ne dépend pas de la "
        + "configuration de l'utilisateur.";

    /// <summary>
    /// Runs a command line past the markers that count.
    /// </summary>
    /// <param name="executable">The resolved path of what is launched.</param>
    /// <param name="arguments">Everything that follows it, exactly as recorded.</param>
    public static PayloadJudgement Inspect(string executable, string arguments)
    {
        if (HostName(executable) is not { } host)
        {
            return PayloadJudgement.Silent;
        }

        // PowerShell's switches are read for PowerShell alone. « cscript //B » and
        // « cmd /c » have their own vocabulary, and lending one host's grammar to another
        // is how an ordinary flag comes to look like a marker.
        var scripted = host is "powershell" or "pwsh";

        var tokens = Tokenise(arguments);
        bool encoded = false, hidden = false, bypass = false;
        bool remote = false, temporary = false, noProfile = false;

        for (var index = 0; index < tokens.Count; index++)
        {
            if (SwitchName(tokens[index], out var glued) is not { } name)
            {
                remote |= IsRemote(tokens[index]);
                temporary |= IsTemporary(tokens[index]);
                continue;
            }

            // A switch takes the following token as its value only when that token is not
            // a switch itself: in « -nop -w hidden », « -w » is not the value of « -nop »,
            // and reading it as one shifts every value by one place.
            var value = glued ?? Following(tokens, index);

            if (value is not null)
            {
                remote |= IsRemote(value);
                temporary |= IsTemporary(value);
            }

            if (!scripted)
            {
                continue;
            }

            // « -ec » is not a prefix of the switch name, so the rule above cannot reach
            // it: it is named by hand, and it is the exception that rule pays for. Naming
            // it costs nothing — no other powershell.exe switch answers to « ec », so the
            // only command line it can flag is one nothing else explains.
            encoded |= Abbreviates(name, "encodedcommand", minimum: 1)
                       || name.Equals("ec", StringComparison.OrdinalIgnoreCase);

            // Three characters, because « -no » alone is ambiguous with -NoLogo and
            // -NonInteractive — PowerShell itself would refuse it.
            noProfile |= Abbreviates(name, "noprofile", minimum: 3);

            // Read from the value rather than from the switch: it is what makes « -w »,
            // « -WindowStyle » and « -windowstyle:hidden » one rule instead of three
            // spellings, and it catches « -ep bypass », whose name no prefix rule reaches.
            hidden |= Is(value, "hidden");
            bypass |= Is(value, "bypass");
        }

        var reasons = new List<string>();

        Add(reasons, encoded, EncodedReason);
        Add(reasons, hidden, HiddenReason);
        Add(reasons, bypass, BypassReason);
        Add(reasons, remote, RemoteReason);
        Add(reasons, temporary, TemporaryReason);

        // -NoProfile on its own accuses good practice: a maintenance script that does not
        // want the operator's profile loaded writes exactly that, and a finding on every
        // careful script is how a report stops being read. It corroborates, it never
        // carries the case by itself.
        if (reasons.Count == 0)
        {
            return PayloadJudgement.Silent;
        }

        Add(reasons, noProfile, NoProfileReason);

        // Reasons are emitted in a fixed order rather than in the order the arguments
        // happen to be written: the same entry has to produce the same report twice, and
        // the fixture references freeze that text.
        reasons.Insert(0, Preamble);

        return new PayloadJudgement(FindingSeverity.Notable, reasons);
    }

    /// <summary>
    /// Splits a command line into arguments the way a reader would, honouring double quotes
    /// so that a folder name containing a space stays one argument. Split on spaces alone,
    /// <c>C:\Temp Files\maj.bat</c> becomes <c>C:\Temp</c> followed by something else — and
    /// the first half is a temporary folder that was never there.
    ///
    /// <para>
    /// The quotes are dropped: what gets compared afterwards is the value, not its spelling.
    /// </para>
    /// </summary>
    private static List<string> Tokenise(string arguments)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        var quoted = false;

        foreach (var character in arguments)
        {
            if (character == '"')
            {
                quoted = !quoted;
                continue;
            }

            if (!quoted && char.IsWhiteSpace(character))
            {
                if (current.Length > 0)
                {
                    tokens.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            current.Append(character);
        }

        if (current.Length > 0)
        {
            tokens.Add(current.ToString());
        }

        return tokens;
    }

    /// <summary>
    /// The host a path names, or <c>null</c> when it names anything else.
    ///
    /// <para>
    /// The file name is compared whole, never searched for: <c>C:\Tools\mypowershell.exe</c>
    /// is not PowerShell, and a substring test would have said it was — the shape that let a
    /// <c>WindowsApps</c> directory created inside a profile pass for the package store. The
    /// <c>.exe</c> suffix is optional because a <c>Run</c> value routinely omits it and lets
    /// Windows resolve the name through the PATH.
    /// </para>
    ///
    /// <para>
    /// Both separators are split by hand rather than through <c>System.IO.Path</c>: these are
    /// Windows paths read from a capture, and the replay runs on Linux in CI, where <c>\</c>
    /// is not a separator and the whole path would come back as one file name.
    /// </para>
    /// </summary>
    private static string? HostName(string executable)
    {
        var separator = executable.LastIndexOfAny(['\\', '/']);
        var name = separator >= 0 ? executable[(separator + 1)..] : executable;

        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            name = name[..^4];
        }

        return Array.Find(Hosts, host => host.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The name of a switch, and the value glued to it when there is one.
    ///
    /// <para>
    /// Splitting on <c>:</c> and <c>=</c> is what reaches
    /// <c>regsvr32 /i:http://…/x.sct</c>, where the address never stands as a token of its
    /// own. Only a token that opens with <c>-</c> or <c>/</c> is split that way — a Windows
    /// path carries a colon of its own, two characters in.
    /// </para>
    /// </summary>
    private static string? SwitchName(string token, out string? glued)
    {
        glued = null;

        if (token.Length < 2 || (token[0] != '-' && token[0] != '/'))
        {
            return null;
        }

        var name = token.TrimStart('-', '/');
        var separator = name.IndexOfAny([':', '=']);

        if (separator >= 0)
        {
            glued = name[(separator + 1)..];
            name = name[..separator];
        }

        return name.Length > 0 ? name : null;
    }

    private static string? Following(List<string> tokens, int index) =>
        index + 1 < tokens.Count && SwitchName(tokens[index + 1], out _) is null
            ? tokens[index + 1]
            : null;

    /// <summary>
    /// Whether <paramref name="name"/> is an abbreviation of <paramref name="full"/> that
    /// PowerShell would itself resolve.
    ///
    /// <para>
    /// It resolves a switch from any prefix of its name, so <c>-EncodedCommand</c> answers
    /// to <c>-enc</c> and to <c>-e</c> alike. Matching literal spellings would catch the
    /// longest and miss the short ones — and it is the short ones that get typed.
    /// </para>
    ///
    /// <para>
    /// <paramref name="minimum"/> is what keeps an abbreviation from reaching a switch it
    /// does not name: <c>-no</c> is ambiguous between -NoProfile, -NoLogo and
    /// -NonInteractive, and PowerShell would refuse it too.
    /// </para>
    /// </summary>
    private static bool Abbreviates(string name, string full, int minimum) =>
        name.Length >= minimum
        && name.Length <= full.Length
        && full.StartsWith(name, StringComparison.OrdinalIgnoreCase);

    private static bool Is(string? value, string expected) =>
        value is not null && value.Equals(expected, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether an argument names something the machine has to go and fetch.
    ///
    /// <para>
    /// The scheme is the whole test, and it has to be: a Windows path is an absolute URI as
    /// far as the parser is concerned — <c>C:\Windows\notepad.exe</c> comes back with the
    /// scheme <c>file</c> — so accepting any absolute URI would read every argument naming a
    /// file as a download.
    /// </para>
    /// </summary>
    private static bool IsRemote(string token) =>
        Uri.TryCreate(token, UriKind.Absolute, out var uri)
        && uri.Scheme is "http" or "https" or "ftp";

    /// <summary>
    /// Whether an argument sits in a temporary folder.
    ///
    /// <para>
    /// Matched as a path segment, never as a substring: <c>C:\Templates\</c> is not a
    /// temporary folder and <c>Contains("temp")</c> would have said it was. That is the same
    /// mistake as the package-store one, on a string an attacker chooses.
    /// </para>
    ///
    /// <para>
    /// A lone <c>temp</c> is only read as a folder when the argument holds a separator: a
    /// bare word is a word, and an entry passing <c>temp</c> to a script is not persisting
    /// anything. The environment references are accepted on their own because they can only
    /// ever expand to that folder.
    /// </para>
    /// </summary>
    private static bool IsTemporary(string token)
    {
        var segments = token.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);

        return segments.Any(segment =>
                   segment.Equals("%TEMP%", StringComparison.OrdinalIgnoreCase)
                   || segment.Equals("%TMP%", StringComparison.OrdinalIgnoreCase))
               || (segments.Length > 1
                   && segments.Any(s => s.Equals("temp", StringComparison.OrdinalIgnoreCase)));
    }

    private static void Add(List<string> reasons, bool found, string reason)
    {
        if (found)
        {
            reasons.Add(reason);
        }
    }
}
