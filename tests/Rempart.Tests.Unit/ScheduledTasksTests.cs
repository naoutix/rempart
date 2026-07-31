using System.Text.RegularExpressions;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Json;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

internal sealed class FakeScheduledTaskProvider(ScheduledTaskRead read) : IScheduledTaskProvider
{
    public ScheduledTaskRead Enumerate() => read;
}

internal sealed class FakeSignatureProvider : ISignatureProvider
{
    private readonly Dictionary<string, FileSignature> signatures =
        new(StringComparer.OrdinalIgnoreCase);

    public FakeSignatureProvider With(
        string path, SignatureStatus status, string? publisher = null, string? sha256 = null)
    {
        signatures[path] = new FileSignature(status, publisher, sha256);
        return this;
    }

    public FileSignature Verify(string path) =>
        signatures.TryGetValue(path, out var signature)
            ? signature
            : new FileSignature(SignatureStatus.Unknown);
}

public class ScheduledTasksTests
{
    private static ScheduledTask Task(
        string path, params TaskAction[] actions) =>
        new(path, path, Enabled: true, "ready", "Contoso", "S-1-5-18", null, actions);

    private static TaskAction Exec(string path) => new("exec", path, string.Empty);

    private static IReadOnlyList<Finding> Collect(
        ScheduledTaskRead read, ISignatureProvider signatures) =>
        new ScheduledTasksCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: signatures,
            scheduledTasks: new FakeScheduledTaskProvider(read)));

    /// <summary>
    /// Windows removes a task by itself only when it is told to delete it once expired
    /// <b>and</b> a trigger actually ends. Either fact alone changes nothing: a task with
    /// an end boundary but no delete setting simply stops firing and stays listed.
    ///
    /// <para>
    /// Covered by a fabricated task rather than a real one: the test machine carries 196
    /// scheduled tasks and not one of them has either setting — cross-checked with
    /// <c>Get-ScheduledTask</c> on 2026-07-24. The zero was verified, not assumed, but it
    /// leaves this branch without a real example.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("PT0S", true, true)]
    [InlineData("P1D", true, true)]
    [InlineData(null, true, false)]
    [InlineData("PT0S", false, false)]
    [InlineData("", true, false)]
    public void A_task_windows_deletes_on_expiry_is_marked_as_transient(
        string? deleteExpiredAfter, bool expiringTrigger, bool expectedMark)
    {
        var task = new ScheduledTask(
            @"\Ponctuelle", @"\Ponctuelle", Enabled: true, "ready", "Contoso", "S-1-5-18",
            null, [Exec(@"C:\tools\once.exe")], deleteExpiredAfter, expiringTrigger);

        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Found([task]),
            new FakeSignatureProvider().With(@"C:\tools\once.exe", SignatureStatus.Unsigned)));

        Assert.Equal(expectedMark, finding.Details.ContainsKey(FindingDetails.Transient));
    }

    /// <summary>
    /// The mark says the task may vanish on its own; it must not soften the judgement.
    /// An unsigned binary launched by a task that deletes itself afterwards is exactly
    /// as suspicious — arguably more.
    /// </summary>
    [Fact]
    public void Being_transient_does_not_lower_the_severity()
    {
        var task = new ScheduledTask(
            @"\Ponctuelle", @"\Ponctuelle", Enabled: true, "ready", null, null, null,
            [Exec(@"C:\tools\once.exe")], "PT0S", HasExpiringTrigger: true);

        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Found([task]),
            new FakeSignatureProvider().With(@"C:\tools\once.exe", SignatureStatus.Unsigned)));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains(FindingDetails.Transient, finding.Details.Keys);
    }

    [Fact]
    public void Unsigned_action_is_suspicious()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\Perso", Exec(@"C:\tools\agent.exe"))]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("non signé", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// Windows ships several hundred signed tasks. If any of them surfaced for
    /// review, the report would become unreadable and stop being read — noise,
    /// not missing coverage, is what kills an audit tool.
    /// </summary>
    [Fact]
    public void Signed_action_is_benign()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\Microsoft\Windows\Truc", Exec(@"C:\Windows\System32\sc.exe"))]),
            new FakeSignatureProvider().With(@"C:\Windows\System32\sc.exe", SignatureStatus.Valid));

        Assert.Equal(FindingSeverity.Benign, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// The other half of REV-17. The scheduler is the larger persistence surface and it
    /// carried the same blind spot as the <c>Run</c> keys: <c>Arguments</c> went into a
    /// detail string and was judged by nobody, so a task launching the validly signed
    /// <c>powershell.exe</c> of the machine came out benign with nothing written beside it.
    /// </summary>
    [Fact]
    public void A_task_hiding_its_payload_behind_a_signed_interpreter_is_notable()
    {
        const string Interpreter = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\Microsoft\Windows\Maintenance",
                new TaskAction("exec", Interpreter, "-NoProfile -w hidden -enc SQBFAFgA"))]),
            new FakeSignatureProvider().With(Interpreter, SignatureStatus.Valid));

        var finding = Assert.Single(findings);

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("encodée", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// And the false positive it must not become. Windows ships a dozen tasks calling into
    /// a system DLL through <c>rundll32</c>; flagging them would put a line on every machine
    /// in the fleet, which is precisely why this collector counts the crowd rather than
    /// detailing it.
    /// </summary>
    [Fact]
    public void A_system_task_calling_into_a_dll_stays_benign()
    {
        const string Interpreter = @"C:\Windows\System32\rundll32.exe";

        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\Microsoft\Windows\Autochk\Proxy",
                new TaskAction("exec", Interpreter, "/d acproxy.dll,PerformAutochkOperations"))]),
            new FakeSignatureProvider().With(Interpreter, SignatureStatus.Valid));

        var finding = Assert.Single(findings);

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Empty(finding.Reasons);
    }

    /// <summary>
    /// The signature is recorded even when valid. Recording it only when it is a
    /// problem would make "verified and good" indistinguishable from "never
    /// verified" — the silent variant of the defect that left WMI inoperative
    /// for two batches.
    /// </summary>
    [Fact]
    public void Valid_signature_is_recorded_not_only_failures()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\T", Exec(@"C:\Windows\System32\sc.exe"))]),
            new FakeSignatureProvider().With(
                @"C:\Windows\System32\sc.exe", SignatureStatus.Valid, "Microsoft Corporation"));

        var details = Assert.Single(findings).Details;
        Assert.Equal("Valid", details["signature"]);
        Assert.Equal("Microsoft Corporation", details["éditeur"]);
    }

    /// <summary>
    /// The scheduler resolves <c>sc.exe</c> at run time. A name the provider
    /// failed to resolve produced, on a real machine, two "target file does not
    /// exist" findings about binaries actually present in System32. A resolution
    /// gap must not masquerade as a fact about the machine.
    /// </summary>
    [Fact]
    public void Unresolved_bare_name_is_reported_as_unresolved_not_as_missing_file()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\T", Exec("mystere.exe"))]),
            new FakeSignatureProvider());

        var finding = Assert.Single(findings);
        var reasons = string.Join(" ", finding.Reasons);

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("Chemin non résolu", reasons);
        Assert.DoesNotContain("n'existe pas", reasons);
    }

    /// <summary>
    /// A task without an executable — a COM handler — has no signature to verify.
    /// It is enumerated with that noted, like a startup-folder shortcut.
    /// </summary>
    [Fact]
    public void Com_handler_task_is_listed_without_being_judged()
    {
        var findings = Collect(
            ScheduledTaskRead.Found(
                [Task(@"\NGEN", new TaskAction("ComHandler", string.Empty, string.Empty))]),
            new FakeSignatureProvider());

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("ComHandler", finding.Details["type"]);
        Assert.Contains("aucune signature", finding.Details["note"]);
    }

    /// <summary>
    /// A disabled task does not run, and the report must say so — but the
    /// finding stands: a disabled task can be re-enabled.
    /// </summary>
    [Fact]
    public void Disabled_task_keeps_its_severity_and_says_so()
    {
        var task = Task(@"\Perso", Exec(@"C:\tools\agent.exe")) with { Enabled = false };

        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Found([task]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned)));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Equal("désactivée", finding.Details["état"]);
        Assert.Contains("désactivée", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// An unreadable scheduler is not an empty scheduler. Silently returning
    /// zero tasks would make a failure look like a healthy machine.
    ///
    /// <para>
    /// And it is not a refused scheduler either, which is the half this test did not hold.
    /// <c>ScheduledTaskRead.Failed</c> carried <c>AccessDenied</c> until #177, so the marshaller
    /// blowing up inside the COM walk — a bug, on any account, with no privilege to be had —
    /// came back « relancer en administrateur » and exited <c>3</c>. The reason printed here
    /// was already right; nothing read it.
    /// </para>
    /// </summary>
    [Fact]
    public void Failed_enumeration_produces_a_finding_never_silence()
    {
        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Failed("MarshalDirectiveException : bidule"),
            new FakeSignatureProvider()));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("bidule", string.Join(" ", finding.Reasons));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.NotEqual(AuditGap.Refused, finding.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", finding.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// <c>E_ACCESSDENIED</c>, the single HRESULT that genuinely means "elevate and retry".
    /// </summary>
    private const int AccessDenied = unchecked((int)0x80070005);

    /// <summary>
    /// A walk refused halfway keeps what it read, and says what it lost.
    ///
    /// <para>
    /// The scenario: an unelevated scan on a machine where one task folder carries a
    /// restrictive ACL — or where an intruder put one on the folder holding their task.
    /// <c>GetTasks</c> answers <c>E_ACCESSDENIED</c>, that branch is skipped, and the report
    /// presented the remaining tasks as the complete inventory of what this project calls the
    /// largest persistence surface on Windows.
    /// </para>
    ///
    /// <para>
    /// Both halves in one test because it is their conjunction that is the fix: answering
    /// with the refusal alone would drop the tasks that were read, which is the same silence
    /// one folder over.
    /// </para>
    /// </summary>
    [Fact]
    public void A_partly_refused_walk_keeps_its_tasks_and_names_the_folder_it_lost()
    {
        const string Refused = @"\Microsoft\Windows\UpdateOrchestrator";

        var findings = Collect(
            ScheduledTaskRead.Partially(
                [Task(@"\Perso", Exec(@"C:\tools\agent.exe"))],
                [TaskFolderGap.Of(Refused, "GetTasks", AccessDenied)]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned));

        Assert.Equal(2, findings.Count);

        var gap = Assert.Single(findings, f => f.Source == "planificateur de tâches");
        Assert.Equal(FindingSeverity.Notable, gap.Severity);
        Assert.Contains(Refused, string.Join(" ", gap.Reasons), StringComparison.Ordinal);

        // And it stays a refusal, which is the half the split must not lose: this folder
        // answered E_ACCESSDENIED, so elevation is exactly the remedy — the marker is what
        // carries it, the walk having written its own sentence in place of the fallback.
        Assert.Equal(AuditGap.Refused, gap.Gap);

        var task = Assert.Single(findings, f => f.Source == @"\Perso");
        Assert.Equal(FindingSeverity.Suspicious, task.Severity);
    }

    /// <summary>
    /// The other half of the same walk, and the reason the partial read has two forms since
    /// #177: a folder can be abandoned without anybody being refused anything.
    ///
    /// <para>
    /// <c>GetFolders</c> answering <c>0x80041318</c>, a task that will not say where it lives,
    /// the depth cap — none of them is a permission, and the walk used to hand all of them
    /// back through the one <c>Partial</c> that carried <c>AccessDenied</c>. The tasks it did
    /// read are kept either way; what changes is whether the report tells its reader to
    /// re-run as administrator over a scheduler that would not have answered anyway.
    /// </para>
    /// </summary>
    [Fact]
    public void A_walk_that_lost_a_folder_without_being_refused_does_not_advise_elevation()
    {
        const string Lost = @"\Microsoft\Windows\UpdateOrchestrator";

        var findings = Collect(
            ScheduledTaskRead.Partially(
                [Task(@"\Perso", Exec(@"C:\tools\agent.exe"))],
                [TaskFolderGap.Of(Lost, "GetFolders", unchecked((int)0x80041318))]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned));

        var gap = Assert.Single(findings, f => f.Source == "planificateur de tâches");

        Assert.Equal(AuditGap.Unreadable, gap.Gap);
        Assert.NotEqual(AuditGap.Refused, gap.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", gap.Reasons),
            StringComparison.OrdinalIgnoreCase);

        // The folder is still named and the tasks are still kept: the split changes the
        // remedy offered, nothing else.
        Assert.Contains(Lost, string.Join(" ", gap.Reasons), StringComparison.Ordinal);
        Assert.Single(findings, f => f.Source == @"\Perso");
    }

    /// <summary>
    /// A walk that met both keeps the elevation advice: it answers for the folder that was
    /// denied, and there is no third gap to say « half of this is a permission ».
    /// </summary>
    [Fact]
    public void A_walk_that_met_a_denial_and_a_failure_still_offers_the_remedy_for_the_denial()
    {
        var findings = Collect(
            ScheduledTaskRead.Partially([],
            [
                TaskFolderGap.Of(@"\A", "GetFolders", unchecked((int)0x80041318)),
                TaskFolderGap.Of(@"\B", "GetTasks", AccessDenied),
            ]),
            new FakeSignatureProvider());

        Assert.Equal(AuditGap.Refused, Assert.Single(findings).Gap);
    }

    /// <summary>
    /// "Never translate a failure into « access denied »", on the surface where it is
    /// easiest to break: the walk reads five HRESULTs per folder and exactly one of them
    /// means the operator lacks a privilege. A damaged scheduler reported as
    /// « relancer en administrateur » sends someone to elevate forever — what a mute WMI
    /// cost this project for two milestones.
    /// </summary>
    [Theory]
    [InlineData(AccessDenied, "0x80070005", true)]
    [InlineData(unchecked((int)0x80041318), "0x80041318", false)]
    public void Only_the_denial_hresult_is_reported_as_a_denial(
        int hresult, string code, bool denial)
    {
        var gap = TaskFolderGap.Of(@"\Microsoft\Windows", "GetTasks", hresult);

        Assert.Equal(denial, gap.Reason.Contains("refus", StringComparison.Ordinal));
        Assert.Contains(code, gap.Reason, StringComparison.Ordinal);
        Assert.Contains("GetTasks", gap.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// No COM result the walk reads can be dropped without leaving a trace — checked against
    /// the file, not against a list of the branches somebody remembered.
    ///
    /// <para>
    /// That distinction is this review's central reproach. Four branches were named in the
    /// finding; a fifth and a sixth were sitting beside them, and a seventh added next year
    /// would sit outside any list written today. The HRESULT-returning members are read from
    /// the interop file on disk, so a call added to the walk — or a member added to the
    /// interop and then used — is inside this guard the day it is written.
    /// </para>
    ///
    /// <para>
    /// Scoped to the walk, deliberately. <c>Execute</c> throws on its two failures, and the
    /// per-task read degrades on purpose: a definition that will not open leaves a task with
    /// no action, which the collector reports as « aucune action lisible » rather than
    /// swallows. Those are answers. The walk's were nothing at all.
    /// </para>
    ///
    /// <para>
    /// This is also the only test that reaches the scheduler's COM path. It has no machine
    /// test — five vtables derived from <c>IDispatch</c>, the riskiest interop in the
    /// repository — so what can be checked without a machine is checked here, and the
    /// judgement below it lives in <c>Rempart.Core</c> where a fake provider can drive it.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_com_result_the_walk_reads_is_recorded_when_it_fails()
    {
        var members = Regex.Matches(
                RepositoryFiles.Read("src/Rempart.Windows/Tasks/TaskSchedulerInterop.cs"),
                @"\[PreserveSig\]\s+int (\w+)\(")
            .Select(match => match.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // A pattern that matches nothing reports success: the two counts below are what
        // stops this guard from passing because it looked at an empty set.
        Assert.NotEmpty(members);

        var body = WalkBody(
            RepositoryFiles.Read("src/Rempart.Windows/Tasks/LiveScheduledTaskProvider.cs"));

        Assert.Contains(members, member => Calls(body, member));

        // Statement by statement: a COM call reads its result through the recorder or it
        // does not read it at all. Braces and semicolons cut the body up, which is enough
        // to tell one call from the next.
        var silent = body.Split(';', '{', '}')
            .Where(statement => members.Any(member => Calls(statement, member))
                && !statement.Contains("Ok(", StringComparison.Ordinal))
            .Select(statement => Regex.Replace(statement, @"\s+", " ").Trim())
            .ToList();

        Assert.True(silent.Count == 0,
            "Appel(s) COM dont l'échec ne laisse aucune trace dans le parcours des dossiers "
            + $"de tâches : {string.Join(" | ", silent)}");
    }

    private static bool Calls(string code, string member) =>
        code.Contains($".{member}(", StringComparison.Ordinal);

    /// <summary>
    /// The body of the folder walk, brace-matched. Interpolations balance their own braces,
    /// so counting them is enough here and does not need a parser.
    /// </summary>
    private static string WalkBody(string source)
    {
        var start = source.IndexOf("private static void Walk(", StringComparison.Ordinal);
        Assert.True(start >= 0,
            "Le parcours des dossiers a changé de signature : ce garde ne regarde plus rien.");

        var open = source.IndexOf('{', start);
        var depth = 0;

        for (var i = open; i < source.Length; i++)
        {
            depth += source[i] switch { '{' => 1, '}' => -1, _ => 0 };

            if (depth == 0)
            {
                return source[open..(i + 1)];
            }
        }

        throw new InvalidOperationException("Corps du parcours non délimité.");
    }

    /// <summary>
    /// Absent from a capture predating this batch: the fixture stays replayable
    /// and yields a "not enumerated" finding rather than an empty scheduler.
    ///
    /// <para>
    /// <b>And not a refused one.</b> This assertion said <c>AccessDenied</c> and the line it
    /// watched said « treated as a denial », so replaying any capture taken before scheduled
    /// tasks were collected told its reader to re-run the scan as administrator — against a
    /// file that had already been written, on a machine that may no longer exist. The remedy
    /// is to re-capture, which is what <c>AuditGap.Unreadable</c> names and exit code <c>5</c>
    /// reports; the finding is asserted here as well as the status, because the status alone
    /// would go green on a collector that stopped reading it.
    /// </para>
    /// </summary>
    [Fact]
    public void Older_snapshot_replays_without_inventing_an_empty_scheduler()
    {
        var read = new SnapshotScheduledTaskProvider(new MachineSnapshot()).Enumerate();

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.NotNull(read.Diagnostic);

        var finding = Assert.Single(Collect(read, new FakeSignatureProvider()));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", finding.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("S-1-5-21-2354378594-2253722242-1776815907-1002")]
    [InlineData(@"DESKTOP-3VR09H0\leoar")]
    public void Anonymiser_hashes_accounts_that_designate_a_person(string account)
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            ScheduledTasks = ScheduledTaskRead.Found(
                [Task(@"\T") with { UserId = account, Author = account }]),
        };

        var task = Anonymiser.Apply(snapshot).ScheduledTasks!.Tasks[0];

        Assert.StartsWith("anon:", task.UserId);
        Assert.StartsWith("anon:", task.Author);
    }

    /// <summary>
    /// The system account designates nobody. Hashing it would cost fixture
    /// readability while protecting nothing: a system task would no longer be
    /// distinguishable from a user task, which is exactly what needs judging.
    /// </summary>
    [Fact]
    public void Anonymiser_leaves_well_known_accounts_readable()
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            ScheduledTasks = ScheduledTaskRead.Found(
                [Task(@"\T") with { UserId = "S-1-5-18", Author = "Microsoft Corporation" }]),
        };

        var task = Anonymiser.Apply(snapshot).ScheduledTasks!.Tasks[0];

        Assert.Equal("S-1-5-18", task.UserId);
        Assert.Equal("Microsoft Corporation", task.Author);
    }

    /// <summary>
    /// A snapshot that declares itself anonymised must be. The account name slips
    /// into profile paths — signature keys, enumerated directories, Run values —
    /// and a capture shared in confidence would pass it on.
    /// </summary>
    [Fact]
    public void Anonymiser_hashes_the_account_name_in_profile_paths()
    {
        const string Path = @"C:\Users\leoar\AppData\Local\Discord\Update.exe";

        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Signatures = { [Path] = new FileSignature(SignatureStatus.Valid) },
            Directories = { [@"C:\Users\leoar\Bureau"] = [Path] },
        };

        snapshot.Registry[SnapshotKeys.Value(@"HKCU\Run", "Discord")] =
            RegistryRead.Found(RegistryValue.OfText(Path));

        var result = Anonymiser.Apply(snapshot);

        Assert.DoesNotContain("leoar", RempartJson.Serialise(result), StringComparison.Ordinal);

        // The rest of the path survives: it is what says which application launches.
        Assert.Contains(result.Signatures.Keys,
            k => k.EndsWith(@"\Discord\Update.exe", StringComparison.Ordinal));
    }

    /// <summary>
    /// These profiles exist identically on every Windows installation: hashing
    /// them would cost fixture readability while protecting nothing.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\Public\Desktop\a.exe")]
    [InlineData(@"C:\Users\Default\NTUSER.DAT")]
    public void Anonymiser_leaves_impersonal_profiles_readable(string path) =>
        Assert.Equal(path, Anonymiser.ScrubProfile(path));
}
