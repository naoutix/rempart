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
    /// </summary>
    [Fact]
    public void Failed_enumeration_produces_a_finding_never_silence()
    {
        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Failed("MarshalDirectiveException : bidule"),
            new FakeSignatureProvider()));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("bidule", string.Join(" ", finding.Reasons));
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
            ScheduledTaskRead.Partial(
                [Task(@"\Perso", Exec(@"C:\tools\agent.exe"))],
                [TaskFolderGap.Of(Refused, "GetTasks", AccessDenied)]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned));

        Assert.Equal(2, findings.Count);

        var gap = Assert.Single(findings, f => f.Source == "planificateur de tâches");
        Assert.Equal(FindingSeverity.Notable, gap.Severity);
        Assert.Contains(Refused, string.Join(" ", gap.Reasons), StringComparison.Ordinal);

        var task = Assert.Single(findings, f => f.Source == @"\Perso");
        Assert.Equal(FindingSeverity.Suspicious, task.Severity);
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
    /// </summary>
    [Fact]
    public void Older_snapshot_replays_without_inventing_an_empty_scheduler()
    {
        var read = new SnapshotScheduledTaskProvider(new MachineSnapshot()).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.NotNull(read.Diagnostic);
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
