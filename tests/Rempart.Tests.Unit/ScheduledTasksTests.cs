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
