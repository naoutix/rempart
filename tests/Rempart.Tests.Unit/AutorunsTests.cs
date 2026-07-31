using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeFileSystemProvider : IFileSystemProvider
{
    private readonly Dictionary<string, DirectoryRead> byDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    public FakeFileSystemProvider With(string directory, params string[] files)
    {
        byDirectory[directory] = DirectoryRead.Found(files);
        return this;
    }

    /// <summary>A folder the scan is refused — the state that used to be indistinguishable
    /// from an empty one (DET-FICHIERS-MUET).
    ///
    /// <para>
    /// <paramref name="reason"/> defaults to the sentence a live provider writes; passing
    /// <c>null</c> stands for a capture carrying a status with no diagnostic beside it,
    /// which is what the collector's own fallback sentence exists for.
    /// </para>
    /// </summary>
    public FakeFileSystemProvider WithDenied(string directory, string? reason = "")
    {
        byDirectory[directory] = reason is null
            ? new DirectoryRead(ReadStatus.AccessDenied, [], null)
            : DirectoryRead.Refused(
                reason is "" ? $"Dossier « {directory} » illisible : accès refusé." : reason);
        return this;
    }

    /// <summary>
    /// A folder the scan could not list <em>without</em> being refused — held open, or on a
    /// volume that went away. The other half of what <see cref="WithDenied"/> used to cover on
    /// its own: both went through a factory called <c>Failed</c> that returned
    /// <c>AccessDenied</c>, so a fake asked for a denial and a fake asked for a failure were
    /// the same object and no test could tell the collector's two answers apart (#173).
    /// </summary>
    public FakeFileSystemProvider WithFailed(string directory, string? reason = "")
    {
        byDirectory[directory] = reason is null
            ? new DirectoryRead(ReadStatus.Failed, [], null)
            : DirectoryRead.Failed(
                reason is ""
                    ? $"Dossier « {directory} » illisible : erreur d'entrée/sortie."
                    : reason);
        return this;
    }

    // Absent rather than Failed for a directory this fake was not told about: it stands for
    // a machine where that folder is simply not there, so a test that forgets to set one up
    // gets the silent answer and not a fabricated denial.
    public DirectoryRead ListFiles(string directory) =>
        byDirectory.TryGetValue(directory, out var read) ? read : DirectoryRead.Absent;
}

public class AutorunsTests
{
    private const string MachineShellFolders =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";

    private const string UserShellFolders =
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";

    private const string CommonStartup =
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";

    private static IReadOnlyList<Finding> Collect(
        IRegistryProvider registry, ISignatureProvider signatures, IFileSystemProvider files) =>
        new AutorunsCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), signatures: signatures, files: files));

    /// <summary>
    /// Startup folders come from the registry (<c>Shell Folders</c>), not from
    /// <c>Environment</c>: an executable dropped there is enumerated and judged on its
    /// signature. This test also runs on the CI Linux runner — it proves the resolution
    /// does not depend on the host.
    /// </summary>
    [Fact]
    public void Startup_folders_are_resolved_from_the_registry()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup);
        var signatures = new FakeSignatureProvider()
            .With($@"{CommonStartup}\evil.exe", SignatureStatus.Unsigned);
        var files = new FakeFileSystemProvider().With(CommonStartup, $@"{CommonStartup}\evil.exe");

        var finding = Assert.Single(Collect(registry, signatures, files));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Equal($@"{CommonStartup}\evil.exe", finding.Target);
    }

    /// <summary>
    /// <c>desktop.ini</c> is filtered out, including when its path carries Windows
    /// backslashes. This is the regression this batch fixes: <c>Path.GetFileName</c> does
    /// not recognise <c>\</c> on Linux and would let the file through on replay. This
    /// test would fail with the old host-dependent implementation.
    /// </summary>
    [Fact]
    public void Desktop_ini_is_filtered_even_with_a_windows_path()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup);
        var files = new FakeFileSystemProvider()
            .With(CommonStartup, $@"{CommonStartup}\desktop.ini");

        Assert.Empty(Collect(registry, new FakeSignatureProvider(), files));
    }

    /// <summary>
    /// A shortcut is enumerated without a verdict: its target is not resolved, and we do
    /// not pretend to verify what it launches.
    /// </summary>
    [Fact]
    public void A_shortcut_is_listed_without_a_signature_verdict()
    {
        var registry = new FakeRegistryProvider()
            .WithText(UserShellFolders, "Startup", @"C:\Users\anon\Startup");
        var files = new FakeFileSystemProvider()
            .With(@"C:\Users\anon\Startup", @"C:\Users\anon\Startup\app.lnk");

        var finding = Assert.Single(Collect(registry, new FakeSignatureProvider(), files));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("raccourci", finding.Details["type"]);
    }

    /// <summary>
    /// The gap REV-17 names, end to end. Everything about the entry is above suspicion —
    /// Microsoft's interpreter, validly signed, in System32 — so the finding used to come
    /// out benign with an empty reason list, and the console, the HTML and the Markdown all
    /// print only what is not benign. The entry was not merely unjudged: it was invisible.
    /// </summary>
    [Fact]
    public void An_encoded_powershell_autorun_is_reported_with_its_reasons()
    {
        const string Interpreter = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

        var registry = new FakeRegistryProvider().WithText(
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Updater",
            $@"""{Interpreter}"" -NoProfile -w hidden -enc SQBFAFgA");
        var signatures = new FakeSignatureProvider().With(Interpreter, SignatureStatus.Valid);

        var finding = Assert.Single(
            Collect(registry, signatures, new FakeFileSystemProvider()));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("encodée", string.Join(" ", finding.Reasons), StringComparison.Ordinal);
        Assert.Equal("Valid", finding.Details["signature"]);
    }

    /// <summary>
    /// The other half, and the one that decides whether the report keeps being read: a
    /// <c>RunOnce</c> entry Windows itself writes launches <c>cmd.exe</c>, and it must stay
    /// exactly where it was. The quoted path carries a space, which is also what the
    /// argument splitting has to survive.
    /// </summary>
    [Fact]
    public void An_ordinary_interpreter_autorun_stays_benign()
    {
        const string Interpreter = @"C:\Windows\System32\cmd.exe";

        var registry = new FakeRegistryProvider().WithText(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Delete Cached Binary",
            $@"{Interpreter} /q /c del /q ""C:\Program Files\Microsoft OneDrive\Setup.exe""");
        var signatures = new FakeSignatureProvider().With(Interpreter, SignatureStatus.Valid);

        var finding = Assert.Single(
            Collect(registry, signatures, new FakeFileSystemProvider()));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Empty(finding.Reasons);
    }

    /// <summary>
    /// The two axes add up rather than replace one another. An unsigned interpreter dropped
    /// in a temporary folder is suspicious because of its signature, and lowering that to
    /// notable because the command line only asks for a look would be a regression the
    /// reader pays for.
    /// </summary>
    [Fact]
    public void A_payload_reason_never_lowers_what_the_signature_decided()
    {
        const string Dropped = @"C:\Users\anon\AppData\Local\Temp\powershell.exe";

        var registry = new FakeRegistryProvider().WithText(
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Updater",
            $"{Dropped} -enc SQBFAFgA");
        var signatures = new FakeSignatureProvider().With(Dropped, SignatureStatus.Unsigned);

        var finding = Assert.Single(
            Collect(registry, signatures, new FakeFileSystemProvider()));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("non signé", string.Join(" ", finding.Reasons), StringComparison.Ordinal);
        Assert.Contains("encodée", string.Join(" ", finding.Reasons), StringComparison.Ordinal);
    }

    /// <summary>
    /// Without a <c>Shell Folders</c> value in the registry, no startup folder is
    /// scanned — no path gets invented, only the Run keys count.
    /// </summary>
    [Fact]
    public void Absent_shell_folder_values_scan_no_startup_folder()
    {
        var files = new FakeFileSystemProvider()
            .With(CommonStartup, $@"{CommonStartup}\whatever.exe");

        Assert.Empty(Collect(new FakeRegistryProvider(), new FakeSignatureProvider(), files));
    }

    private const string MachineRun =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>
    /// A <c>Run</c> key whose enumeration was refused. The same shape the startup folder
    /// already had (DET-FICHIERS-MUET), one surface over: an ACL laid on the key by whoever
    /// wants their entry unseen produced « aucun démarrage automatique » — on the first
    /// place an audit looks, answering exactly like a clean machine.
    /// </summary>
    [Fact]
    public void A_refused_run_key_is_reported_rather_than_read_as_no_autorun()
    {
        var registry = new FakeRegistryProvider().WithDeniedEnumeration(MachineRun);

        var finding = Assert.Single(
            Collect(registry, new FakeSignatureProvider(), new FakeFileSystemProvider()));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal(MachineRun, finding.Source);
        Assert.Contains("illisible", string.Join(" ", finding.Reasons), StringComparison.Ordinal);
    }

    /// <summary>
    /// The asymmetry, asserted so the fix above cannot be widened into noise: an empty
    /// <c>Run</c> key is an <em>answer</em>, and most machines hold nothing in four of the
    /// five. Only a refusal is a hole in what the scan saw — the same line the collector
    /// already draws between <c>NotFound</c> and <c>AccessDenied</c> on a startup folder.
    /// </summary>
    [Fact]
    public void An_empty_run_key_stays_silent()
    {
        Assert.Empty(Collect(
            new FakeRegistryProvider(), new FakeSignatureProvider(), new FakeFileSystemProvider()));
    }

    /// <summary>
    /// The refusal does not cost the keys that answered. Four <c>Run</c> keys out of five
    /// still enumerate, and the entry they hold is judged as usual — dropping it because a
    /// neighbour refused would trade one silence for another, which is the rule
    /// <c>ScheduledTaskRead.Partial</c> settled one issue ago.
    /// </summary>
    [Fact]
    public void A_refused_run_key_does_not_cost_the_entries_of_the_keys_that_answered()
    {
        var registry = new FakeRegistryProvider()
            .WithDeniedEnumeration(MachineRun)
            .WithText(@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "App",
                @"C:\App\app.exe");
        var signatures = new FakeSignatureProvider().With(@"C:\App\app.exe", SignatureStatus.Valid);

        var findings = Collect(registry, signatures, new FakeFileSystemProvider());

        Assert.Contains(findings, finding => finding.Target == @"C:\App\app.exe");
        Assert.Contains(findings, finding => finding.Source == MachineRun);
    }

    /// <summary>
    /// The <c>Shell Folders</c> read, which goes through the same enumeration. A refusal
    /// there yields no path at all, so no startup folder is ever walked and the
    /// <c>AccessDenied</c> finding one level down cannot fire either: the silence hides a
    /// silence.
    /// </summary>
    [Fact]
    public void A_refused_shell_folders_key_says_the_startup_folders_were_never_reached()
    {
        var registry = new FakeRegistryProvider().WithDeniedEnumeration(MachineShellFolders);

        var finding = Assert.Single(
            Collect(registry, new FakeSignatureProvider(), new FakeFileSystemProvider()));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal(MachineShellFolders, finding.Source);
    }

    /// <summary>
    /// The two ways a startup folder stops answering, told apart by what the reader is asked
    /// to do about it — the inversion #173 was opened over, at the collector that made it.
    ///
    /// <para>
    /// <c>IFileSystemProvider</c> documented one speaking state as « the listing was refused »
    /// while <c>LiveFileSystemProvider</c> reached it through <c>IOException</c> too, so a
    /// folder held open by another process was reported as one elevation would open. Both
    /// halves are asserted here because only the pair is a claim: a fix that answered
    /// <c>Unreadable</c> to everything would satisfy the second assertion and break the first,
    /// and it is the first that carries the commonest gap this tool has.
    /// </para>
    /// </summary>
    [Fact]
    public void A_startup_folder_that_failed_is_not_a_startup_folder_that_was_denied()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup);

        var denied = Assert.Single(Collect(registry, new FakeSignatureProvider(),
            new FakeFileSystemProvider().WithDenied(CommonStartup)));

        Assert.Equal(AuditGap.Refused, denied.Gap);

        var failed = Assert.Single(Collect(registry, new FakeSignatureProvider(),
            new FakeFileSystemProvider().WithFailed(CommonStartup)));

        Assert.Equal(AuditGap.Unreadable, failed.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", failed.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The same pair with nothing to print, which is the half the guards in
    /// <c>ExitCodeTests</c> cannot reach: they plant a diagnostic on every provider, so the
    /// sentence they check is always the read's own. A capture carrying a status and no
    /// diagnostic beside it replays here, and then the <em>fallback</em> is what reaches the
    /// report — a sentence promising elevation under <see cref="AuditGap.Unreadable"/> would
    /// contradict the value in the same finding and nothing else would notice.
    /// </summary>
    [Fact]
    public void A_startup_folder_that_failed_without_a_reason_still_offers_no_remedy()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup);

        var failed = Assert.Single(Collect(registry, new FakeSignatureProvider(),
            new FakeFileSystemProvider().WithFailed(CommonStartup, reason: null)));

        Assert.Equal(AuditGap.Unreadable, failed.Gap);
        Assert.NotEmpty(failed.Reasons);
        Assert.DoesNotContain("administrateur", string.Join(" ", failed.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A scan wired with no file provider at all, which is the third producer on this channel
    /// and the one that moved without being named.
    ///
    /// <para>
    /// <c>UnavailableFileSystem</c> calls <c>DirectoryRead.Failed</c>, and that call changed
    /// meaning under it in #173: the factory kept its name and stopped returning
    /// <see cref="ReadStatus.AccessDenied"/>. The new answer is the right one — no privilege
    /// supplies a provider nobody wired, so « droits insuffisants » was advice that could not
    /// work — but nothing asserted either answer, before or after, and the whole argument for
    /// keeping the name was that the callers who moved would be looked at one by one. This
    /// looks at the one that was not.
    /// </para>
    /// </summary>
    [Fact]
    public void A_scan_with_no_file_provider_is_unreadable_rather_than_denied()
    {
        var registry = new FakeRegistryProvider()
            .WithText(MachineShellFolders, "Common Startup", CommonStartup);

        // No files argument: ProviderSet falls back to UnavailableFileSystem, which is the
        // subject here and cannot be named from this assembly.
        var finding = Assert.Single(new AutorunsCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), signatures: new FakeSignatureProvider())));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.NotEqual(AuditGap.Refused, finding.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", finding.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }
}
