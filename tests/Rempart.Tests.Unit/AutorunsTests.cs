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
            : DirectoryRead.Failed(
                reason is "" ? $"Dossier « {directory} » illisible : accès refusé." : reason);
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
}
