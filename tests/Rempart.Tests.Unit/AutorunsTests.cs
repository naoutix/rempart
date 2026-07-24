using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeFileSystemProvider : IFileSystemProvider
{
    private readonly Dictionary<string, List<string>> byDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    public FakeFileSystemProvider With(string directory, params string[] files)
    {
        byDirectory[directory] = [.. files];
        return this;
    }

    public IReadOnlyList<string> ListFiles(string directory) =>
        byDirectory.TryGetValue(directory, out var files) ? files : [];
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
}
