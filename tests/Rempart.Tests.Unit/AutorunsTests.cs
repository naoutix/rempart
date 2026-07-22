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
    /// Les dossiers de démarrage viennent du registre (<c>Shell Folders</c>), pas de
    /// <c>Environment</c> : un exécutable qui y est déposé est énuméré et jugé sur sa
    /// signature. Ce test s'exécute aussi sur le runner Linux de la CI — il prouve que la
    /// résolution ne dépend pas de l'hôte.
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
    /// <c>desktop.ini</c> est filtré, y compris quand son chemin porte des contre-obliques
    /// Windows. C'est la régression que corrige le lot : <c>Path.GetFileName</c> ne
    /// reconnaît pas le <c>\</c> sur Linux et laisserait passer le fichier au rejeu. Ce
    /// test échouerait avec l'ancienne implémentation dépendante de l'hôte.
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
    /// Un raccourci est énuméré sans être jugé : sa cible n'est pas résolue, on ne prétend
    /// pas vérifier ce qu'il lance.
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
    /// Sans valeur <c>Shell Folders</c> dans le registre, aucun dossier de démarrage n'est
    /// parcouru — pas d'invention de chemin, seules les clés Run comptent.
    /// </summary>
    [Fact]
    public void Absent_shell_folder_values_scan_no_startup_folder()
    {
        var files = new FakeFileSystemProvider()
            .With(CommonStartup, $@"{CommonStartup}\whatever.exe");

        Assert.Empty(Collect(new FakeRegistryProvider(), new FakeSignatureProvider(), files));
    }
}
