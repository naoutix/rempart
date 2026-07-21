using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class LogonExtensibilityTests
{
    private const string Winlogon =
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Windows =
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    private static IReadOnlyList<Finding> Collect(
        FakeRegistryProvider registry, ISignatureProvider signatures) =>
        new LogonExtensibilityCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), signatures: signatures));

    /// <summary>
    /// La configuration par défaut : Userinit et Shell pointent leurs programmes
    /// attendus, tous deux signés. Rien à examiner — sinon le rapport crierait à chaque
    /// scan d'une machine saine.
    /// </summary>
    [Fact]
    public void The_default_userinit_and_shell_are_benign()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,")
            .WithText(Winlogon, "Shell", @"C:\W\explorer.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid)
            .With(@"C:\W\explorer.exe", SignatureStatus.Valid);

        Assert.All(Collect(registry, signatures), f => Assert.Equal(FindingSeverity.Benign, f.Severity));
    }

    /// <summary>
    /// Un exécutable ajouté à Userinit est signalé même signé : c'est l'ajout à cet
    /// emplacement qui compte, une technique de persistance classique.
    /// </summary>
    [Fact]
    public void An_extra_userinit_entry_is_notable_even_when_signed()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,C:\evil\hook.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid)
            .With(@"C:\evil\hook.exe", SignatureStatus.Valid);

        var extra = Collect(registry, signatures).Single(f => f.Target.Contains("hook"));

        Assert.Equal(FindingSeverity.Notable, extra.Severity);
        Assert.Contains("inattendue", string.Join(" ", extra.Reasons));
    }

    /// <summary>
    /// Le même ajout, non signé, cumule les deux motifs et reste au moins suspect : la
    /// signature ne peut qu'aggraver, jamais abaisser.
    /// </summary>
    [Fact]
    public void An_extra_unsigned_userinit_entry_is_suspicious()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,C:\evil\hook.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid)
            .With(@"C:\evil\hook.exe", SignatureStatus.Unsigned);

        var extra = Collect(registry, signatures).Single(f => f.Target.Contains("hook"));

        Assert.Equal(FindingSeverity.Suspicious, extra.Severity);
    }

    /// <summary>
    /// Un shell qui n'est pas <c>explorer.exe</c> est signalé — le remplacer est un
    /// détournement d'ouverture de session.
    /// </summary>
    [Fact]
    public void A_shell_other_than_explorer_is_flagged()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Shell", @"C:\evil\shell.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\evil\shell.exe", SignatureStatus.Valid);

        Assert.Equal(FindingSeverity.Notable, Assert.Single(Collect(registry, signatures)).Severity);
    }

    /// <summary>
    /// Une DLL dans AppInit_DLLs est notable quelle que soit sa signature : le mécanisme
    /// injecte dans chaque processus graphique et n'a plus lieu d'être sur une machine
    /// moderne.
    /// </summary>
    [Fact]
    public void A_present_appinit_dll_is_notable_even_when_signed()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Windows, "AppInit_DLLs", @"C:\legit\hook.dll");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\legit\hook.dll", SignatureStatus.Valid);

        var finding = Assert.Single(Collect(registry, signatures));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("AppInit", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// AppInit_DLLs vide — le cas normal — ne produit aucun constat. L'absence de valeur
    /// est un état sain, pas une lacune.
    /// </summary>
    [Fact]
    public void An_empty_appinit_produces_no_finding()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid);

        // Seul Userinit est présent : aucun constat AppInit.
        Assert.DoesNotContain(Collect(registry, signatures), f => f.Source == "AppInit_DLLs");
    }
}
