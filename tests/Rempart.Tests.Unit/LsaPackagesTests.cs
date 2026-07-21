using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class LsaPackagesTests
{
    private const string Lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

    private static IReadOnlyList<Finding> Collect(
        FakeRegistryProvider registry, ISignatureProvider signatures) =>
        new LsaPackagesCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), signatures: signatures));

    /// <summary>
    /// Les paquets par défaut sont signés par Microsoft : bénins. Sur une machine saine,
    /// rien à examiner.
    /// </summary>
    [Fact]
    public void Signed_default_packages_are_benign()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Lsa, "Authentication Packages", "msv1_0")
            .WithText(Lsa, "Notification Packages", "scecli");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\Windows\System32\msv1_0.dll", SignatureStatus.Valid)
            .With(@"C:\Windows\System32\scecli.dll", SignatureStatus.Valid);

        Assert.All(Collect(registry, signatures), f => Assert.Equal(FindingSeverity.Benign, f.Severity));
    }

    /// <summary>
    /// Une DLL non signée dans un paquet de sécurité est suspecte : c'est la marque d'un
    /// vol d'identifiants persistant (un <c>mimilib</c> enregistré comme SSP).
    /// </summary>
    [Fact]
    public void An_unsigned_package_is_suspicious()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Lsa, "Security Packages", "mimilib");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\Windows\System32\mimilib.dll", SignatureStatus.Unsigned);

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(Collect(registry, signatures)).Severity);
    }

    /// <summary>
    /// Windows note une liste vide par la valeur littérale <c>""</c>. Ce n'est pas un
    /// paquet : aucun constat, et surtout pas un <c>"".dll</c> introuvable inventé.
    /// </summary>
    [Fact]
    public void The_empty_list_marker_produces_no_finding()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Lsa, "Security Packages", "\"\"");

        Assert.Empty(Collect(registry, new FakeSignatureProvider()));
    }

    /// <summary>
    /// Plusieurs paquets dans une valeur multi-chaîne sont jugés chacun. Le provider les
    /// rend joints par des sauts de ligne.
    /// </summary>
    [Fact]
    public void Multiple_packages_in_a_multistring_are_each_judged()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Lsa, "Authentication Packages", "msv1_0\nkerberos\nwdigest");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\Windows\System32\msv1_0.dll", SignatureStatus.Valid)
            .With(@"C:\Windows\System32\kerberos.dll", SignatureStatus.Valid)
            .With(@"C:\Windows\System32\wdigest.dll", SignatureStatus.Unsigned);

        var findings = Collect(registry, signatures);

        Assert.Equal(3, findings.Count);
        Assert.Single(findings, f => f.Severity == FindingSeverity.Suspicious);
    }

    /// <summary>
    /// Une liste refusée à la lecture n'est pas une liste vide : c'est justement là qu'un
    /// paquet ajouté se cacherait. On le dit, on ne se tait pas.
    /// </summary>
    [Fact]
    public void An_access_denied_list_is_reported_never_silent()
    {
        var registry = new FakeRegistryProvider()
            .WithAccessDenied(Lsa, "Authentication Packages");

        var finding = Assert.Single(Collect(registry, new FakeSignatureProvider()));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("refusée", string.Join(" ", finding.Reasons));
    }
}
