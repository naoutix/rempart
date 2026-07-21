using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class UnquotedServicePathTests
{
    [Theory]
    // Non quoté, espace dans le chemin de l'exécutable → vulnérable.
    [InlineData(@"C:\Program Files\Éditeur\svc.exe", true)]
    [InlineData(@"C:\Program Files\App\svc.exe -k pool", true)]
    // Entre guillemets → sûr, quel que soit l'espace.
    [InlineData("\"C:\\Program Files\\App\\svc.exe\"", false)]
    // Espace seulement dans les arguments, pas dans le chemin → sûr.
    [InlineData(@"C:\Windows\system32\svchost.exe -k netsvcs -p", false)]
    // Aucun espace → sûr.
    [InlineData(@"C:\Windows\system32\lsass.exe", false)]
    // Pas d'exécutable .exe (pilote, forme inhabituelle) → hors périmètre.
    [InlineData(@"C:\Windows\system32\drivers\pilote.sys", false)]
    [InlineData("", false)]
    public void The_detection_flags_only_a_genuine_unquoted_path(string pathName, bool vulnerable)
    {
        Assert.Equal(vulnerable, UnquotedServicePathCollector.IsUnquotedWithSpace(pathName));
    }

    private static IReadOnlyList<Finding> Collect(WmiRead services) =>
        new UnquotedServicePathCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            wmi: new FakeWmiProvider(services)));

    private static WmiInstance Service(string name, string path) =>
        new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Name"] = name,
            ["PathName"] = path,
        });

    [Fact]
    public void A_vulnerable_service_produces_one_notable_finding()
    {
        var findings = Collect(WmiRead.Found(
        [
            Service("BonService", @"C:\Windows\system32\bon.exe -k pool"),
            Service("MauvaisService", @"C:\Program Files\Éditeur\mauvais.exe"),
        ]));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("MauvaisService", finding.Source);
        Assert.Contains("guillemets", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void Services_all_quoted_or_spaceless_produce_nothing()
    {
        var findings = Collect(WmiRead.Found(
        [
            Service("A", "\"C:\\Program Files\\App\\a.exe\""),
            Service("B", @"C:\Windows\system32\b.exe"),
        ]));

        Assert.Empty(findings);
    }

    /// <summary>
    /// Une énumération refusée n'est pas une absence de service vulnérable : c'est un
    /// trou dans l'audit, et il se dit.
    /// </summary>
    [Fact]
    public void An_access_denied_enumeration_is_reported()
    {
        var finding = Assert.Single(Collect(WmiRead.AccessDenied));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("refusée", string.Join(" ", finding.Reasons));
    }
}
