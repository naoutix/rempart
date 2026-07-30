using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class UnquotedServicePathTests
{
    [Theory]
    // Unquoted, space in the executable path → vulnerable.
    [InlineData(@"C:\Program Files\Éditeur\svc.exe", true)]
    [InlineData(@"C:\Program Files\App\svc.exe -k pool", true)]
    // Quoted → safe, whatever the spaces.
    [InlineData("\"C:\\Program Files\\App\\svc.exe\"", false)]
    // Space only in the arguments, not in the path → safe.
    [InlineData(@"C:\Windows\system32\svchost.exe -k netsvcs -p", false)]
    // No space at all → safe.
    [InlineData(@"C:\Windows\system32\lsass.exe", false)]
    // No .exe executable (driver, unusual form) → out of scope.
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
    /// A denied enumeration is not an absence of vulnerable services: it is a hole in
    /// the audit, and it gets said.
    /// </summary>
    [Fact]
    public void An_access_denied_enumeration_is_reported()
    {
        var finding = Assert.Single(Collect(WmiRead.AccessDenied));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("refusée", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// The state between the two: <c>Win32_Service</c> answered for a while and then stopped.
    ///
    /// <para>
    /// This collector opened on « refused → return the finding », which threw away the
    /// services the walk had already handed over. A machine whose enumeration breaks after
    /// the vulnerable service would then be told its audit failed and nothing else, with the
    /// unquoted path sitting in the list that was dropped on the way out. The gap is
    /// reported <em>and</em> what was read is judged — the shape
    /// <c>ListeningPortsCollector</c> and <c>ScheduledTasksCollector</c> already take.
    /// </para>
    /// </summary>
    [Fact]
    public void A_truncated_enumeration_reports_the_gap_and_still_judges_what_it_read()
    {
        var findings = Collect(WmiRead.Partial(
            [
                Service("BonService", @"C:\Windows\system32\bon.exe -k pool"),
                Service("MauvaisService", @"C:\Program Files\Éditeur\mauvais.exe"),
            ],
            "L'énumération WMI de Win32_Service s'est interrompue sur 0x80041004."));

        Assert.Equal(2, findings.Count);

        var gap = Assert.Single(findings, f => f.Source == "Win32_Service");
        Assert.Contains("0x80041004", string.Join(" ", gap.Reasons), StringComparison.Ordinal);

        Assert.Single(findings, f => f.Source == "MauvaisService");
    }
}
