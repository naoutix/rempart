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
    /// The default packages are signed by Microsoft: benign. On a healthy machine,
    /// nothing to review.
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
    /// An unsigned DLL among the security packages is suspicious: it is the hallmark of
    /// persistent credential theft (a <c>mimilib</c> registered as an SSP).
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
    /// Windows records an empty list as the literal value <c>""</c>. That is not a
    /// package: no finding, and above all no invented, unfindable <c>"".dll</c>.
    /// </summary>
    [Fact]
    public void The_empty_list_marker_produces_no_finding()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Lsa, "Security Packages", "\"\"");

        Assert.Empty(Collect(registry, new FakeSignatureProvider()));
    }

    /// <summary>
    /// Several packages in a multi-string value are each judged on their own. The
    /// provider returns them joined by newlines.
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
    /// A list whose read was denied is not an empty list: that is exactly where an added
    /// package would hide. We say so, we do not stay silent.
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
