using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class ComHijackTests
{
    private const string Clsid = @"HKCU\Software\Classes\CLSID";

    private static IReadOnlyList<Finding> Collect(
        FakeRegistryProvider registry, ISignatureProvider signatures) =>
        new ComHijackCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), signatures: signatures));

    /// <summary>
    /// A COM component registered per-user is notable even when signed: the location,
    /// writable without privilege, is what makes the vector — not the nature of the binary.
    /// </summary>
    [Fact]
    public void A_per_user_com_server_is_notable_even_when_signed()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Clsid, "{1111}")
            .WithText($@"{Clsid}\{{1111}}\InprocServer32", "", @"C:\App\legit.dll");

        var signatures = new FakeSignatureProvider().With(@"C:\App\legit.dll", SignatureStatus.Valid);

        var finding = Assert.Single(Collect(registry, signatures));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("prime sur", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void An_unsigned_per_user_com_server_is_suspicious()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Clsid, "{2222}")
            .WithText($@"{Clsid}\{{2222}}\InprocServer32", "", @"C:\evil\hook.dll");

        var signatures = new FakeSignatureProvider().With(@"C:\evil\hook.dll", SignatureStatus.Unsigned);

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(Collect(registry, signatures)).Severity);
    }

    /// <summary>
    /// A <c>LocalServer32</c> value is a command line: the quoted path and its arguments
    /// must be untangled, otherwise the executable comes out as missing — a false positive
    /// observed in the wild on Adobe's entry.
    /// </summary>
    [Fact]
    public void A_local_server_command_line_is_reduced_to_its_executable()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Clsid, "{3333}")
            .WithText($@"{Clsid}\{{3333}}\LocalServer32", "",
                "\"C:\\Program Files\\Éditeur\\app.exe\" -ToastActivated");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\Program Files\Éditeur\app.exe", SignatureStatus.Valid);

        var finding = Assert.Single(Collect(registry, signatures));
        Assert.Equal(@"C:\Program Files\Éditeur\app.exe", finding.Target);
        Assert.Equal("Valid", finding.Details["signature"]);
    }

    /// <summary>
    /// A DLL under WindowsApps is unsigned at the file level but signed through its MSIX
    /// package. The finding stays notable — it is a per-user COM — but not suspicious:
    /// Windows guarantees the package is verified.
    /// </summary>
    [Fact]
    public void A_windowsapps_binary_is_not_treated_as_unsigned()
    {
        var registry = new FakeRegistryProvider()
            .WithSubKeys(Clsid, "{4444}")
            .WithText($@"{Clsid}\{{4444}}\LocalServer32", "",
                @"C:\Program Files\WindowsApps\Éditeur.App_1.0\app.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\Program Files\WindowsApps\Éditeur.App_1.0\app.exe", SignatureStatus.Unsigned);

        var finding = Assert.Single(Collect(registry, signatures));
        // Notable via the COM floor, but not suspicious: the MSIX signature prevails.
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("MSIX", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void No_per_user_clsid_produces_no_finding()
    {
        Assert.Empty(Collect(new FakeRegistryProvider(), new FakeSignatureProvider()));
    }
}
