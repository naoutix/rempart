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
    /// Un composant COM enregistré côté utilisateur est notable même signé : l'emplacement
    /// inscriptible sans privilège en fait le vecteur, pas la nature du binaire.
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
    /// Une valeur <c>LocalServer32</c> est une ligne de commande : le chemin quoté et ses
    /// arguments doivent être démêlés, sans quoi l'exécutable ressort introuvable — un faux
    /// positif observé en vrai sur l'entrée d'Adobe.
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
    /// Une DLL sous WindowsApps est non signée au niveau fichier mais signée par son
    /// paquet MSIX. Le constat reste notable — c'est un COM utilisateur — mais pas
    /// suspect : Windows garantit que le paquet est vérifié.
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
        // Notable via le plancher COM, mais pas suspect : la signature MSIX prime.
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("MSIX", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void No_per_user_clsid_produces_no_finding()
    {
        Assert.Empty(Collect(new FakeRegistryProvider(), new FakeSignatureProvider()));
    }
}
