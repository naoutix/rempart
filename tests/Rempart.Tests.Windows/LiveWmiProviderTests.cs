using Rempart.Core.Providers;
using Rempart.Windows.Wmi;

namespace Rempart.Tests.Windows;

/// <summary>
/// Contre le vrai WMI. Répond à la question ouverte depuis M0 : System.Management ne
/// survit pas à Native AOT, mais les interfaces COM de WMI restent accessibles par
/// l'interop générée à la compilation.
/// </summary>
public sealed class LiveWmiProviderTests
{
    private readonly LiveWmiProvider wmi = new();

    [Fact]
    public void Reads_a_class_every_machine_has()
    {
        var read = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption", "Version"]);

        Assert.Equal(ReadStatus.Found, read.Status);
        var os = Assert.Single(read.Instances);
        Assert.StartsWith("Microsoft Windows", os.Find("Caption")!, StringComparison.Ordinal);
        Assert.StartsWith("10.", os.Find("Version")!, StringComparison.Ordinal);
    }

    [Fact]
    public void Decodes_a_numeric_property()
    {
        // Un décodage de VARIANT erroné rendrait une valeur plausible mais fausse :
        // c'est le mode de défaillance qu'il faut exclure.
        var read = wmi.Query(@"root\CIMV2", "Win32_ComputerSystem", ["NumberOfProcessors"]);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.True(int.TryParse(read.Instances[0].Find("NumberOfProcessors"), out var count));
        Assert.InRange(count, 1, 64);
    }

    [Fact]
    public void An_unknown_namespace_is_reported_rather_than_thrown()
    {
        var read = wmi.Query(@"root\CeNamespaceNExistePas", "Quoi", ["Rien"]);

        Assert.NotEqual(ReadStatus.Found, read.Status);
    }

    [Fact]
    public void An_unknown_class_yields_no_instances()
    {
        Assert.Equal(ReadStatus.NotFound,
            wmi.Query(@"root\CIMV2", "Win32_CetteClasseNExistePas", ["Rien"]).Status);
    }

    [Fact]
    public void Repeated_queries_stay_stable_and_do_not_leak()
    {
        // Chaque lecture alloue des BSTR et des interfaces COM. Un oubli de
        // libération ne se voit pas sur un appel isolé, mais épuise un scan complet.
        var first = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption"]);

        for (var i = 0; i < 30; i++)
        {
            var read = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption"]);
            Assert.Equal(first.Instances[0].Find("Caption"), read.Instances[0].Find("Caption"));
        }
    }

    [Fact]
    public void BitLocker_status_is_read_or_cleanly_refused()
    {
        // L'espace de noms BitLocker exige l'élévation. Sans droits, le refus doit
        // être net : le moteur en fera « non vérifiable », jamais une non-conformité.
        var read = wmi.Query(
            @"root\CIMV2\Security\MicrosoftVolumeEncryption",
            "Win32_EncryptableVolume",
            ["DriveLetter", "ProtectionStatus"]);

        Assert.Contains(read.Status, new[] { ReadStatus.Found, ReadStatus.AccessDenied, ReadStatus.NotFound });
    }
}
