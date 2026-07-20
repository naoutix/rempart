using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Contre de vrais binaires. La verification Authenticode est ce qui distingue un
/// programme legitime lance au demarrage d'un executable depose la par un tiers :
/// un chemin et un nom s'imitent trivialement, une signature non.
/// </summary>
public sealed class LiveSignatureProviderTests
{
    private readonly LiveSignatureProvider signatures = new();

    [Fact]
    public void A_windows_binary_verifies_as_valid()
    {
        var result = signatures.Verify(Path.Combine(
            Environment.SystemDirectory, "kernel32.dll"));

        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.NotNull(result.Sha256);
    }

    [Fact]
    public void A_catalog_signed_binary_has_no_embedded_publisher()
    {
        // Les binaires systeme sont signes par catalogue, pas par certificat
        // embarque : WinVerifyTrust les valide, mais il n'y a rien a lire dans le
        // fichier. L'editeur reste donc renseigne pour les binaires tiers, qui
        // portent presque toujours une signature embarquee -- et ce sont eux qui
        // comptent dans une enumeration de demarrages automatiques.
        var result = signatures.Verify(Path.Combine(
            Environment.SystemDirectory, "kernel32.dll"));

        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.Null(result.Publisher);
    }

    [Fact]
    public void An_unsigned_file_is_reported_unsigned_not_unknown()
    {
        // La distinction porte tout le constat : « pas signe » est un fait,
        // « je n'ai pas pu verifier » est une lacune.
        var path = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);

        try
        {
            Assert.Equal(SignatureStatus.Unsigned, signatures.Verify(path).Status);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_missing_file_is_distinguished_from_an_unsigned_one()
    {
        // Une entree de demarrage pointant vers un fichier absent est elle-meme un
        // constat : reste d'une desinstallation, ou cible d'un detournement futur.
        Assert.Equal(SignatureStatus.FileNotFound,
            signatures.Verify(@"C:\CeFichierNExistePas\rien.exe").Status);
    }

    [Fact]
    public void The_hash_is_stable_across_reads()
    {
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        Assert.Equal(signatures.Verify(path).Sha256, signatures.Verify(path).Sha256);
    }

    [Fact]
    public void Repeated_verifications_do_not_exhaust_state()
    {
        // WinVerifyTrust alloue un etat que seul un second appel libere. Un oubli ne
        // se voit pas sur un fichier isole, mais epuise l'enumeration complete des
        // demarrages automatiques.
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        for (var i = 0; i < 60; i++)
        {
            Assert.Equal(SignatureStatus.Valid, signatures.Verify(path).Status);
        }
    }
}
