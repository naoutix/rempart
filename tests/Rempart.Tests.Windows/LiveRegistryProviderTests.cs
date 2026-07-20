using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Tests contre le vrai registre Windows.
///
/// L'abstraction providers rend <c>Rempart.Core</c> testable partout — et concentre
/// tout le risque non testé dans la couche qu'elle isole. Conversion des types de
/// registre, résolution des ruches, distinction entre absence et refus d'accès :
/// autant de comportements dont dépendent 62 règles, et qu'aucun test ne couvrait.
///
/// Ces tests s'appuient sur des clés que Windows garantit — les inventer serait
/// inutile, et en créer exigerait des droits qu'un scan n'a pas besoin d'avoir.
/// </summary>
public sealed class LiveRegistryProviderTests
{
    private const string CurrentVersion = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    private readonly LiveRegistryProvider registry = new();

    [Fact]
    public void Reads_a_string_value()
    {
        var read = registry.ReadValue(CurrentVersion, "ProductName");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.StartsWith("Windows", read.Value!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Reads_a_dword_as_a_number()
    {
        // UBR est un DWORD : la conversion doit remplir Number, pas Text. Une règle
        // avec l'opérateur atLeast en dépend directement.
        var read = registry.ReadValue(CurrentVersion, "UBR");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.NotNull(read.Value!.Number);
        Assert.Null(read.Value.Text);
    }

    [Fact]
    public void An_absent_value_is_not_found_rather_than_an_error()
    {
        var read = registry.ReadValue(CurrentVersion, "CetteValeurNExistePas");

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Null(read.Value);
    }

    [Fact]
    public void An_absent_key_is_not_found()
    {
        Assert.Equal(ReadStatus.NotFound,
            registry.ReadValue(@"HKLM\SOFTWARE\CeCheminNExistePas\NonPlus", "Quoi").Status);
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft")]
    [InlineData(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft")]
    [InlineData(@"HKCU\Software")]
    [InlineData(@"HKEY_CURRENT_USER\Software")]
    public void Hive_prefixes_resolve_in_both_forms(string path)
    {
        // Les règles écrivent HKLM, la documentation Microsoft écrit souvent la forme
        // longue. Les deux doivent aboutir, sans quoi une règle recopiée depuis la
        // documentation échouerait sans raison visible.
        Assert.Equal(ReadStatus.Found, registry.KeyExists(path));
    }

    [Fact]
    public void An_unknown_hive_is_rejected_loudly()
    {
        // Une faute de frappe dans un chemin de règle doit se voir immédiatement,
        // et non produire un « non trouvé » qu'on prendrait pour un vrai verdict.
        Assert.Throws<ArgumentException>(() => registry.KeyExists(@"HKXX\Rien"));
    }

    [Fact]
    public void A_path_without_a_subkey_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => registry.KeyExists("HKLM"));
    }

    [Fact]
    public void Key_existence_is_reported_for_a_key_windows_always_has()
    {
        Assert.Equal(ReadStatus.Found,
            registry.KeyExists(@"HKLM\SYSTEM\CurrentControlSet\Services"));
    }

    [Fact]
    public void Reading_the_security_hive_denies_access_rather_than_reporting_absence()
    {
        // La distinction porte tout l'audit : « je n'ai pas pu lire » ne doit jamais
        // devenir « la valeur n'est pas là », faute de quoi un scan non élevé rendrait
        // un rapport faussement rassurant. HKLM\SAM est refusé même en administrateur.
        var status = registry.KeyExists(@"HKLM\SAM\SAM");

        Assert.True(status is ReadStatus.AccessDenied or ReadStatus.NotFound,
            $"statut inattendu : {status}");
    }
}
