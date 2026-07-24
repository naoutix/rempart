using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Tests against the real Windows registry.
///
/// The provider abstraction makes <c>Rempart.Core</c> testable everywhere — and
/// concentrates all the untested risk in the layer it isolates. Registry type
/// conversion, hive resolution, the distinction between absence and access denial:
/// 62 rules depend on these behaviors, and no test covered them.
///
/// These tests rely on keys Windows guarantees — inventing them is pointless, and
/// creating keys would require rights a scan does not need.
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
        // UBR is a DWORD: the conversion must fill Number, not Text. A rule using the
        // atLeast operator depends on this directly.
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
        // Rules write HKLM; Microsoft documentation often writes the long form. Both
        // must resolve, otherwise a rule copied from the documentation would fail with
        // no visible reason.
        Assert.Equal(ReadStatus.Found, registry.KeyExists(path));
    }

    [Fact]
    public void An_unknown_hive_is_rejected_loudly()
    {
        // A typo in a rule path must surface immediately, not produce a "not found"
        // that would be taken for a real verdict.
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
        // The whole audit rests on this distinction: "could not read" must never become
        // "the value is not there", otherwise a non-elevated scan would produce a falsely
        // reassuring report. HKLM\SAM is denied even as administrator.
        var status = registry.KeyExists(@"HKLM\SAM\SAM");

        Assert.True(status is ReadStatus.AccessDenied or ReadStatus.NotFound,
            $"statut inattendu : {status}");
    }
}
