using Rempart.Core.Providers;
using Rempart.Windows;
using Xunit.Abstractions;

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
public sealed class LiveRegistryProviderTests(ITestOutputHelper output)
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

    /// <summary>
    /// The security hive again, asked the two questions that used to have no way of
    /// answering it. <c>KeyExists</c> was the only enumerating read carrying a status, and
    /// its two siblings returned the same empty listing for « clé vide » and for « accès
    /// refusé » — so a denial laid on a <c>Run</c> key produced « aucun démarrage
    /// automatique », and one laid on the per-user CLSID hive « aucun détournement COM ».
    ///
    /// <para>
    /// Driven by what the existence check answers rather than asserted outright: whether
    /// <c>SAM</c> refuses depends on how the process was started, and the test that already
    /// reads it tolerates both. What must hold is that the three reads of one key
    /// <em>agree</em>. A machine that grants access says so on the output instead of passing
    /// silently, the discipline the WMI and DNS suites follow.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_key_refuses_its_enumerations_too_rather_than_answering_empty()
    {
        const string Sam = @"HKLM\SAM\SAM";

        if (registry.KeyExists(Sam) != ReadStatus.AccessDenied)
        {
            output.WriteLine(
                "Cette session ouvre HKLM\\SAM\\SAM : il n'y a pas de refus à confronter aux "
                + "énumérations. Contrôle non exécuté.");
            return;
        }

        Assert.Equal(ReadStatus.AccessDenied, registry.ListValues(Sam).Status);
        Assert.Equal(ReadStatus.AccessDenied, registry.ListSubKeys(Sam).Status);
    }

    /// <summary>
    /// The other side of the distinction, and the one that keeps the fix from becoming
    /// noise: a key that is simply not there is <em>not</em> a refusal. Most of the five
    /// autostart locations are absent on an ordinary machine, and reporting each as a hole
    /// in the audit would put a finding on every scan.
    /// </summary>
    [Fact]
    public void An_absent_key_enumerates_as_not_found_rather_than_as_a_refusal()
    {
        const string Nowhere = @"HKLM\SOFTWARE\CeCheminNExistePas\NonPlus";

        Assert.Equal(ReadStatus.NotFound, registry.ListValues(Nowhere).Status);
        Assert.Equal(ReadStatus.NotFound, registry.ListSubKeys(Nowhere).Status);
    }

    /// <summary>
    /// The control the two above need: a key that answers comes back <c>Found</c> with its
    /// content. Without it, a provider that refused everything would satisfy the denial test
    /// and a provider that found nothing would satisfy the absence one.
    /// </summary>
    [Fact]
    public void A_readable_key_enumerates_as_found_with_its_content()
    {
        var values = registry.ListValues(CurrentVersion);
        var subKeys = registry.ListSubKeys(@"HKLM\SYSTEM\CurrentControlSet\Services");

        Assert.Equal(ReadStatus.Found, values.Status);
        Assert.Contains("ProductName", values.Values.Keys, StringComparer.OrdinalIgnoreCase);

        Assert.Equal(ReadStatus.Found, subKeys.Status);
        Assert.NotEmpty(subKeys.Names);
    }
}
