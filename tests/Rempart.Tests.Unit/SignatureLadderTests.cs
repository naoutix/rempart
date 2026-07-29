using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// The ladder is shared by every persistence collector — autoruns, scheduled tasks,
/// drivers, processes, LSA packages, COM hijacking, Winlogon/AppInit, listening ports —
/// so a hole here is a hole in all eight at once. It had no tests of its own until this
/// file: the MSIX exemption was only ever exercised through <c>ComHijackTests</c>, with
/// the legitimate path, which is how it stayed unanchored.
/// </summary>
public class SignatureLadderTests
{
    private static SignatureJudgement Judge(string path, SignatureStatus status) =>
        SignatureLadder.Judge(path, new FakeSignatureProvider().With(path, status));

    /// <summary>
    /// The defect this file was written for. The exemption used to be a substring
    /// search, so any directory named <c>WindowsApps</c> — including one created in a
    /// profile, where no privilege is needed — turned an unsigned binary benign and
    /// skipped the unusual-location escalation on the way out.
    /// </summary>
    [Fact]
    public void An_unsigned_binary_under_a_windowsapps_folder_anyone_can_create_stays_suspicious()
    {
        var judgement = Judge(
            @"C:\Users\claire\AppData\Local\Temp\WindowsApps\updater.exe",
            SignatureStatus.Unsigned);

        Assert.Equal(FindingSeverity.Suspicious, judgement.Severity);
        Assert.DoesNotContain("MSIX", string.Join(" ", judgement.Reasons));
    }

    /// <summary>
    /// The other half of the same defect: the exemption returned early, so a binary that
    /// slipped through it was never measured against the unusual-location list either.
    /// A fake store inside Temp has to collect both remarks, not neither.
    /// </summary>
    [Fact]
    public void A_binary_that_is_not_in_a_package_store_is_still_measured_against_its_location()
    {
        var judgement = Judge(
            @"C:\Users\claire\AppData\Local\Temp\WindowsApps\updater.exe",
            SignatureStatus.Unsigned);

        Assert.Contains("emplacement inhabituel", string.Join(" ", judgement.Reasons));
    }

    /// <summary>
    /// The case the exemption exists for, and which must keep working: marking every
    /// Store application suspicious would be the false positive this project refuses.
    /// </summary>
    [Fact]
    public void An_unsigned_binary_in_the_system_package_store_is_benign()
    {
        var judgement = Judge(
            @"C:\Program Files\WindowsApps\Éditeur.App_1.0_x64__8wekyb3d8bbwe\app.exe",
            SignatureStatus.Unsigned);

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
        Assert.Contains("MSIX", string.Join(" ", judgement.Reasons));
    }

    [Fact]
    public void The_32_bit_package_store_is_a_package_store_too()
    {
        var judgement = Judge(
            @"C:\Program Files (x86)\WindowsApps\Éditeur.App_1.0\app.exe",
            SignatureStatus.Unsigned);

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
    }

    /// <summary>
    /// Store applications can be installed to another volume, and that volume declares
    /// its own store at its root — <c>Get-AppxVolume</c> reports a <c>PackageStorePath</c>
    /// per volume. Anchoring on <c>%ProgramFiles%</c> alone would have accused every
    /// application on such a machine.
    /// </summary>
    [Fact]
    public void A_package_store_at_the_root_of_another_volume_is_a_package_store()
    {
        var judgement = Judge(
            @"D:\WindowsApps\Éditeur.App_1.0\app.exe",
            SignatureStatus.Unsigned);

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
    }

    /// <summary>
    /// A signed binary is benign wherever it sits in a store, and the exemption must not
    /// be what decides that — it only ever concerned unsigned files.
    /// </summary>
    [Fact]
    public void A_signed_binary_owes_nothing_to_the_package_store_exemption()
    {
        var judgement = Judge(@"C:\Program Files\Éditeur\app.exe", SignatureStatus.Valid);

        Assert.Equal(FindingSeverity.Benign, judgement.Severity);
        Assert.Empty(judgement.Reasons);
    }
}
