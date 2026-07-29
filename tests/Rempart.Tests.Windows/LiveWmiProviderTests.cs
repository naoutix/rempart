using System.Runtime.InteropServices;
using Rempart.Core.Providers;
using Rempart.Windows.Wmi;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against the real WMI. Answers the question open since M0: System.Management does not
/// survive Native AOT, but the WMI COM interfaces stay accessible through interop
/// generated at compile time.
///
/// <para>
/// <b>These tests judge the decoding, not the runner's WMI.</b> A shared Windows runner
/// periodically answers every query with zero rows — five occurrences in one day, once on
/// a branch that changed no C# at all. That is a machine failing to answer, and failing
/// the build on it says nothing about Rempart. What must never be tolerated is the other
/// failure: WMI answering, and the decoding getting it wrong. So each test below asks
/// first whether WMI answered, and only then holds it to account.
/// </para>
/// <para>
/// A skipped check is stated on the test output rather than passing quietly: a test that
/// can pass vacuously has to say when it did, or it becomes a green light that means
/// nothing.
/// </para>
/// </summary>
public sealed class LiveWmiProviderTests(ITestOutputHelper output)
{
    private readonly LiveWmiProvider wmi = new();

    /// <summary>
    /// Whether WMI is answering at all on this machine, probed through a class every
    /// Windows installation carries. Zero rows here cannot mean "no such class": it means
    /// the service is not serving.
    /// </summary>
    private bool WmiAnswers(string reason)
    {
        var probe = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption"]);

        if (probe.Status == ReadStatus.Found && probe.Instances.Count > 0)
        {
            return true;
        }

        output.WriteLine(
            $"WMI n'a pas répondu sur cette machine (Win32_OperatingSystem -> {probe.Status}, "
            + $"{probe.Instances.Count} instance(s), diagnostic : {probe.Diagnostic ?? "aucun"}). "
            + $"Contrôle non exécuté : {reason}");

        return false;
    }

    [Fact]
    public void Reads_a_class_every_machine_has()
    {
        if (!WmiAnswers("lecture de Win32_OperatingSystem")) { return; }

        var read = wmi.Query(@"root\CIMV2", "Win32_OperatingSystem", ["Caption", "Version"]);

        Assert.Equal(ReadStatus.Found, read.Status);
        var os = Assert.Single(read.Instances);
        Assert.StartsWith("Microsoft Windows", os.Find("Caption")!, StringComparison.Ordinal);
        Assert.StartsWith("10.", os.Find("Version")!, StringComparison.Ordinal);
    }

    [Fact]
    public void Decodes_a_numeric_property()
    {
        // A wrong VARIANT decode would return a plausible but wrong value: that is
        // the failure mode to rule out.
        if (!WmiAnswers("décodage d'une propriété numérique")) { return; }

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
        // Guarded like the positive checks, and for a subtler reason: a mute WMI returns
        // NotFound for everything, so without the probe this test passes exactly when the
        // machine is broken. A green that survives the failure it should detect is worse
        // than no test.
        if (!WmiAnswers("classe inconnue rendue sans instance")) { return; }

        Assert.Equal(ReadStatus.NotFound,
            wmi.Query(@"root\CIMV2", "Win32_CetteClasseNExistePas", ["Rien"]).Status);
    }

    [Fact]
    public void Repeated_queries_stay_stable_and_do_not_leak()
    {
        // Each read allocates BSTRs and COM interfaces. A missing release is invisible
        // on a single call but exhausts a full scan.
        if (!WmiAnswers("stabilité de 30 lectures répétées")) { return; }

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
        // The BitLocker namespace requires elevation. Without rights, the denial must
        // be clean: the engine turns it into "not verifiable", never into a
        // non-compliance.
        var read = wmi.Query(
            @"root\CIMV2\Security\MicrosoftVolumeEncryption",
            "Win32_EncryptableVolume",
            ["DriveLetter", "ProtectionStatus"]);

        Assert.Contains(read.Status, new[] { ReadStatus.Found, ReadStatus.AccessDenied, ReadStatus.NotFound });
    }

    /// <summary>
    /// A COM failure carrying a chosen HRESULT, so that the three tests below judge the
    /// mapping rather than the runner's WMI. Synthesized because the codes that matter — a
    /// damaged repository, a service that will not start — cannot be provoked on a healthy
    /// machine, and the check above, which only asks that the status be one of three enum
    /// values, cannot tell any of them from a denial.
    /// </summary>
    private static COMException Com(uint hresult) =>
        new("échec COM simulé", unchecked((int)hresult));

    [Theory]
    [InlineData(0x80041010u)] // WBEM_E_INVALID_CLASS: damaged or partial repository
    [InlineData(0x800706BAu)] // RPC_S_SERVER_UNAVAILABLE: Winmgmt is not serving
    [InlineData(0x80041013u)] // WBEM_E_PROVIDER_LOAD_FAILURE
    [InlineData(0x80041045u)] // WBEM_E_SERVER_TOO_BUSY
    [InlineData(0x80041014u)] // WBEM_E_INITIALIZATION_FAILURE
    public void A_com_failure_names_its_hresult_instead_of_claiming_a_denial(uint hresult)
    {
        // Every one of these once returned WmiRead.AccessDenied with a null diagnostic, so
        // the four `type: wmi` rules — plus drivers, processes and unquoted service paths —
        // advised « relancer en administrateur » to a user who already was.
        var read = LiveWmiProvider.Classify(Com(hresult));

        Assert.NotNull(read.Diagnostic);
        Assert.Contains($"0x{hresult:X8}", read.Diagnostic, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0x80041003u)] // WBEM_E_ACCESS_DENIED
    [InlineData(0x80070005u)] // E_ACCESSDENIED
    [InlineData(0x80041062u)] // WBEM_E_PRIVILEGE_NOT_HELD
    public void A_genuine_refusal_stays_a_refusal_without_a_diagnostic(uint hresult)
    {
        // The counterpart: dropping one of these from the list would turn a real denial into
        // a failure, and « relancer en administrateur » would stop being said when it is the
        // right advice.
        var read = LiveWmiProvider.Classify(Com(hresult));

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Diagnostic);
    }

    [Theory]
    [InlineData(0x8004100Eu)] // WBEM_E_INVALID_NAMESPACE: feature absent from this edition
    [InlineData(0x80041002u)] // WBEM_E_NOT_FOUND
    public void An_absent_namespace_is_absence_not_refusal(uint hresult)
    {
        Assert.Equal(ReadStatus.NotFound, LiveWmiProvider.Classify(Com(hresult)).Status);
    }
}
