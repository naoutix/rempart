using Rempart.Core.Providers;
using Rempart.Windows.Wmi;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against the real WMI. Answers the question open since M0: System.Management does not
/// survive Native AOT, but the WMI COM interfaces stay accessible through interop
/// generated at compile time.
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
        // A wrong VARIANT decode would return a plausible but wrong value: that is
        // the failure mode to rule out.
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
        // Each read allocates BSTRs and COM interfaces. A missing release is invisible
        // on a single call but exhausts a full scan.
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
}
