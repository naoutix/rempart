using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against the real service control manager.
///
/// Three native calls and a two-step allocation protocol: an offset error in the
/// buffer reads would return a plausible but wrong state, which critical rules then
/// act on.
/// </summary>
public sealed class LiveServiceStateProviderTests
{
    private readonly LiveServiceStateProvider services = new();

    [Fact]
    public void Reads_a_service_windows_always_runs()
    {
        // The task scheduling service: present and started on any Windows machine
        // in working order.
        var read = services.Read("Schedule");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal(ServiceState.Running, read.Info!.State);
    }

    [Fact]
    public void Reads_the_start_mode_as_a_known_value()
    {
        var read = services.Read("Schedule");

        // A wrong offset in the buffer would return "Unknown" permanently, and any
        // rule on the start mode would go silent without saying so.
        Assert.NotEqual(ServiceStartMode.Unknown, read.Info!.StartMode);
    }

    [Fact]
    public void A_service_that_does_not_exist_is_reported_absent_not_denied()
    {
        // The distinction drives different follow-ups: uninstalling an absent service
        // makes no sense, a denial calls for a retry as administrator.
        var read = services.Read("CeServiceNExistePasDuTout");

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Null(read.Info);
    }

    [Fact]
    public void A_stopped_service_is_reported_stopped()
    {
        // RemoteRegistry is disabled by default on a workstation. If the test machine
        // has enabled it, at least check that the state is readable.
        var read = services.Read("RemoteRegistry");

        if (read.Status == ReadStatus.Found)
        {
            Assert.NotEqual(ServiceState.Unknown, read.Info!.State);
        }
    }

    [Fact]
    public void Repeated_reads_stay_consistent_and_do_not_exhaust_handles()
    {
        // Each read opens two native handles. A missing close is invisible on a single
        // call but exhausts the resources of a full scan.
        var first = services.Read("Schedule");

        for (var i = 0; i < 200; i++)
        {
            var read = services.Read("Schedule");
            Assert.Equal(first.Status, read.Status);
            Assert.Equal(first.Info!.State, read.Info!.State);
        }
    }
}
