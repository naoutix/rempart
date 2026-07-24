using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Real-machine test, on the LiveDnsAndHostsProviderTests model: the runner's proxy
/// config is unknown, so we check that it reads without throwing and stays consistent.
/// </summary>
public sealed class LiveProxyProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var config = new LiveProxyProvider().Read();

        // Internal consistency: an enabled WinHTTP scope always carries a decoded server.
        Assert.NotNull(config);
        if (config.WinHttp.Enabled)
        {
            Assert.False(string.IsNullOrEmpty(config.WinHttp.Server));
        }
    }
}
