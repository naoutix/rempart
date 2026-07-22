using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Test machine réelle, sur le modèle de LiveDnsAndHostsProviderTests : on ne connaît pas
/// la config proxy du runner, on vérifie qu'elle se lit sans lever et reste cohérente.
/// </summary>
public sealed class LiveProxyProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var config = new LiveProxyProvider().Read();

        // Cohérence interne : un scope WinHTTP activé porte forcément un serveur décodé.
        Assert.NotNull(config);
        if (config.WinHttp.Enabled)
        {
            Assert.False(string.IsNullOrEmpty(config.WinHttp.Server));
        }
    }
}
