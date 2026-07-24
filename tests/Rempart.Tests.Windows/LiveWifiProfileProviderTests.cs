using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Real-machine test: the runner's saved networks are unknown, so we check that the read
/// does not throw and that what it returns is consistent.
/// </summary>
public sealed class LiveWifiProfileProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var profiles = new LiveWifiProfileProvider().Read();

        Assert.NotNull(profiles);
        // A profile that was read always carries a name (otherwise it is discarded).
        Assert.All(profiles, profile => Assert.False(string.IsNullOrEmpty(profile.Name)));
    }

    [Fact]
    public void Parses_a_profile_xml_from_a_temporary_directory()
    {
        var root = Path.Combine(Path.GetTempPath(), "rempart-wifi-" + Guid.NewGuid().ToString("N"));
        var interfaceDir = Path.Combine(root, "{00000000-0000-0000-0000-000000000000}");
        Directory.CreateDirectory(interfaceDir);
        try
        {
            File.WriteAllText(Path.Combine(interfaceDir, "profile.xml"),
                """
                <?xml version="1.0"?>
                <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
                  <name>MonReseau</name>
                  <connectionMode>auto</connectionMode>
                  <MSM><security><authEncryption>
                    <authentication>WPA2PSK</authentication>
                    <encryption>AES</encryption>
                  </authEncryption></security></MSM>
                </WLANProfile>
                """);

            var profile = Assert.Single(new LiveWifiProfileProvider(root).Read());

            Assert.Equal("MonReseau", profile.Name);
            Assert.Equal("WPA2PSK", profile.Authentication);
            Assert.Equal("AES", profile.Encryption);
            Assert.True(profile.AutoConnect);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
