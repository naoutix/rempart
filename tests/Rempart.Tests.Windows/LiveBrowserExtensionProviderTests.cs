using Rempart.Windows;

namespace Rempart.Tests.Windows;

public class LiveBrowserExtensionProviderTests
{
    // Non-deterministic ground: a CI runner may have no browser profile at all. The
    // decoding logic is unit-tested against captured file shapes; this guards the
    // I/O path — it must not throw, and what it returns must be well-formed.
    [Fact]
    public void Read_does_not_throw_and_returns_wellformed_entries()
    {
        var extensions = new LiveBrowserExtensionProvider().Read();

        Assert.All(extensions, e =>
        {
            Assert.False(string.IsNullOrEmpty(e.Browser));
            Assert.False(string.IsNullOrEmpty(e.Profile));
            Assert.False(string.IsNullOrEmpty(e.Id));
            Assert.False(string.IsNullOrEmpty(e.Name));
            Assert.False(string.IsNullOrEmpty(e.Version));

            // Never a path: a profile name must not leak the Windows user name.
            Assert.DoesNotContain('\\', e.Profile);
            Assert.DoesNotContain('/', e.Profile);
        });
    }
}
