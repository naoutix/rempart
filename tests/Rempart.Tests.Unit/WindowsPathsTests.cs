using Rempart.Core.Findings;

namespace Rempart.Tests.Unit;

/// <summary>
/// The convention three collectors used to spell out separately. These tests exist less
/// to check string concatenation than to pin the property that made hard-coding the right
/// choice: the result must not depend on the machine running it, because a snapshot
/// captured on Windows is replayed on Linux in CI.
/// </summary>
public class WindowsPathsTests
{
    [Fact]
    public void Resolves_a_bare_name_into_System32()
    {
        Assert.Equal(@"C:\Windows\System32\lsass.dll", WindowsPaths.InSystem32("lsass.dll"));
    }

    [Fact]
    public void Resolves_a_bare_name_into_the_Windows_directory()
    {
        Assert.Equal(@"C:\Windows\explorer.exe", WindowsPaths.InWindows("explorer.exe"));
    }

    [Fact]
    public void Uses_backslashes_whatever_the_host_separator_is()
    {
        // The trap this replaces: Path.Combine on Linux yields "C:\Windows/System32/x",
        // which no comparison against a captured Windows path can match. Asserting the
        // absence of a forward slash is the whole point of the helper.
        Assert.DoesNotContain('/', WindowsPaths.InSystem32("x.dll"));
        Assert.DoesNotContain('/', WindowsPaths.InWindows("x.exe"));
    }
}
