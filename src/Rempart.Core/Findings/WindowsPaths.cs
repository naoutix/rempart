namespace Rempart.Core.Findings;

/// <summary>
/// The canonical Windows locations a bare name resolves to, spelled once.
///
/// <para>
/// Three collectors — COM hijacking, LSA packages, logon extensibility — each carried
/// their own copy of <c>C:\Windows\System32\</c> and their own paragraph explaining why it
/// was hard-coded. The explanation is the interesting part and it belongs in one place.
/// </para>
///
/// <para>
/// <b>Deliberately hard-coded, and deliberately not using <c>System.IO.Path</c>.</b>
/// Resolution must not consult the disk or the host: a snapshot captured on Windows is
/// replayed on Linux in CI, where <c>Path.Combine</c> would produce forward slashes and
/// the real Windows directory does not exist. A path that resolved differently on the
/// replaying machine would make a fixture depend on where it runs — the same separator
/// trap already hit once with the drivers.
/// </para>
///
/// <para>
/// The cost is accepted: a machine whose Windows lives elsewhere than <c>C:\Windows</c>
/// gets a path that does not exist, and the finding says the target was not found rather
/// than claiming something false about it.
/// </para>
/// </summary>
public static class WindowsPaths
{
    public const string WindowsDirectory = @"C:\Windows";

    public const string System32Directory = @"C:\Windows\System32";

    /// <summary>Resolves a bare file name to its System32 location.</summary>
    public static string InSystem32(string name) => System32Directory + @"\" + name;

    /// <summary>
    /// Resolves a bare file name to the Windows directory itself — where
    /// <c>explorer.exe</c> lives, assuming System32 for it once made the shell come out
    /// as "file not found".
    /// </summary>
    public static string InWindows(string name) => WindowsDirectory + @"\" + name;
}
