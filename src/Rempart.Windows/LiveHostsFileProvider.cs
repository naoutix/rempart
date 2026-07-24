using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads the <c>hosts</c> file from disk.
///
/// <para>
/// Its location is fixed — <c>%SystemRoot%\System32\drivers\etc\hosts</c>. A missing or
/// unreadable file returns an empty list instead of an error: the scan of the other
/// surfaces must continue, and "no hosts file" is treated as "no entries", not as a
/// failure.
/// </para>
/// </summary>
public sealed class LiveHostsFileProvider : IHostsFileProvider
{
    public IReadOnlyList<string> ReadLines()
    {
        var root = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var path = $@"{root}\System32\drivers\etc\hosts";

        try
        {
            return File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
