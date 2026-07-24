using Rempart.Core.Providers;

namespace Rempart.Windows;

public sealed class LiveFileSystemProvider : IFileSystemProvider
{
    public IReadOnlyList<string> ListFiles(string directory)
    {
        try
        {
            return Directory.Exists(directory)
                ? Directory.GetFiles(directory)
                : [];
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Access denial returns an empty list: the other locations still need scanning.
            return [];
        }
    }
}
