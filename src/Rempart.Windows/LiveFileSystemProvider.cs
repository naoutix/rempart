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
            // Un refus rend une liste vide : les autres emplacements comptent aussi.
            return [];
        }
    }
}
