namespace Rempart.Core.Providers;

/// <summary>
/// Lists the files of a directory.
///
/// Abstracted for the same reason as the registry (ADR-001, D5): a snapshot must be
/// replayable offline, and a directory enumeration is part of what a scan observes.
/// </summary>
public interface IFileSystemProvider
{
    /// <summary>
    /// Files in the directory, as full paths. Empty if the directory does not exist or
    /// is not readable — enumeration of the other locations must continue.
    /// </summary>
    IReadOnlyList<string> ListFiles(string directory);
}
