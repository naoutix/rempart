namespace Rempart.Core.Providers;

/// <summary>
/// Reads the <c>hosts</c> file, line by line, unparsed.
///
/// <para>
/// The <c>hosts</c> file bypasses DNS: a mapping in it is consulted before any name
/// server. It is used from both sides — an ad blocker maps domains to a null address,
/// and malware redirects Windows Update to an address it controls. Parsing happens in
/// the core; the provider only returns the lines, so the judgment can be tested without
/// a file.
/// </para>
/// </summary>
public interface IHostsFileProvider
{
    IReadOnlyList<string> ReadLines();
}
