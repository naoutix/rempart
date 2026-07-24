using System.Xml.Linq;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads saved Wi-Fi profiles from their XML files.
///
/// <para>
/// Windows keeps each profile in cleartext under
/// <c>ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{interface}\{profile}.xml</c> —
/// one file per known network. The XML carries the SSID (<c>name</c>), the connection
/// mode (<c>connectionMode</c>: <c>auto</c> or <c>manual</c>), and the security
/// settings (<c>authentication</c>, <c>encryption</c>). It is read and decoded here;
/// the collector only sees <see cref="WifiProfile"/> instances, so replay does not
/// need the disk.
/// </para>
///
/// <para>
/// Elements are read by local name, without a namespace: the profile schema nests the
/// security section in a distinct namespace, and targeting the v1 namespace would miss
/// fields from later versions.
/// </para>
/// </summary>
public sealed class LiveWifiProfileProvider : IWifiProfileProvider
{
    private readonly string profilesRoot;

    public LiveWifiProfileProvider()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Wlansvc", "Profiles", "Interfaces"))
    {
    }

    public LiveWifiProfileProvider(string profilesRoot) => this.profilesRoot = profilesRoot;

    public IReadOnlyList<WifiProfile> Read()
    {
        var profiles = new List<WifiProfile>();

        if (!Directory.Exists(profilesRoot))
        {
            return profiles;
        }

        foreach (var file in SafeEnumerate(profilesRoot))
        {
            if (TryParse(file) is { } profile)
            {
                profiles.Add(profile);
            }
        }

        return profiles;
    }

    private static IEnumerable<string> SafeEnumerate(string root)
    {
        try
        {
            // Each interface has its own subdirectory; one profile per XML file.
            return Directory.EnumerateFiles(root, "*.xml", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Without elevation the directory may be denied: nothing is fabricated,
            // the rest of the scan material is still collected.
            return [];
        }
    }

    private static WifiProfile? TryParse(string file)
    {
        try
        {
            var document = XDocument.Parse(File.ReadAllText(file));

            var name = Local(document, "name");
            if (string.IsNullOrEmpty(name))
            {
                return null;
            }

            var mode = Local(document, "connectionMode");
            var auth = Local(document, "authentication") ?? string.Empty;
            var encryption = Local(document, "encryption") ?? string.Empty;

            return new WifiProfile(
                name,
                auth,
                encryption,
                AutoConnect: string.Equals(mode, "auto", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex)
            when (ex is System.Xml.XmlException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static string? Local(XDocument document, string localName) =>
        document.Descendants()
            .FirstOrDefault(element => element.Name.LocalName == localName)?.Value;
}
