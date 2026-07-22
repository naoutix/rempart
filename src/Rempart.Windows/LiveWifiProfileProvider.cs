using System.Xml.Linq;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Lit les profils Wi-Fi enregistrés depuis leurs fichiers XML.
///
/// <para>
/// Windows conserve chaque profil en clair sous
/// <c>ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{interface}\{profil}.xml</c> —
/// un fichier par réseau connu. Le XML porte le SSID (<c>name</c>), le mode de connexion
/// (<c>connectionMode</c> : <c>auto</c> ou <c>manual</c>) et la sécurité
/// (<c>authentication</c>, <c>encryption</c>). On le lit et on le décode ici ; le
/// collecteur ne voit que des <see cref="WifiProfile"/>, donc le rejeu n'a pas besoin du
/// disque.
/// </para>
///
/// <para>
/// La lecture des éléments se fait par nom local, sans namespace : le schéma de profil
/// imbrique la sécurité dans un espace de noms distinct, et cibler le namespace v1
/// raterait les champs des versions ultérieures.
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
            // Chaque interface a son sous-dossier ; un profil par fichier XML.
            return Directory.EnumerateFiles(root, "*.xml", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Sans élévation, le dossier peut être refusé : on n'invente rien, l'autre
            // matière du scan reste collectée.
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
