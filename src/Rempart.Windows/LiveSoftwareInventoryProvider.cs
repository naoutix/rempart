using Rempart.Core.Providers;
using Rempart.Core.Software;

namespace Rempart.Windows;

/// <summary>
/// Agrège l'inventaire logiciel de ses quatre sources autoritatives.
///
/// <para>
/// Uninstall, Appx et App Paths sont lus au registre via <see cref="IRegistryProvider"/>,
/// donc rejouables. Chocolatey énumère des dossiers, ce que l'abstraction de fichiers ne
/// fait pas : la lecture est directe, mais son résultat décodé part au snapshot comme le
/// reste (patron A2). Le collecteur ne voit que des <see cref="InstalledSoftware"/>.
/// </para>
/// </summary>
public sealed class LiveSoftwareInventoryProvider : ISoftwareInventoryProvider
{
    private static readonly string[] UninstallRoots =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    private const string AppxInstalled =
        @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    private const string AppxProvisioned =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications";

    private const string AppPaths =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";

    private readonly IRegistryProvider registry;
    private readonly string chocolateyLib;

    public LiveSoftwareInventoryProvider()
        : this(new LiveRegistryProvider(), @"C:\ProgramData\chocolatey\lib")
    {
    }

    public LiveSoftwareInventoryProvider(IRegistryProvider registry, string chocolateyLib)
    {
        this.registry = registry;
        this.chocolateyLib = chocolateyLib;
    }

    public IReadOnlyList<InstalledSoftware> Read()
    {
        var software = new List<InstalledSoftware>();

        ReadUninstall(software);
        ReadAppx(software);
        ReadAppPaths(software);
        ReadChocolatey(software);

        return software;
    }

    private void ReadUninstall(List<InstalledSoftware> software)
    {
        foreach (var root in UninstallRoots)
        {
            foreach (var key in registry.ListSubKeys(root))
            {
                var path = $@"{root}\{key}";
                var name = Text(path, "DisplayName");

                // Sans nom d'affichage, c'est une mise à jour ou un correctif, pas un
                // logiciel à part entière ; on l'écarte. Un composant système masqué
                // (SystemComponent=1) l'est aussi : ce n'est pas installé par l'utilisateur.
                if (string.IsNullOrWhiteSpace(name)
                    || registry.ReadValue(path, "SystemComponent").Value?.Number == 1)
                {
                    continue;
                }

                software.Add(new InstalledSoftware(
                    name, Text(path, "DisplayVersion"), Text(path, "Publisher"),
                    SoftwareSource.Uninstall, Provisioned: false, SurvivesFeatureUpdate: true,
                    Identifier: key));
            }
        }
    }

    private void ReadAppx(List<InstalledSoftware> software)
    {
        var provisioned = new HashSet<string>(registry.ListSubKeys(AppxProvisioned), StringComparer.OrdinalIgnoreCase);

        foreach (var fullName in registry.ListSubKeys(AppxInstalled))
        {
            var (name, version) = AppxPackageName.Parse(fullName);
            var isProvisioned = provisioned.Contains(fullName);

            software.Add(new InstalledSoftware(
                name, version, Publisher: null, SoftwareSource.Appx,
                Provisioned: isProvisioned,
                // Un paquet provisionné revient après une mise à jour de fonctionnalité ;
                // un paquet seulement installé par l'utilisateur peut disparaître.
                SurvivesFeatureUpdate: isProvisioned,
                Identifier: AppxPackageName.FamilyName(fullName)));
        }
    }

    private void ReadAppPaths(List<InstalledSoftware> software)
    {
        foreach (var exe in registry.ListSubKeys(AppPaths))
        {
            software.Add(new InstalledSoftware(
                exe, Version: null, Publisher: null, SoftwareSource.AppPath,
                Provisioned: false, SurvivesFeatureUpdate: true));
        }
    }

    private void ReadChocolatey(List<InstalledSoftware> software)
    {
        if (!Directory.Exists(chocolateyLib))
        {
            return;
        }

        try
        {
            foreach (var directory in Directory.EnumerateDirectories(chocolateyLib))
            {
                software.Add(new InstalledSoftware(
                    Path.GetFileName(directory), Version: null, Publisher: "Chocolatey",
                    SoftwareSource.Chocolatey, Provisioned: false, SurvivesFeatureUpdate: true));
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Refusé ou illisible : on n'invente rien, les autres sources restent collectées.
        }
    }

    private string? Text(string path, string value)
    {
        var read = registry.ReadValue(path, value);
        return read.Status == ReadStatus.Found ? read.Value?.Text : null;
    }
}
