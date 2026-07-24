using Rempart.Core.Providers;
using Rempart.Core.Software;

namespace Rempart.Windows;

/// <summary>
/// Aggregates the software inventory from its four authoritative sources.
///
/// <para>
/// Uninstall, Appx, and App Paths are read from the registry via
/// <see cref="IRegistryProvider"/>, so they are replayable. Chocolatey enumerates
/// directories, which the file abstraction does not do: the read is direct, but its
/// decoded result goes into the snapshot like the rest (pattern A2). The collector
/// only sees <see cref="InstalledSoftware"/> instances.
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

                // Without a display name it is an update or a hotfix, not a standalone
                // application; skip it. A hidden system component (SystemComponent=1)
                // is skipped too: it was not installed by the user.
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
                // A provisioned package comes back after a feature update; a package
                // installed only by the user can disappear.
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
            // Denied or unreadable: nothing is fabricated, the other sources are still collected.
        }
    }

    private string? Text(string path, string value)
    {
        var read = registry.ReadValue(path, value);
        return read.Status == ReadStatus.Found ? read.Value?.Text : null;
    }
}
