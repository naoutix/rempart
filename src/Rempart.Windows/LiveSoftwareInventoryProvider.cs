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
    private readonly Func<string, string[]> chocolateyPackages;

    public LiveSoftwareInventoryProvider()
        : this(new LiveRegistryProvider(), @"C:\ProgramData\chocolatey\lib")
    {
    }

    /// <param name="enumerate">
    /// How the Chocolatey library is listed, <c>Directory.GetDirectories</c> in production.
    ///
    /// <para>
    /// A parameter for the reason <see cref="LiveFileSystemProvider"/> takes one, and it is the
    /// reason #173 stayed open through three rounds there: the mapping below —
    /// <c>UnauthorizedAccessException</c> to a denial, <c>IOException</c> to a failure — is a
    /// contract nothing else states, and a real directory can be staged as <em>refused</em> but
    /// not as <em>failing</em>. Without the seam, the branch that names the defect is the one
    /// branch no test can enter.
    /// </para>
    /// </param>
    public LiveSoftwareInventoryProvider(
        IRegistryProvider registry, string chocolateyLib, Func<string, string[]>? enumerate = null)
    {
        this.registry = registry;
        this.chocolateyLib = chocolateyLib;
        chocolateyPackages = enumerate ?? Directory.GetDirectories;
    }

    /// <summary>
    /// The four sources, and what each of them could not read.
    ///
    /// <para>
    /// The two gap lists are threaded through rather than thrown away, which is the whole of
    /// #184 on this surface: six registry enumerations and one directory listing feed one
    /// inventory, each could answer « refusé » since REV-11, and the return type had nowhere
    /// to say so — an ACL on the uninstall keys produced the same empty list as a machine with
    /// nothing installed. Kept apart by cause, because the advice differs: a denial is repaired
    /// by elevating and an I/O failure is not.
    /// </para>
    ///
    /// <para>
    /// A denial anywhere makes the whole read a refusal even when something else also broke,
    /// and the sentence names both sources. Ranking it the other way would drop the one piece
    /// of advice that works on part of the hole; the reader is told what was lost either way.
    /// </para>
    /// </summary>
    public SoftwareInventoryRead Read()
    {
        var software = new List<InstalledSoftware>();
        var denied = new List<string>();
        var unreadable = new List<string>();

        ReadUninstall(software, denied);
        ReadAppx(software, denied);
        ReadAppPaths(software, denied);
        ReadChocolatey(software, denied, unreadable);

        if (denied.Count > 0)
        {
            return SoftwareInventoryRead.Refused(software, [.. denied, .. unreadable]);
        }

        return unreadable.Count > 0
            ? SoftwareInventoryRead.Failed(software, unreadable)
            : SoftwareInventoryRead.Found(software);
    }

    /// <summary>
    /// The names of a key's subkeys, noting the path when the enumeration was denied.
    ///
    /// <para>
    /// <c>NotFound</c> is not noted and is not a hole: <c>WOW6432Node</c> is absent on an ARM
    /// installation and the per-user uninstall key on a fresh profile, and calling either of
    /// them a gap would put a NOTABLE on ordinary machines.
    /// </para>
    /// </summary>
    private IReadOnlyList<string> SubKeys(string keyPath, List<string> denied)
    {
        var listing = registry.ListSubKeys(keyPath);

        if (listing.Status is ReadStatus.AccessDenied)
        {
            denied.Add(keyPath);
        }

        return listing.Names;
    }

    private void ReadUninstall(List<InstalledSoftware> software, List<string> denied)
    {
        foreach (var root in UninstallRoots)
        {
            foreach (var key in SubKeys(root, denied))
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

    private void ReadAppx(List<InstalledSoftware> software, List<string> denied)
    {
        var provisioned = new HashSet<string>(
            SubKeys(AppxProvisioned, denied), StringComparer.OrdinalIgnoreCase);

        // A leftover scale or language asset is not an installed application, and the
        // repository keeps one long after its package is gone. Of what remains, an
        // updated package leaves its older versions registered: one row per identity,
        // the highest version, architectures kept apart.
        var installed = AppxPackageName.LatestPerIdentity(
            SubKeys(AppxInstalled, denied)
                .Where(fullName => !AppxPackageName.IsResourcePackage(fullName)));

        foreach (var fullName in installed)
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

    private void ReadAppPaths(List<InstalledSoftware> software, List<string> denied)
    {
        foreach (var exe in SubKeys(AppPaths, denied))
        {
            software.Add(new InstalledSoftware(
                exe, Version: null, Publisher: null, SoftwareSource.AppPath,
                Provisioned: false, SurvivesFeatureUpdate: true));
        }
    }

    /// <summary>
    /// The one source that is not the registry, and the only one that can fail without anyone
    /// denying anything.
    ///
    /// <para>
    /// <c>Directory.Exists</c> answering false is not a gap: Chocolatey is simply not
    /// installed, which is the state of most machines. The two exceptions below are, and they
    /// were caught together and dropped in silence — so a library the scan could not open
    /// looked exactly like a machine that never installed a package. Told apart because the
    /// advice differs: an ACL is opened by elevating, an I/O error is not.
    /// </para>
    /// </summary>
    private void ReadChocolatey(
        List<InstalledSoftware> software, List<string> denied, List<string> unreadable)
    {
        if (!Directory.Exists(chocolateyLib))
        {
            return;
        }

        try
        {
            foreach (var directory in chocolateyPackages(chocolateyLib))
            {
                software.Add(new InstalledSoftware(
                    Path.GetFileName(directory), Version: null, Publisher: "Chocolatey",
                    SoftwareSource.Chocolatey, Provisioned: false, SurvivesFeatureUpdate: true));
            }
        }
        catch (UnauthorizedAccessException)
        {
            denied.Add(chocolateyLib);
        }
        catch (IOException)
        {
            // Not a denial and not returned as one — the invariant CONTRIBUTING records, and
            // the defect #173 spent three rounds on one channel over.
            unreadable.Add(chocolateyLib);
        }
    }

    private string? Text(string path, string value)
    {
        var read = registry.ReadValue(path, value);
        return read.Status == ReadStatus.Found ? read.Value?.Text : null;
    }
}
