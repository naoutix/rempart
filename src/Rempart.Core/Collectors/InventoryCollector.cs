using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

/// <summary>
/// Identité de la machine : matériel, OS, firmware, TPM, Secure Boot.
///
/// Tout provient du registre et de l'API système — pas de WMI. C'est délibéré : WMI
/// via System.Management ne survit pas proprement à la compilation Native AOT, et le
/// livrable en binaire unique en dépend. Les données qui exigent réellement WMI
/// (numéro de série châssis, détail TPM) attendent que la question soit tranchée (M2).
///
/// La collecte se fait en deux temps : lecture d'abord, composition ensuite. L'ordre
/// des champs restitués est donc un choix de lisibilité, indépendant de l'ordre des
/// accès au registre.
/// </summary>
public sealed class InventoryCollector : ICollector
{
    private const string CurrentVersionKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private const string BiosKey = @"HKLM\HARDWARE\DESCRIPTION\System\BIOS";
    private const string SecureBootStateKey = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State";
    private const string TpmServiceKey = @"HKLM\SYSTEM\CurrentControlSet\Services\TPM";

    public string Name => "inventory";

    public CollectorResult Collect(ProviderSet providers)
    {
        var diagnostics = new List<string>();
        var denied = false;

        string? Read(string keyPath, string valueName)
        {
            var read = providers.Registry.ReadValue(keyPath, valueName);
            if (read.Status == ReadStatus.AccessDenied)
            {
                denied = true;
                diagnostics.Add($"Accès refusé : {keyPath}\\{valueName}");
                return null;
            }

            return read.Status == ReadStatus.Found ? read.Value?.ToString() : null;
        }

        // ─ Lecture ────────────────────────────────────────────────────────────────
        var registryProductName = Read(CurrentVersionKey, "ProductName");
        var displayVersion = Read(CurrentVersionKey, "DisplayVersion");
        var build = Read(CurrentVersionKey, "CurrentBuildNumber");
        var updateBuildRevision = Read(CurrentVersionKey, "UBR");
        var edition = Read(CurrentVersionKey, "EditionID");
        var installationType = Read(CurrentVersionKey, "InstallationType");

        var manufacturer = Read(BiosKey, "SystemManufacturer");
        var model = Read(BiosKey, "SystemProductName");
        var family = Read(BiosKey, "SystemFamily");
        var biosVersion = Read(BiosKey, "BIOSVersion");
        var biosDate = Read(BiosKey, "BIOSReleaseDate");
        var baseboardManufacturer = Read(BiosKey, "BaseBoardManufacturer");
        var baseboardProduct = Read(BiosKey, "BaseBoardProduct");

        var secureBoot = ReadSecureBoot(providers, diagnostics, ref denied);
        var tpm = ReadTpm(providers, diagnostics, ref denied);
        var system = providers.SystemInfo.Read();

        // ─ Composition ────────────────────────────────────────────────────────────
        // os.name en tête : c'est la seule ligne à laquelle on peut se fier pour la
        // version de Windows. La valeur brute du registre ferme la liste, où elle
        // n'induit plus personne en erreur.
        var fields = new Dictionary<string, string?>
        {
            ["os.name"] = DeriveOsName(build, registryProductName),
            ["os.displayVersion"] = displayVersion,
            ["os.build"] = build,
            ["os.updateBuildRevision"] = updateBuildRevision,
            ["os.edition"] = edition,
            ["os.installationType"] = installationType,
            ["os.version"] = system.OsVersion,
            ["os.is64Bit"] = system.Is64BitOperatingSystem.ToString(),

            ["hardware.manufacturer"] = manufacturer,
            ["hardware.model"] = model,
            ["hardware.family"] = family,
            ["hardware.baseboardManufacturer"] = baseboardManufacturer,
            ["hardware.baseboardProduct"] = baseboardProduct,
            ["machine.name"] = system.MachineName,
            ["machine.processorCount"] = system.ProcessorCount.ToString(),
            ["machine.uptimeSeconds"] = system.UptimeSeconds.ToString(),

            ["firmware.type"] = system.FirmwareType,
            ["firmware.biosVersion"] = biosVersion,
            ["firmware.biosDate"] = biosDate,

            ["security.secureBoot"] = secureBoot,
            ["security.tpmService"] = tpm,

            ["scan.elevated"] = system.IsElevated.ToString(),

            // Conservée telle que lue. Un audit doit pouvoir montrer sa source, pas
            // seulement sa conclusion : le jour où une règle surprend, c'est cette
            // valeur qu'on veut voir. Le nom du champ dit d'où elle vient.
            ["os.registryProductName"] = registryProductName,
        };

        if (!system.IsElevated)
        {
            diagnostics.Add(
                "Scan non élevé : certaines valeurs sont hors de portée. " +
                "Relancer en administrateur pour un inventaire complet.");
        }

        var status = denied ? CollectorStatus.InsufficientPrivileges : CollectorStatus.Ok;
        return new CollectorResult(Name, status, fields, diagnostics);
    }

    /// <summary>
    /// La clé n'existe pas du tout en démarrage Legacy/CSM. Absence et désactivation
    /// appellent des remédiations différentes — migrer en UEFI, ou simplement activer.
    /// </summary>
    private static string? ReadSecureBoot(
        ProviderSet providers, List<string> diagnostics, ref bool denied)
    {
        var read = providers.Registry.ReadValue(SecureBootStateKey, "UEFISecureBootEnabled");

        switch (read.Status)
        {
            case ReadStatus.Found:
                return read.Value?.Number == 1 ? "enabled" : "disabled";
            case ReadStatus.NotFound:
                return "unsupported";
            default:
                denied = true;
                diagnostics.Add($"Accès refusé : {SecureBootStateKey}");
                return null;
        }
    }

    private static string? ReadTpm(ProviderSet providers, List<string> diagnostics, ref bool denied)
    {
        var status = providers.Registry.KeyExists(TpmServiceKey);

        switch (status)
        {
            case ReadStatus.Found:
                return "present";
            case ReadStatus.NotFound:
                return "absent";
            default:
                denied = true;
                diagnostics.Add($"Accès refusé : {TpmServiceKey}");
                return null;
        }
    }

    /// <summary>
    /// Seuils de build : 22000 marque Windows 11, 10240 Windows 10. Les éditions
    /// Server ne sont pas couvertes ici — le parc visé est constitué de postes clients.
    /// </summary>
    internal static string? DeriveOsName(string? build, string? productName)
    {
        if (!int.TryParse(build, out var buildNumber))
        {
            // Sans build lisible, mieux vaut rendre la valeur brute du registre que
            // d'inventer une version.
            return productName;
        }

        var edition = productName?.Replace("Windows 10", string.Empty, StringComparison.Ordinal)
            .Replace("Windows 11", string.Empty, StringComparison.Ordinal)
            .Trim();

        var family = buildNumber switch
        {
            >= 22000 => "Windows 11",
            >= 10240 => "Windows 10",
            _ => null,
        };

        if (family is null)
        {
            return productName;
        }

        return string.IsNullOrEmpty(edition) ? family : $"{family} {edition}";
    }
}
