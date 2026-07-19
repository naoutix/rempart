using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

/// <summary>
/// Identité de la machine : matériel, OS, firmware, TPM, Secure Boot.
///
/// Tout provient du registre et de l'API système — pas de WMI. C'est délibéré : WMI
/// via System.Management ne survit pas proprement à la compilation Native AOT, et le
/// livrable en binaire unique en dépend. Les données qui exigent réellement WMI
/// (numéro de série châssis, détail TPM) attendent que la question soit tranchée (M2).
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
        var fields = new Dictionary<string, string?>();
        var diagnostics = new List<string>();
        var denied = false;

        void Read(string label, string keyPath, string valueName)
        {
            var read = providers.Registry.ReadValue(keyPath, valueName);
            switch (read.Status)
            {
                case ReadStatus.Found:
                    fields[label] = read.Value?.ToString();
                    break;
                case ReadStatus.NotFound:
                    fields[label] = null;
                    break;
                case ReadStatus.AccessDenied:
                    fields[label] = null;
                    denied = true;
                    diagnostics.Add($"Accès refusé : {keyPath}\\{valueName}");
                    break;
            }
        }

        Read("os.product", CurrentVersionKey, "ProductName");
        Read("os.displayVersion", CurrentVersionKey, "DisplayVersion");
        Read("os.build", CurrentVersionKey, "CurrentBuildNumber");

        // ProductName annonce encore « Windows 10 » sur tout Windows 11 : Microsoft ne
        // l'a jamais corrigé. Le numéro de build fait foi, sans quoi toute règle
        // conditionnée à la version porterait sur une valeur fausse.
        fields["os.name"] = DeriveOsName(fields.GetValueOrDefault("os.build"),
            fields.GetValueOrDefault("os.product"));

        Read("os.updateBuildRevision", CurrentVersionKey, "UBR");
        Read("os.edition", CurrentVersionKey, "EditionID");
        Read("os.installationType", CurrentVersionKey, "InstallationType");

        Read("hardware.manufacturer", BiosKey, "SystemManufacturer");
        Read("hardware.model", BiosKey, "SystemProductName");
        Read("hardware.family", BiosKey, "SystemFamily");
        Read("firmware.biosVersion", BiosKey, "BIOSVersion");
        Read("firmware.biosDate", BiosKey, "BIOSReleaseDate");
        Read("hardware.baseboardManufacturer", BiosKey, "BaseBoardManufacturer");
        Read("hardware.baseboardProduct", BiosKey, "BaseBoardProduct");

        // Secure Boot : la clé n'existe pas du tout en démarrage Legacy/CSM.
        // Absence et désactivation sont deux états différents, on ne les confond pas.
        var secureBoot = providers.Registry.ReadValue(SecureBootStateKey, "UEFISecureBootEnabled");
        fields["security.secureBoot"] = secureBoot.Status switch
        {
            ReadStatus.Found => secureBoot.Value?.Number == 1 ? "enabled" : "disabled",
            ReadStatus.NotFound => "unsupported",
            _ => null,
        };
        if (secureBoot.Status == ReadStatus.AccessDenied)
        {
            denied = true;
            diagnostics.Add($"Accès refusé : {SecureBootStateKey}");
        }

        var tpm = providers.Registry.KeyExists(TpmServiceKey);
        fields["security.tpmService"] = tpm switch
        {
            ReadStatus.Found => "present",
            ReadStatus.NotFound => "absent",
            _ => null,
        };
        if (tpm == ReadStatus.AccessDenied)
        {
            denied = true;
            diagnostics.Add($"Accès refusé : {TpmServiceKey}");
        }

        var system = providers.SystemInfo.Read();
        fields["machine.name"] = system.MachineName;
        fields["os.version"] = system.OsVersion;
        fields["os.is64Bit"] = system.Is64BitOperatingSystem.ToString();
        fields["machine.processorCount"] = system.ProcessorCount.ToString();
        fields["machine.uptimeSeconds"] = system.UptimeSeconds.ToString();
        fields["firmware.type"] = system.FirmwareType;
        fields["scan.elevated"] = system.IsElevated.ToString();

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
