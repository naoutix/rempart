using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

/// <summary>
/// Machine identity: hardware, OS, firmware, TPM, Secure Boot.
///
/// Everything comes from the registry and the system API — no WMI. This is deliberate:
/// WMI through System.Management does not survive Native AOT compilation cleanly, and
/// the single-binary deliverable depends on AOT. Data that genuinely requires WMI
/// (chassis serial number, TPM details) is deferred until that question is settled (M2).
///
/// Collection happens in two phases: read first, then compose. The order of the
/// returned fields is therefore a readability choice, independent of the order of
/// registry accesses.
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

        // ─ Read ───────────────────────────────────────────────────────────────────
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
        // os.name comes first: it is the only field that can be trusted for the Windows
        // version. The raw registry value is placed at the end of the list, where it is
        // less likely to be mistaken for the authoritative version.
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

            // Kept exactly as read. An audit must be able to show its source, not only
            // its conclusion: when a rule result is surprising, this is the value to
            // inspect. The field name states where it comes from.
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
    /// The key does not exist at all under Legacy/CSM boot. Absence and disabled state
    /// call for different remediations — migrate to UEFI, or simply enable it.
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
    /// Build thresholds: 22000 marks Windows 11, 10240 Windows 10. Server editions are
    /// not covered here — the target fleet consists of client workstations.
    /// </summary>
    internal static string? DeriveOsName(string? build, string? productName)
    {
        if (!int.TryParse(build, out var buildNumber))
        {
            // Without a parseable build number, return the raw registry value rather
            // than invent a version.
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
