using Rempart.Core.Providers;
using Rempart.Core.Rules;

namespace Rempart.Core.Snapshots;

public enum SyntheticProfile
{
    /// <summary>Chaque règle voit sa clé positionnée sur la valeur qu'elle attend.</summary>
    Hardened,

    /// <summary>
    /// Aucune clé de durcissement posée : le cas le plus répandu en parc réel, et
    /// celui qui exerce la sémantique des défauts Windows.
    /// </summary>
    WindowsDefaults,
}

/// <summary>
/// Fabrique un instantané synthétique à partir d'une capture réelle, en substituant
/// aux valeurs observées celles qu'exigent les règles.
///
/// Existe parce que les fixtures étaient jusqu'ici régénérées par un script jetable
/// qui reparsait le YAML à coups d'expressions régulières — une seconde implémentation
/// du chargeur, ni versionnée ni testée. Ici, ce sont les règles chargées par le moteur
/// lui-même qui pilotent la substitution : une fixture ne peut plus diverger du format
/// qu'elle est censée exercer.
/// </summary>
public static class SyntheticSnapshot
{
    public static MachineSnapshot Build(
        MachineSnapshot source,
        IReadOnlyList<Rule> rules,
        SyntheticProfile profile,
        string machineName,
        bool domainJoined = false,
        bool elevated = true,
        IReadOnlyList<string>? denyPathFragments = null)
    {
        var snapshot = new MachineSnapshot
        {
            CapturedAtUtc = "2026-01-01T00:00:00.0000000Z",
            Anonymised = true,
            Registry = new Dictionary<string, RegistryRead>(source.Registry),
            SystemInfo = (source.SystemInfo ?? Fallback) with
            {
                MachineName = machineName,
                IsDomainJoined = domainJoined,
                IsElevated = elevated,
                // Figé : une fixture ne peut pas porter une durée qui change.
                UptimeSeconds = 3600,
            },
        };

        foreach (var rule in rules)
        {
            // Seul le contrôle principal est positionné, jamais la condition
            // d'applicabilité : certaines règles s'excluent par construction, et
            // satisfaire les deux côtés produirait un instantané incohérent.
            Apply(snapshot, rule.Check, profile);
        }

        foreach (var fragment in denyPathFragments ?? [])
        {
            Deny(snapshot, fragment);
        }

        return snapshot;
    }

    private static void Apply(MachineSnapshot snapshot, CheckSpec check, SyntheticProfile profile)
    {
        var key = check.Kind == CheckKind.RegistryKey
            ? SnapshotKeys.Existence(check.Path)
            : SnapshotKeys.Value(check.Path, check.ValueName!);

        // Ne rien inventer : si la capture d'origine n'a pas vu cette clé, l'ajouter
        // masquerait une lacune de la capture au lieu de la révéler.
        if (!snapshot.Registry.ContainsKey(key))
        {
            return;
        }

        snapshot.Registry[key] = profile switch
        {
            SyntheticProfile.WindowsDefaults => RegistryRead.NotFound,
            _ => Satisfying(check),
        };
    }

    /// <summary>Valeur qui fait passer le contrôle.</summary>
    private static RegistryRead Satisfying(CheckSpec check) => check.Operator switch
    {
        CheckOperator.Absent => RegistryRead.NotFound,
        CheckOperator.Exists => RegistryRead.Found(RegistryValue.OfNumber(1)),

        // Le contraire de la valeur refusée. Prendre 0 par défaut suffit, sauf quand
        // c'est précisément 0 qui est refusé.
        CheckOperator.NotEquals => RegistryRead.Found(
            RegistryValue.OfNumber(check.Expected == "0" ? 1 : 0)),

        _ when check.Kind == CheckKind.RegistryKey => RegistryRead.Found(RegistryValue.OfNumber(1)),

        _ => long.TryParse(check.Expected, out var number)
            ? RegistryRead.Found(RegistryValue.OfNumber(number))
            : RegistryRead.Found(RegistryValue.OfText(check.Expected ?? string.Empty)),
    };

    /// <summary>
    /// Simule un accès refusé sur les clés dont le chemin contient le fragment donné.
    /// Sert à produire une fixture de scan non élevé.
    /// </summary>
    private static void Deny(MachineSnapshot snapshot, string fragment)
    {
        foreach (var key in snapshot.Registry.Keys
                     .Where(k => k.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                     .ToList())
        {
            snapshot.Registry[key] = RegistryRead.AccessDenied;
        }
    }

    private static readonly SystemInfo Fallback = new(
        MachineName: "anon:synthetic",
        OsVersion: "10.0.26200.0",
        Is64BitOperatingSystem: true,
        IsElevated: true,
        ProcessorCount: 8,
        UptimeSeconds: 3600,
        FirmwareType: "uefi");
}
