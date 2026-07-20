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
            Services = new Dictionary<string, ServiceRead>(source.Services),
            Policy = source.Policy,
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
        if (check.Kind == CheckKind.Service)
        {
            ApplyService(snapshot, check, profile);
            return;
        }

        if (check.Kind == CheckKind.Policy)
        {
            ApplyPolicy(snapshot, check, profile);
            return;
        }

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

    /// <summary>
    /// Un service n'a pas de « défaut Windows » : son état est directement observable.
    /// Le profil « defaults » le laisse donc tel que la capture l'a vu, au lieu de le
    /// déclarer absent — ce qui décrirait une machine qui n'existe pas.
    /// </summary>
    private static void ApplyService(MachineSnapshot snapshot, CheckSpec check, SyntheticProfile profile)
    {
        if (profile == SyntheticProfile.WindowsDefaults || !snapshot.Services.ContainsKey(check.Path))
        {
            return;
        }

        snapshot.Services[check.Path] = check.Expected?.ToLowerInvariant() switch
        {
            "absent" when check.Operator == CheckOperator.Equals => ServiceRead.NotInstalled,
            _ => ServiceRead.Found(new ServiceInfo(
                check.Path, SatisfyingState(check), SatisfyingStartMode(check))),
        };
    }

    /// <summary>
    /// Un fait de politique n'a pas non plus de « défaut Windows » : il est lu ou il
    /// ne l'est pas. Le profil « defaults » le laisse tel quel plutôt que de le
    /// supprimer, ce qui rendrait la règle non vérifiable au lieu de non conforme.
    /// </summary>
    private static void ApplyPolicy(MachineSnapshot snapshot, CheckSpec check, SyntheticProfile profile)
    {
        if (profile == SyntheticProfile.WindowsDefaults || snapshot.Policy is not { } existing)
        {
            return;
        }

        var facts = new Dictionary<string, string>(existing.Values, StringComparer.Ordinal)
        {
            [check.Path] = SatisfyingFact(check),
        };

        snapshot.Policy = existing with { Values = facts };
    }

    private static string SatisfyingFact(CheckSpec check) => check.Operator switch
    {
        // Un plancher se satisfait par la valeur attendue elle-même, un plafond aussi :
        // les deux comparaisons sont larges.
        CheckOperator.AtLeast or CheckOperator.AtMost or CheckOperator.Equals =>
            check.Expected ?? "0",

        CheckOperator.NotEquals => check.Expected == "0" ? "1" : "0",

        _ => check.Expected ?? "0",
    };

    private static ServiceState SatisfyingState(CheckSpec check)
    {
        if (!string.Equals(check.ValueName, "state", StringComparison.OrdinalIgnoreCase))
        {
            return ServiceState.Running;
        }

        return check.Operator == CheckOperator.NotEquals
            ? Opposite(Parse(check.Expected, ServiceState.Running))
            : Parse(check.Expected, ServiceState.Running);
    }

    private static ServiceStartMode SatisfyingStartMode(CheckSpec check)
    {
        if (string.Equals(check.ValueName, "state", StringComparison.OrdinalIgnoreCase))
        {
            return ServiceStartMode.Automatic;
        }

        var expected = Parse(check.Expected, ServiceStartMode.Automatic);

        return check.Operator == CheckOperator.NotEquals
            ? expected == ServiceStartMode.Disabled ? ServiceStartMode.Automatic : ServiceStartMode.Disabled
            : expected;
    }

    private static ServiceState Opposite(ServiceState state) =>
        state == ServiceState.Running ? ServiceState.Stopped : ServiceState.Running;

    private static T Parse<T>(string? raw, T fallback) where T : struct, Enum =>
        Enum.TryParse<T>(raw, ignoreCase: true, out var parsed) ? parsed : fallback;

    /// <summary>Valeur qui fait passer le contrôle.</summary>
    private static RegistryRead Satisfying(CheckSpec check) => check.Operator switch
    {
        CheckOperator.Absent => RegistryRead.NotFound,
        CheckOperator.Exists => RegistryRead.Found(RegistryValue.OfNumber(1)),

        // Le contraire de la valeur refusée. Prendre 0 par défaut suffit, sauf quand
        // c'est précisément 0 qui est refusé.
        CheckOperator.NotEquals => RegistryRead.Found(
            RegistryValue.OfNumber(check.Expected == "0" ? 1 : 0)),

        // Un plafond se satisfait par zéro, sauf si le plafond est lui-même zéro.
        CheckOperator.AtMost => RegistryRead.Found(RegistryValue.OfNumber(
            long.TryParse(check.Expected, out var cap) && cap < 0 ? cap : 0)),

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
