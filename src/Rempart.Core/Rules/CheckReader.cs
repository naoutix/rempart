using Rempart.Core.Providers;

namespace Rempart.Core.Rules;

/// <summary>
/// Résultat brut de la lecture d'un contrôle, avant tout jugement.
/// </summary>
/// <param name="Found">Valeur réellement présente, ou null si absente.</param>
/// <param name="Effective">
/// Valeur qui régit le comportement : <paramref name="Found"/> ou, à défaut, le défaut
/// Windows déclaré par la règle.
/// </param>
/// <param name="Denied">L'accès a été refusé : ni conforme, ni non conforme.</param>
public sealed record CheckReading(string? Found, string? Effective, bool Denied)
{
    /// <summary>Ce que le rapport affiche, défaut Windows mentionné le cas échéant.</summary>
    public string? Describe(CheckSpec check)
    {
        if (Denied)
        {
            return null;
        }

        if (Found is not null)
        {
            return Found;
        }

        return check.WindowsDefault is { } fallback
            ? $"absent (défaut Windows : {fallback})"
            : "absent";
    }
}

/// <summary>
/// Seul point du projet qui traduit un <see cref="CheckSpec"/> en appels de provider.
///
/// L'évaluation et la capture avaient chacune leur version de cette traduction, à tenir
/// synchronisées sans que rien ne le garantisse. Le prochain type de contrôle oublié
/// côté capture aurait produit des instantanés silencieusement incomplets, et un échec
/// de rejeu bien plus tard, avec un message sans rapport avec la cause.
/// </summary>
public static class CheckReader
{
    public static CheckReading Read(CheckSpec check, ProviderSet providers) => check.Kind switch
    {
        CheckKind.Service => ReadService(check, providers.Services),
        CheckKind.Policy => ReadPolicy(check, providers.Policy),
        CheckKind.Wmi => ReadWmi(check, providers.Wmi),
        _ => Read(check, providers.Registry),
    };

    /// <summary>
    /// Un fait absent du dictionnaire n'est pas une non-conformité : l'API n'a pas su
    /// l'établir. Rendre « non vérifiable » plutôt qu'un verdict évite de reprocher à
    /// une machine ce que l'outil n'a pas su lire.
    /// </summary>
    private static CheckReading ReadPolicy(CheckSpec check, ISecurityPolicyProvider policy)
    {
        var facts = policy.Read();

        if (facts.Denied || facts.Find(check.Path) is not { } value)
        {
            return new CheckReading(null, null, Denied: true);
        }

        return new CheckReading(value, value, Denied: false);
    }

    /// <summary>
    /// Un service absent n'est pas un refus d'accès : il n'y a rien à lire, et la
    /// comparaison portera sur « absent ». Distinguer les deux évite de conclure à
    /// une non-conformité là où le scan n'a simplement pas pu regarder.
    /// </summary>
    private static CheckReading ReadService(CheckSpec check, IServiceStateProvider services)
    {
        var read = services.Read(check.Path);

        if (read.Status == ReadStatus.AccessDenied)
        {
            return new CheckReading(null, null, Denied: true);
        }

        if (read.Info is not { } info)
        {
            return new CheckReading(null, "absent", Denied: false);
        }

        var observed = check.ValueName?.ToLowerInvariant() switch
        {
            "state" => info.State.ToString().ToLowerInvariant(),
            _ => info.StartMode.ToString().ToLowerInvariant(),
        };

        return new CheckReading(observed, observed, Denied: false);
    }

    /// <summary>
    /// Un contrôle WMI porte sur toutes les instances rendues : chaque volume, chaque
    /// adaptateur. Il n'est satisfait que si toutes le sont — un seul disque non
    /// chiffré suffit à exposer les données qu'il porte.
    ///
    /// Quand les instances divergent, la valeur observée les énumère et la comparaison
    /// échoue d'elle-même : aucune valeur unique ne peut correspondre à plusieurs.
    /// </summary>
    private static CheckReading ReadWmi(CheckSpec check, IWmiProvider wmi)
    {
        var separator = check.Path.IndexOf(':');
        if (separator < 0 || check.ValueName is null)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var read = wmi.Query(
            check.Path[..separator], check.Path[(separator + 1)..], [check.ValueName]);

        // Aucune instance : il n'y a rien à juger. BitLocker absent d'une édition
        // Famille n'est pas une non-conformité, c'est une absence de sujet.
        if (read.Status != ReadStatus.Found || read.Instances.Count == 0)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var values = read.Instances
            .Select(i => i.Find(check.ValueName))
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (values.Count == 0)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var observed = values.Count == 1 ? values[0] : string.Join(", ", values);
        return new CheckReading(observed, observed, Denied: false);
    }

    public static CheckReading Read(CheckSpec check, IRegistryProvider registry)
    {
        if (check.Kind == CheckKind.RegistryKey)
        {
            var status = registry.KeyExists(check.Path);

            return status == ReadStatus.AccessDenied
                ? new CheckReading(null, null, Denied: true)
                : new CheckReading(
                    Found: status == ReadStatus.Found ? "present" : null,
                    Effective: status == ReadStatus.Found ? "present" : null,
                    Denied: false);
        }

        var read = registry.ReadValue(check.Path, check.ValueName!);

        if (read.Status == ReadStatus.AccessDenied)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var found = read.Status == ReadStatus.Found ? read.Value?.ToString() : null;

        // Clé absente : le comportement effectif est celui du défaut Windows déclaré
        // par la règle. Le verdict porte donc sur ce que fait réellement la machine,
        // pas sur la présence d'une entrée de registre.
        return new CheckReading(found, found ?? check.WindowsDefault, Denied: false);
    }

    /// <summary>
    /// Effectue la lecture sans exploiter le résultat, pour qu'un provider
    /// d'enregistrement la consigne. Passe par <see cref="Read"/> : c'est ce qui
    /// garantit que capture et évaluation touchent exactement les mêmes clés.
    /// </summary>
    public static void Touch(CheckSpec check, ProviderSet providers) =>
        _ = Read(check, providers);
}
