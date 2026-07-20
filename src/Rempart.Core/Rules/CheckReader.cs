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
    public static void Touch(CheckSpec check, IRegistryProvider registry) =>
        _ = Read(check, registry);
}
