namespace Rempart.Core.Providers;

/// <summary>
/// Faits de sécurité qui ne se lisent ni au registre ni au gestionnaire de services :
/// politique de mot de passe, verrouillage de compte, comptes locaux.
///
/// Exposés comme un dictionnaire de valeurs nommées plutôt que comme un modèle typé.
/// Une règle compare une valeur à une attente ; lui donner une liste de comptes à
/// parcourir demanderait un langage d'expression dans le YAML, ce qui reviendrait à
/// écrire du code dans un fichier de données. Les agrégats — nombre d'administrateurs,
/// compte invité actif — répondent aux questions qu'un audit pose réellement.
/// </summary>
public interface ISecurityPolicyProvider
{
    /// <summary>
    /// Faits disponibles, indexés par nom. Une clé absente signifie que le fait n'a pas
    /// pu être établi : la règle correspondante rendra « non vérifiable », jamais un
    /// échec — l'outil ne sait pas, il ne juge pas.
    /// </summary>
    PolicyFacts Read();
}

public sealed record PolicyFacts(
    IReadOnlyDictionary<string, string> Values,
    bool Denied = false)
{
    public static readonly PolicyFacts AccessDenied =
        new(new Dictionary<string, string>(), Denied: true);

    public string? Find(string name) =>
        Values.TryGetValue(name, out var value) ? value : null;
}

/// <summary>Noms des faits, pour éviter les chaînes libres dans le code.</summary>
public static class PolicyFactNames
{
    public const string PasswordMinLength = "password.minLength";
    public const string PasswordMaxAgeDays = "password.maxAgeDays";
    public const string PasswordHistoryLength = "password.historyLength";
    public const string LockoutThreshold = "lockout.threshold";
    public const string LockoutDurationMinutes = "lockout.durationMinutes";
    public const string LocalAdminCount = "accounts.localAdminCount";
    public const string GuestEnabled = "accounts.guestEnabled";
    public const string AccountsWithoutPassword = "accounts.withoutPassword";
    public const string AccountsPasswordNeverExpires = "accounts.passwordNeverExpires";
}
