namespace Rempart.Core.Software;

/// <summary>
/// Décompose un nom complet de paquet Appx.
///
/// <para>
/// La forme canonique est <c>Nom_Version_Architecture_ResourceId_EmpreinteÉditeur</c>,
/// segments joints par des tirets bas — p. ex.
/// <c>AdobeNotificationClient_7.0.2.14_x64__enpm4xejd91yc</c>. On en tire le nom et la
/// version ; le reste (architecture, empreinte d'éditeur) n'a pas d'intérêt à l'inventaire.
/// Pur, sans réflexion. Ne lève jamais : un nom atypique (un GUID, des segments manquants)
/// rend le nom complet tel quel, sans version.
/// </para>
/// </summary>
public static class AppxPackageName
{
    public static (string Name, string? Version) Parse(string fullName)
    {
        var parts = fullName.Split('_');
        if (parts.Length < 2 || parts[0].Length == 0)
        {
            return (fullName, null);
        }

        // La version est le deuxième segment quand il en a la forme (chiffres et points).
        var version = parts[1].Length > 0 && parts[1].All(c => char.IsDigit(c) || c == '.')
            ? parts[1]
            : null;

        return (parts[0], version);
    }

    /// <summary>
    /// Dérive le Package Family Name (<c>Nom_HashÉditeur</c>) d'un nom complet
    /// <c>Nom_Version_Arch__HashÉditeur</c> : le nom (avant le premier <c>_</c>) et le
    /// hash d'éditeur (après le dernier <c>_</c>). Un nom sans séparateur est rendu tel
    /// quel — c'est déjà un identifiant.
    /// </summary>
    public static string FamilyName(string fullName)
    {
        var first = fullName.IndexOf('_');
        var last = fullName.LastIndexOf('_');
        return first < 0 || first == last
            ? fullName
            : string.Concat(fullName.AsSpan(0, first), "_", fullName.AsSpan(last + 1));
    }
}
