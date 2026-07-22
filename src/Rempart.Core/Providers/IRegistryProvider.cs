namespace Rempart.Core.Providers;

/// <summary>
/// Issue d'une lecture. Distinguer <see cref="NotFound"/> de <see cref="AccessDenied"/>
/// est essentiel : une clé absente est une information, un accès refusé est un trou
/// dans l'audit. Les confondre produirait un rapport qui ment par omission.
/// </summary>
public enum ReadStatus
{
    Found,
    NotFound,
    AccessDenied,
}

public sealed record RegistryValue(string Kind, string? Text, long? Number)
{
    public static RegistryValue OfText(string text) => new("String", text, null);

    public static RegistryValue OfNumber(long number) => new("DWord", null, number);

    public override string ToString() => Text ?? Number?.ToString() ?? string.Empty;
}

public sealed record RegistryRead(ReadStatus Status, RegistryValue? Value)
{
    public static readonly RegistryRead NotFound = new(ReadStatus.NotFound, null);
    public static readonly RegistryRead AccessDenied = new(ReadStatus.AccessDenied, null);

    public static RegistryRead Found(RegistryValue value) => new(ReadStatus.Found, value);
}

/// <summary>
/// Accès au registre. Aucun collecteur n'appelle Windows directement (ADR-001, D5) :
/// c'est ce qui permet de rejouer un scan hors-ligne depuis un instantané.
/// </summary>
public interface IRegistryProvider
{
    /// <param name="keyPath">Chemin complet, p. ex. <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</c>.</param>
    RegistryRead ReadValue(string keyPath, string valueName);

    /// <summary>Existence d'une clé — utile quand la présence seule est le signal.</summary>
    ReadStatus KeyExists(string keyPath);

    /// <summary>
    /// Toutes les valeurs d'une clé, nom par nom.
    ///
    /// Les règles interrogent une valeur qu'elles connaissent ; l'énumération des
    /// démarrages automatiques, elle, découvre ce qui s'y trouve. On ne peut pas
    /// chercher par nom ce dont on ignore l'existence.
    /// </summary>
    IReadOnlyDictionary<string, RegistryValue> ListValues(string keyPath);

    /// <summary>
    /// Les noms des sous-clés d'une clé. Pour découvrir une arborescence dont on ne
    /// connaît pas les entrées — les CLSID enregistrés par un utilisateur, par exemple,
    /// dont les identifiants sont imprévisibles. Vide si la clé est absente ou refusée.
    /// </summary>
    IReadOnlyList<string> ListSubKeys(string keyPath);
}
