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
}
