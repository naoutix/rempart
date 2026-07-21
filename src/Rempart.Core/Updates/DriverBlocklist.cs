using System.Text.Json;
using Rempart.Core.Json;

namespace Rempart.Core.Updates;

/// <summary>Un pilote connu pour être vulnérable ou malveillant, identifié par empreinte.</summary>
public sealed record BlockedDriver(string Sha256, string Name, string Category);

/// <summary>Le fichier de liste de blocage tel qu'il est sérialisé et signé.</summary>
public sealed record DriverBlocklistFile(
    string AsOfUtc,
    string? Source,
    List<BlockedDriver> Drivers);

/// <summary>
/// La liste des pilotes vulnérables connus (LOLDrivers), interrogeable par empreinte.
///
/// <para>
/// Cette donnée est le cas d'école de l'ADR-002 : ~1 500 entrées rafraîchies chaque
/// semaine, qu'il serait vain d'embarquer figées. Le socle livré est donc
/// volontairement <b>vide</b> — un plancher honnête (D12), pas une liste périmée qui
/// donnerait une fausse impression de couverture. La vraie liste arrive signée par
/// <c>rempart update</c>, une fois le canal branché sur ce type de données.
/// </para>
///
/// <para>
/// Ne rien inventer : embarquer des empreintes « de mémoire » produirait une donnée de
/// sécurité fausse — soit muette, soit trompeuse. Le mécanisme est là ; la matière
/// vient d'une source vérifiable ou de rien.
/// </para>
/// </summary>
public sealed class DriverBlocklist
{
    private readonly Dictionary<string, BlockedDriver> bySha256;

    public string AsOfUtc { get; }

    public int Count => bySha256.Count;

    private DriverBlocklist(string asOfUtc, IEnumerable<BlockedDriver> drivers)
    {
        AsOfUtc = asOfUtc;

        // Indexée par empreinte en minuscules : c'est sous cette forme que le
        // fournisseur de signature rend une empreinte, et une comparaison sensible à la
        // casse manquerait un pilote pour une simple différence de forme.
        bySha256 = drivers
            .Where(d => !string.IsNullOrWhiteSpace(d.Sha256))
            .GroupBy(d => d.Sha256.Trim().ToLowerInvariant(), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
    }

    public static readonly DriverBlocklist Empty = new("", []);

    /// <summary>
    /// Cherche un pilote par empreinte. <c>null</c> si l'empreinte est absente ou
    /// inconnue — un pilote dont on n'a pas pu calculer l'empreinte n'est pas déclaré
    /// sûr, il n'est simplement pas trouvé ici, et son verdict reste celui de sa
    /// signature.
    /// </summary>
    public BlockedDriver? Match(string? sha256) =>
        sha256 is { Length: > 0 } && bySha256.TryGetValue(sha256.Trim().ToLowerInvariant(), out var d)
            ? d
            : null;

    public static DriverBlocklist Parse(string json)
    {
        var file = JsonSerializer.Deserialize(json, RempartJsonContext.Default.DriverBlocklistFile);

        // Un fichier illisible n'est pas une liste vide : lever plutôt que charger « au
        // mieux » une liste de sécurité tronquée. L'appelant (le magasin) traduit cela
        // en refus visible.
        if (file is null)
        {
            throw new JsonException("Liste de blocage illisible.");
        }

        return new DriverBlocklist(file.AsOfUtc ?? "", file.Drivers ?? []);
    }
}
