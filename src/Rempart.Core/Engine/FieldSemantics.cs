namespace Rempart.Core.Engine;

/// <summary>
/// Certains champs ne peuvent pas être comparés bêtement d'un scan à l'autre.
///
/// Les distinguer sert deux usages : les tests sur fixtures (une sortie de référence ne
/// peut pas figer un uptime) et <c>rempart diff</c> (M7), qui signalerait sinon un écart
/// entre deux machines à chaque champ volatil.
/// </summary>
public static class FieldSemantics
{
    /// <summary>Change à chaque exécution, sans porter d'information de posture.</summary>
    public static readonly IReadOnlySet<string> Volatile = new HashSet<string>(StringComparer.Ordinal)
    {
        "machine.uptimeSeconds",
    };

    /// <summary>Remplacé par une empreinte dans les instantanés anonymisés.</summary>
    public static readonly IReadOnlySet<string> Identifying = new HashSet<string>(StringComparer.Ordinal)
    {
        "machine.name",
    };

    public static bool IsComparable(string field) =>
        !Volatile.Contains(field) && !Identifying.Contains(field);
}
