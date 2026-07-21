using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// Ce qu'une mise à jour changerait au catalogue en vigueur.
///
/// <para>
/// Le socle est un plancher (ADR-002, D12) : une mise à jour peut corriger ou ajouter
/// un contrôle, jamais en retirer un embarqué. Un contrôle présent dans le socle et
/// absent de la mise à jour n'est donc pas « retiré » — il reste, tel quel. C'est
/// pourquoi ce différentiel n'a pas de catégorie « supprimé » : elle serait toujours
/// vide, et l'y laisser inviterait un jour à la remplir, c'est-à-dire à percer le
/// plancher.
/// </para>
/// </summary>
public sealed record CatalogDiff(
    IReadOnlyList<string> Added,
    IReadOnlyList<RuleChange> Modified,
    int Unchanged)
{
    public bool ChangesNothing => Added.Count == 0 && Modified.Count == 0;

    /// <summary>
    /// Compare un catalogue entrant au catalogue en vigueur, par identifiant.
    ///
    /// « Modifié » se juge sur l'empreinte par règle, pas sur le texte : reformuler une
    /// justification ne modifie pas un contrôle, changer un seuil oui. C'est la même
    /// aune que l'empreinte du catalogue, pour qu'un rapport et un différentiel ne se
    /// contredisent jamais sur ce qui « a changé ».
    /// </summary>
    public static CatalogDiff Between(
        IReadOnlyList<Rule> current, IReadOnlyList<Rule> incoming)
    {
        var byId = current.ToDictionary(
            r => r.Id, RuleCatalog.RuleFingerprint, StringComparer.OrdinalIgnoreCase);

        var added = new List<string>();
        var modified = new List<RuleChange>();
        var unchanged = 0;

        foreach (var rule in incoming)
        {
            var incomingPrint = RuleCatalog.RuleFingerprint(rule);

            if (!byId.TryGetValue(rule.Id, out var currentPrint))
            {
                added.Add(rule.Id);
            }
            else if (!string.Equals(currentPrint, incomingPrint, StringComparison.Ordinal))
            {
                modified.Add(new RuleChange(rule.Id, currentPrint, incomingPrint));
            }
            else
            {
                unchanged++;
            }
        }

        return new CatalogDiff(
            [.. added.OrderBy(id => id, StringComparer.Ordinal)],
            [.. modified.OrderBy(c => c.Id, StringComparer.Ordinal)],
            unchanged);
    }
}

/// <summary>
/// Un contrôle modifié, avec les empreintes avant et après. Les montrer permet de
/// distinguer d'un coup d'œil deux mises à jour qui touchent la même règle.
/// </summary>
public sealed record RuleChange(string Id, string Before, string After);
