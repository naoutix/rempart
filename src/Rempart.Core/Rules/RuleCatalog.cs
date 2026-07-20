using System.Reflection;

namespace Rempart.Core.Rules;

/// <summary>
/// Les règles livrées, embarquées dans le binaire.
///
/// Embarquées et non lues depuis le disque : le binaire doit rester autonome sur clé
/// USB, sans dossier compagnon à ne pas oublier de copier. Un chargement depuis un
/// répertoire externe pourra s'ajouter, mais comme complément, jamais comme socle.
/// </summary>
public static class RuleCatalog
{
    private static IReadOnlyList<Rule>? cached;

    public static IReadOnlyList<Rule> Load()
    {
        if (cached is not null)
        {
            return cached;
        }

        var assembly = typeof(RuleCatalog).Assembly;
        var rules = new List<Rule>();

        foreach (var name in assembly.GetManifestResourceNames()
                     .Where(n => n.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(n => n, StringComparer.Ordinal))
        {
            rules.AddRange(RuleLoader.Load(ReadResource(assembly, name), name));
        }

        // Le chargement échoue plutôt que de livrer un catalogue vide en silence :
        // un scan sans règles rendrait un rapport parfaitement vert.
        if (rules.Count == 0)
        {
            throw new RuleFormatException(
                "Aucune règle embarquée. Vérifier l'inclusion de rules/**/*.yaml en ressources.");
        }

        var violations = ProtectedComponents.FindViolations(rules);
        if (violations.Count > 0)
        {
            throw new RuleFormatException(
                "Règles ciblant un composant protégé (ADR-001, D7) : " +
                string.Join(", ", violations.Select(r => r.Id)));
        }

        return cached = rules;
    }

    private static string ReadResource(Assembly assembly, string name)
    {
        using var stream = assembly.GetManifestResourceStream(name)
            ?? throw new RuleFormatException($"Ressource illisible : {name}");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
