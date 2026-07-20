using System.Reflection;

namespace Rempart.Core.Rules;

/// <summary>
/// Les règles livrées, embarquées dans le binaire, éventuellement complétées par un
/// répertoire externe.
///
/// Embarquées et non lues depuis le disque : le binaire doit rester autonome sur clé
/// USB, sans dossier compagnon à ne pas oublier de copier. Le répertoire externe est
/// un complément — pour itérer sur des règles sans recompiler, et pour porter des
/// contrôles propres à un parc que le catalogue livré n'a pas à connaître.
///
/// Une règle reste une donnée déclarative : elle lit le registre, elle n'exécute rien.
/// Charger un répertoire externe n'ouvre donc pas de surface d'exécution.
/// </summary>
public static class RuleCatalog
{
    private static IReadOnlyList<Rule>? cachedEmbedded;

    /// <param name="externalDirectory">
    /// Répertoire de YAML supplémentaires, parcouru récursivement. Les identifiants
    /// doivent rester uniques : une collision avec le catalogue livré est une erreur,
    /// pas une redéfinition silencieuse.
    /// </param>
    public static IReadOnlyList<Rule> Load(string? externalDirectory = null)
    {
        var rules = new List<Rule>(LoadEmbedded());

        if (externalDirectory is not null)
        {
            rules.AddRange(LoadExternal(externalDirectory));
        }

        // Le contrôle est fait ici, entre fichiers : le chargeur ne voit qu'un fichier
        // à la fois et ne peut pas repérer un doublon réparti sur deux sources.
        var duplicates = rules
            .GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicates.Count > 0)
        {
            throw new RuleFormatException(
                $"Identifiants en double entre sources : {string.Join(", ", duplicates)}. " +
                "Une règle externe ne peut pas redéfinir une règle livrée — " +
                "lui donner un identifiant distinct.");
        }

        return rules;
    }

    private static IReadOnlyList<Rule> LoadEmbedded()
    {
        if (cachedEmbedded is not null)
        {
            return cachedEmbedded;
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

        return cachedEmbedded = rules;
    }

    private static IReadOnlyList<Rule> LoadExternal(string directory)
    {
        if (!Directory.Exists(directory))
        {
            throw new RuleFormatException($"Répertoire de règles introuvable : {directory}");
        }

        var files = Directory
            .EnumerateFiles(directory, "*.yaml", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        if (files.Count == 0)
        {
            // Un répertoire vide passé explicitement est très probablement une erreur
            // de chemin. Le signaler évite un scan qui semble complet.
            throw new RuleFormatException($"Aucun fichier .yaml dans : {directory}");
        }

        var rules = new List<Rule>();
        foreach (var file in files)
        {
            rules.AddRange(RuleLoader.Load(File.ReadAllText(file), file));
        }

        // La liste noire s'applique aux règles externes comme aux autres : c'est
        // précisément là qu'une règle non relue pourrait cibler un composant critique.
        var violations = ProtectedComponents.FindViolations(rules);
        if (violations.Count > 0)
        {
            throw new RuleFormatException(
                "Règles externes ciblant un composant protégé (ADR-001, D7) : " +
                string.Join(", ", violations.Select(r => r.Id)));
        }

        return rules;
    }

    private static string ReadResource(Assembly assembly, string name)
    {
        using var stream = assembly.GetManifestResourceStream(name)
            ?? throw new RuleFormatException($"Ressource illisible : {name}");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
