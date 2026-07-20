using YamlDotNet.RepresentationModel;

namespace Rempart.Core.Rules;

public sealed class RuleFormatException(string message) : Exception(message);

/// <summary>
/// Charge les règles depuis YAML.
///
/// Le mapping est écrit à la main, sur l'API bas niveau de YamlDotNet : aucune réflexion,
/// donc compatible Native AOT sans générateur de source. Le bénéfice principal est
/// ailleurs — la validation est stricte et située, et rapporte la ligne fautive. Un
/// fichier de règles se relit et s'édite souvent ; un message comme « impossible de
/// convertir » y serait inutilisable.
///
/// Tout écart fait échouer le chargement. Une règle mal formée qu'on ignorerait
/// silencieusement produirait un audit qui paraît complet en ayant sauté un contrôle.
/// </summary>
public static class RuleLoader
{
    public static IReadOnlyList<Rule> Load(string yaml, string origin = "<inline>")
    {
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(yaml));
        }
        catch (Exception ex)
        {
            throw new RuleFormatException($"{origin} : YAML illisible — {ex.Message}");
        }

        if (stream.Documents.Count == 0)
        {
            return [];
        }

        if (stream.Documents[0].RootNode is not YamlSequenceNode root)
        {
            throw new RuleFormatException(
                $"{origin} : le document doit être une liste de règles.");
        }

        var rules = new List<Rule>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var node in root)
        {
            var rule = ReadRule(Mapping(node, origin), origin);

            if (!seen.Add(rule.Id))
            {
                throw new RuleFormatException(
                    $"{origin} : identifiant en double « {rule.Id} ». " +
                    "Les identifiants sont référencés dans les rapports et les profils.");
            }

            rules.Add(rule);
        }

        return rules;
    }

    private static Rule ReadRule(YamlMappingNode map, string origin)
    {
        var id = RequiredText(map, "id", origin);
        var context = $"{origin}, règle {id}";

        var check = ReadCheck(Mapping(Required(map, "check", context), context), context);

        return new Rule(
            Id: id,
            Title: RequiredText(map, "title", context),
            Severity: ParseEnum<Severity>(RequiredText(map, "severity", context), "severity", context),
            Domain: RequiredText(map, "domain", context),
            Rationale: RequiredText(map, "rationale", context),
            References: ReadStringList(map, "references"),
            Check: check,
            Remediation: TryGet(map, "remediation") is YamlMappingNode remediation
                ? ReadRemediation(remediation, context)
                : null);
    }

    private static CheckSpec ReadCheck(YamlMappingNode map, string context)
    {
        var kind = ParseEnum<CheckKind>(RequiredText(map, "type", context), "type", context);
        var op = ParseEnum<CheckOperator>(
            OptionalText(map, "operator") ?? nameof(CheckOperator.Equals), "operator", context);

        var expected = OptionalText(map, "expect");
        var windowsDefault = OptionalText(map, "windowsDefault");

        // Un opérateur de comparaison sans valeur attendue passerait le chargement et
        // produirait un verdict arbitraire à l'exécution. Mieux vaut refuser le fichier.
        var comparison = op is CheckOperator.Equals or CheckOperator.NotEquals or CheckOperator.AtLeast;
        if (comparison && expected is null)
        {
            throw new RuleFormatException(
                $"{context} : l'opérateur « {op} » exige un champ « expect ».");
        }

        // Exigence délibérément stricte. Sur le registre Windows, une clé absente est
        // le cas courant, pas l'exception : sans défaut déclaré, la règle produirait
        // un verdict au hasard sur la majorité des machines.
        if (comparison && windowsDefault is null)
        {
            throw new RuleFormatException(
                $"{context} : l'opérateur « {op} » exige un champ « windowsDefault » — " +
                "la valeur qu'applique Windows quand la clé est absente. " +
                "Sans elle, une clé manquante donnerait un verdict arbitraire.");
        }

        var valueName = OptionalText(map, "value");
        if (kind == CheckKind.Registry && valueName is null)
        {
            throw new RuleFormatException(
                $"{context} : un contrôle « registry » exige un champ « value ». " +
                "Pour tester l'existence d'une clé, utiliser « type: registryKey ».");
        }

        return new CheckSpec(
            kind, RequiredText(map, "path", context), valueName, op, expected, windowsDefault);
    }

    private static Remediation ReadRemediation(YamlMappingNode map, string context) => new(
        ParseEnum<Reversibility>(
            RequiredText(map, "reversibility", context), "reversibility", context),
        RequiredText(map, "impact", context));

    // ─ Accès typés ────────────────────────────────────────────────────────────────

    private static YamlMappingNode Mapping(YamlNode node, string context) =>
        node as YamlMappingNode
        ?? throw new RuleFormatException($"{context} : bloc attendu à la ligne {node.Start.Line}.");

    private static YamlNode Required(YamlMappingNode map, string key, string context) =>
        TryGet(map, key)
        ?? throw new RuleFormatException($"{context} : champ obligatoire « {key} » absent.");

    private static YamlNode? TryGet(YamlMappingNode map, string key) =>
        map.Children.TryGetValue(new YamlScalarNode(key), out var value) ? value : null;

    private static string RequiredText(YamlMappingNode map, string key, string context)
    {
        var text = OptionalText(map, key);
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new RuleFormatException($"{context} : champ obligatoire « {key} » absent ou vide.");
        }

        return text;
    }

    private static string? OptionalText(YamlMappingNode map, string key) =>
        TryGet(map, key) is YamlScalarNode scalar ? scalar.Value : null;

    private static IReadOnlyList<string> ReadStringList(YamlMappingNode map, string key) =>
        TryGet(map, key) is YamlSequenceNode sequence
            ? [.. sequence.OfType<YamlScalarNode>().Select(s => s.Value).OfType<string>()]
            : [];

    private static T ParseEnum<T>(string raw, string field, string context) where T : struct, Enum
    {
        if (Enum.TryParse<T>(raw, ignoreCase: true, out var parsed))
        {
            return parsed;
        }

        throw new RuleFormatException(
            $"{context} : valeur inconnue « {raw} » pour « {field} ». " +
            $"Attendu : {string.Join(", ", Enum.GetNames<T>().Select(n => n.ToLowerInvariant()))}.");
    }
}
