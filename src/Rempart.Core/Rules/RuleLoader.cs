using YamlDotNet.RepresentationModel;

namespace Rempart.Core.Rules;

public sealed class RuleFormatException(string message) : Exception(message);

/// <summary>
/// Loads rules from YAML.
///
/// The mapping is hand-written on YamlDotNet's low-level API: no reflection, so it is
/// Native AOT compatible without a source generator. The main benefit is elsewhere —
/// validation is strict, local, and reports the offending line. A rules file gets
/// reread and edited often; a message like "cannot convert" would be useless there.
///
/// Any deviation fails the load. A malformed rule that was silently ignored would
/// produce an audit that looks complete while having skipped a check.
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
                : null,
            AppliesWhen: TryGet(map, "appliesWhen") is YamlMappingNode applicability
                ? ReadApplicability(applicability, context)
                : null);
    }

    private static Applicability ReadApplicability(YamlMappingNode map, string context)
    {
        var domainJoined = OptionalText(map, "domainJoined") is { } raw
            ? bool.TryParse(raw, out var parsed)
                ? parsed
                : throw new RuleFormatException(
                    $"{context} : « domainJoined » attend true ou false, reçu « {raw} ».")
            : (bool?)null;

        var registry = TryGet(map, "registry") is YamlMappingNode nested
            ? ReadCheck(nested, $"{context}, appliesWhen")
            : null;

        // An empty block suggests there is a condition while the rule actually applies
        // everywhere. Better to reject the file than to ship a lost intent.
        var applicability = new Applicability(domainJoined, registry);
        if (applicability.IsUnconditional)
        {
            throw new RuleFormatException(
                $"{context} : « appliesWhen » ne pose aucune condition. " +
                "Renseigner « domainJoined » ou « registry », ou retirer le bloc.");
        }

        return applicability;
    }

    private static CheckSpec ReadCheck(YamlMappingNode map, string context)
    {
        var kind = ParseEnum<CheckKind>(RequiredText(map, "type", context), "type", context);
        var op = ParseEnum<CheckOperator>(
            OptionalText(map, "operator") ?? nameof(CheckOperator.Equals), "operator", context);

        var expected = OptionalText(map, "expect");
        var windowsDefault = OptionalText(map, "windowsDefault");

        // A comparison operator without an expected value would pass loading and produce
        // an arbitrary verdict at run time. Better to reject the file.
        var comparison = op is CheckOperator.Equals or CheckOperator.NotEquals
            or CheckOperator.AtLeast or CheckOperator.AtMost;
        if (comparison && expected is null)
        {
            throw new RuleFormatException(
                $"{context} : l'opérateur « {op} » exige un champ « expect ».");
        }

        // Deliberately strict requirement. In the Windows registry, an absent key is
        // the common case, not the exception: without a declared default, the rule
        // would produce a random verdict on most machines.
        // Not relevant for a service: its state is directly observable, there is no
        // "value Windows applies when the key is absent".
        if (comparison && windowsDefault is null
            && kind is not (CheckKind.Service or CheckKind.Policy or CheckKind.Wmi))
        {
            throw new RuleFormatException(
                $"{context} : l'opérateur « {op} » exige un champ « windowsDefault » — " +
                "la valeur qu'applique Windows quand la clé est absente. " +
                "Sans elle, une clé manquante donnerait un verdict arbitraire.");
        }

        var valueName = OptionalText(map, "value");

        if (kind == CheckKind.Service && valueName is not null
            && valueName is not ("state" or "startMode"))
        {
            throw new RuleFormatException(
                $"{context} : « value » vaut « state » ou « startMode », reçu « {valueName} ».");
        }

        if (kind == CheckKind.Wmi)
        {
            if (!RequiredText(map, "path", context).Contains(':'))
            {
                throw new RuleFormatException(
                    $"{context} : un contrôle « wmi » attend « path » sous la forme " +
                    "« espaceDeNoms:Classe ».");
            }

            if (valueName is null)
            {
                throw new RuleFormatException(
                    $"{context} : un contrôle « wmi » exige « value », le nom de la propriété. " +
                    "Les énumérer demanderait un SAFEARRAY, hors de portée de l'interop AOT.");
            }
        }

        if (kind == CheckKind.Registry && valueName is null)
        {
            throw new RuleFormatException(
                $"{context} : un contrôle « registry » exige un champ « value ». " +
                "Pour tester l'existence d'une clé, utiliser « type: registryKey ».");
        }

        return new CheckSpec(
            kind, RequiredText(map, "path", context), valueName, op, expected, windowsDefault);
    }

    private static Remediation ReadRemediation(YamlMappingNode map, string context)
    {
        // "impact" used to be a single free-text field. It attracted generalities like
        // "may have side effects", on which no decision can be made.
        if (TryGet(map, "impact") is not null)
        {
            throw new RuleFormatException(
                $"{context} : le champ « impact » est remplacé par « breaks », " +
                "« affects » et, facultativement, « verifyBefore ».");
        }

        return new Remediation(
            ParseEnum<Reversibility>(
                RequiredText(map, "reversibility", context), "reversibility", context),
            Breaks: RequiredText(map, "breaks", context),
            Affects: RequiredText(map, "affects", context),
            VerifyBefore: OptionalText(map, "verifyBefore"));
    }

    // ─ Typed accessors ────────────────────────────────────────────────────────────

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
