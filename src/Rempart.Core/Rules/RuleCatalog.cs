using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Rempart.Core.Rules;

/// <summary>
/// The shipped rules, embedded in the binary, optionally supplemented by an external
/// directory.
///
/// Embedded rather than read from disk: the binary must stay self-contained on a USB
/// stick, with no companion folder one could forget to copy. The external directory is
/// a supplement — to iterate on rules without recompiling, and to carry fleet-specific
/// checks the shipped catalog has no business knowing about.
///
/// A rule remains declarative data: it reads the registry, it executes nothing.
/// Loading an external directory therefore opens no execution surface.
/// </summary>
public static class RuleCatalog
{
    /// <summary>
    /// Reference date of the embedded data: when the shipped catalog was last
    /// reviewed.
    ///
    /// <para>
    /// Declared by hand, for lack of a reliable automatic source: the binary ships as
    /// AOT, with no usable compilation date, and a date derived from the file system
    /// would not survive caching. <b>Must be advanced with every material revision of
    /// the catalog</b> — otherwise the report would claim fresher data than it
    /// actually has, exactly the lie D15 is meant to prevent.
    /// </para>
    ///
    /// <para>
    /// It is a floor: once <c>rempart update</c> loads signed data, its publication
    /// date takes over (ADR-002, D15).
    /// </para>
    /// </summary>
    public const string EmbeddedAsOfUtc = "2026-07-21T00:00:00Z";

    private static IReadOnlyList<Rule>? cachedEmbedded;

    /// <param name="externalDirectory">
    /// Directory of additional YAML files, walked recursively. Identifiers must stay
    /// unique: a collision with the shipped catalog is an error, not a silent
    /// redefinition.
    /// </param>
    public static IReadOnlyList<Rule> Load(string? externalDirectory = null)
    {
        var rules = new List<Rule>(LoadEmbedded());

        if (externalDirectory is not null)
        {
            rules.AddRange(LoadExternal(externalDirectory));
        }

        // The check happens here, across files: the loader only sees one file at a
        // time and cannot spot a duplicate spread over two sources.
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

    /// <summary>
    /// Fingerprint of the evaluated rule set.
    ///
    /// Two reports with the same score are only comparable if they were produced by
    /// the same catalog. Without this fingerprint, a gap between two machines could
    /// come from a rule change rather than a configuration change — and nothing
    /// would tell them apart. Essential for "rempart diff" (M7).
    /// </summary>
    public static string Fingerprint(IReadOnlyList<Rule> rules)
    {
        var builder = new StringBuilder();

        foreach (var rule in rules.OrderBy(r => r.Id, StringComparer.Ordinal))
        {
            builder.Append(RuleContent(rule)).Append('\n');
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()));
        return $"{rules.Count}:{Convert.ToHexStringLower(digest)[..12]}";
    }

    /// <summary>
    /// Fingerprint of a single rule, over the same fields as <see cref="Fingerprint"/>.
    ///
    /// Extracted so that the diff of an update (ADR-002, D14) judges a change by the
    /// same yardstick as the catalog fingerprint: two rules with the same identifier
    /// only differ if one of these fields changes. A second definition of "what
    /// matters in a rule" would sooner or later diverge from this one.
    /// </summary>
    public static string RuleFingerprint(Rule rule) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(RuleContent(rule))))[..12];

    /// <summary>
    /// Identifier, severity, target and default: everything that changes a verdict.
    /// The title and rationale are not part of it — a rewording must neither make two
    /// reports incomparable nor wrongly mark an update as "modified".
    /// </summary>
    private static string RuleContent(Rule rule) =>
        string.Join('|',
            rule.Id, rule.Severity, rule.Check.Path, rule.Check.ValueName,
            rule.Check.Operator, rule.Check.Expected, rule.Check.WindowsDefault);

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

        // Loading fails rather than silently delivering an empty catalog:
        // a scan without rules would produce a perfectly green report.
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
            // An explicitly passed empty directory is most likely a path mistake.
            // Reporting it avoids a scan that merely looks complete.
            throw new RuleFormatException($"Aucun fichier .yaml dans : {directory}");
        }

        var rules = new List<Rule>();
        foreach (var file in files)
        {
            rules.AddRange(RuleLoader.Load(File.ReadAllText(file), file));
        }

        // The blocklist applies to external rules like any other: that is precisely
        // where an unreviewed rule could target a critical component.
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
