using Rempart.Core.Cli;
using Rempart.Core.Rules;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Surfaces what the scan cannot display: the rationale, the references, and the
/// real cost of a fix. Without this command, that information only existed in the
/// YAML files — written down, but out of reach in practice.
/// </summary>
internal static class ExplainCommand
{
    public static int Run(string[] args)
    {
        // Through Positional, not from a fixed slot. Read at index 1, the identifier of
        // "rempart explain --rules ./mes-regles WIN-CRED-001" was "--rules": no identifier
        // found, so the command listed the whole catalog instead of explaining the rule
        // asked for — and said nothing, since listing is what an argument-less explain
        // legitimately does (DET-EXPLAIN-POSITIONNEL). Positional skips an option and the
        // value it carries, so the identifier is found wherever it is written. WordAt stays
        // right for the command word at index 0, which nothing can precede.
        var positional = Positional(args, CommandSurface.ValueTaking("explain"));
        var id = positional.Count > 0 ? positional[0] : null;
        var rules = RuleCatalog.Load(RulesDirectory(args));

        if (id is null)
        {
            Console.WriteLine($"{rules.Count} contrôles :");
            foreach (var group in rules.GroupBy(r => r.Domain).OrderBy(g => g.Key, StringComparer.Ordinal))
            {
                Console.WriteLine();
                Console.WriteLine($"  {group.Key}");
                foreach (var rule in group)
                {
                    Console.WriteLine($"    {rule.Id,-14} {rule.Severity,-8} {rule.Title}");
                }
            }

            return 0;
        }

        var found = rules.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
        if (found is null)
        {
            Console.Error.WriteLine($"Règle inconnue : {id}. « rempart explain » liste les contrôles.");
            return 1;
        }

        Console.WriteLine($"{found.Id} — {found.Title}");
        Console.WriteLine($"  sévérité   {found.Severity}");
        Console.WriteLine($"  domaine    {found.Domain}");
        if (found.References.Count > 0)
        {
            Console.WriteLine($"  références {string.Join(", ", found.References)}");
        }

        Console.WriteLine();
        Console.WriteLine("Pourquoi");
        WriteWrapped(found.Rationale);

        Console.WriteLine();
        Console.WriteLine("Ce qui est vérifié");
        Console.WriteLine($"  {found.Check.Path}");
        if (found.Check.ValueName is { } value)
        {
            Console.WriteLine($"  valeur « {value} » {found.Check.Operator} {found.Check.Expected}");
        }
        else
        {
            Console.WriteLine($"  la clé doit être {found.Check.Operator}");
        }

        if (found.Check.WindowsDefault is { } fallback)
        {
            Console.WriteLine($"  si la valeur est absente, Windows applique : {fallback}");
        }

        if (found.Remediation is not { } remediation)
        {
            Console.WriteLine();
            Console.WriteLine("Correction");
            Console.WriteLine("  Aucune remédiation décrite pour cette règle.");
            return 0;
        }

        Console.WriteLine();
        Console.WriteLine($"Correction — réversibilité : {remediation.Reversibility}");
        Console.WriteLine("  Ce qui cesse de fonctionner");
        WriteWrapped(remediation.Breaks, "    ");
        Console.WriteLine("  Qui est concerné");
        WriteWrapped(remediation.Affects, "    ");

        if (remediation.VerifyBefore is { } verify)
        {
            Console.WriteLine("  À vérifier avant d'appliquer");
            WriteWrapped(verify, "    ");
        }

        Console.WriteLine();
        Console.WriteLine("  La v1 n'applique aucune correction : elle constate et documente.");

        return 0;
    }

    private static void WriteWrapped(string text, string indent = "  ")
    {
        var words = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var line = new System.Text.StringBuilder(indent);

        foreach (var word in words)
        {
            if (line.Length + word.Length + 1 > 88)
            {
                Console.WriteLine(line.ToString());
                line.Clear().Append(indent);
            }

            line.Append(word).Append(' ');
        }

        if (line.Length > indent.Length)
        {
            Console.WriteLine(line.ToString().TrimEnd());
        }
    }
}
