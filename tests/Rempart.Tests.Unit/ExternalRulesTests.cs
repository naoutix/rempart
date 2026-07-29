using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// The external directory is for iterating on rules without recompiling, and for
/// fleet-specific checks. It supplements the shipped catalog, it does not replace it.
/// </summary>
public sealed class ExternalRulesTests : IDisposable
{
    private readonly string directory = Directory.CreateTempSubdirectory("rempart-rules").FullName;

    private const string Extra = """
        - id: LOCAL-001
          title: Un contrôle propre au parc
          severity: medium
          domain: local
          rationale: >
            Vérifie un réglage interne que le catalogue livré n'a pas à connaître,
            parce qu'il ne concerne que ce parc précis.
          check:
            type: registry
            path: HKLM\SOFTWARE\Interne
            value: Reglage
            operator: equals
            expect: "1"
            windowsDefault: "0"
        """;

    private static readonly string Second =
        Extra.Replace("LOCAL-001", "LOCAL-002", StringComparison.Ordinal);

    public void Dispose() => Directory.Delete(directory, recursive: true);

    [Fact]
    public void External_rules_come_in_addition_to_the_shipped_ones()
    {
        Write("local.yaml", Extra);

        var rules = RuleCatalog.Load(directory);

        Assert.Contains(rules, r => r.Id == "LOCAL-001");
        Assert.Contains(rules, r => r.Id.StartsWith("WIN-", StringComparison.Ordinal));
    }

    [Fact]
    public void Without_a_directory_only_the_shipped_rules_are_loaded()
    {
        Assert.DoesNotContain(RuleCatalog.Load(), r => r.Id == "LOCAL-001");
    }

    [Fact]
    public void An_external_rule_cannot_silently_redefine_a_shipped_one()
    {
        // A tacit redefinition would make two machines diverge with nothing in
        // the report to show it.
        Write("collision.yaml", Extra.Replace("LOCAL-001", "WIN-CRED-001"));

        var ex = Assert.Throws<RuleFormatException>(() => RuleCatalog.Load(directory));

        Assert.Contains("WIN-CRED-001", ex.Message, StringComparison.Ordinal);
        Assert.Contains("double", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Subdirectories_are_explored()
    {
        Directory.CreateDirectory(Path.Combine(directory, "parc"));
        Write(Path.Combine("parc", "local.yaml"), Extra);

        Assert.Contains(RuleCatalog.Load(directory), r => r.Id == "LOCAL-001");
    }

    [Fact]
    public void A_missing_directory_is_an_error_not_a_silent_skip()
    {
        var missing = Path.Combine(directory, "absent");

        var ex = Assert.Throws<RuleFormatException>(() => RuleCatalog.Load(missing));

        Assert.Contains(missing, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_directory_is_reported_rather_than_ignored()
    {
        // Almost always a path mistake. Ignoring it would give a scan that looks
        // complete while having loaded zero extra rules.
        var ex = Assert.Throws<RuleFormatException>(() => RuleCatalog.Load(directory));

        // The message is where the user learns how to name their files; naming only
        // half the accepted spellings is how the other half got written by mistake.
        Assert.Contains(".yaml", ex.Message, StringComparison.Ordinal);
        Assert.Contains(".yml", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Both_spellings_of_the_extension_are_loaded_from_a_mixed_directory()
    {
        // A directory holding one of each used to load the ".yaml" and drop the
        // ".yml" without a word, the file count being non-zero.
        Write("a.yaml", Extra);
        Write("b.yml", Second);

        var rules = RuleCatalog.Load(directory);

        Assert.Contains(rules, r => r.Id == "LOCAL-001");
        Assert.Contains(rules, r => r.Id == "LOCAL-002");
    }

    [Fact]
    public void A_directory_holding_only_the_short_spelling_is_loaded()
    {
        Write("local.yml", Extra);

        Assert.Contains(RuleCatalog.Load(directory), r => r.Id == "LOCAL-001");
    }

    [Fact]
    public void Neither_the_spelling_nor_a_document_separator_moves_the_fingerprint()
    {
        // The fingerprint is what says whether two reports are comparable. It must
        // follow the rules loaded, never how the file carrying them was named or
        // punctuated -- otherwise a reformatting would read as a catalog change.
        Write("un-seul.yaml", $"{Extra}\n{Second}");
        var joined = RuleCatalog.Fingerprint(RuleCatalog.Load(directory));

        File.Delete(Path.Combine(directory, "un-seul.yaml"));
        Write("coupe-en-deux.yml", $"{Extra}\n---\n{Second}");

        Assert.Equal(joined, RuleCatalog.Fingerprint(RuleCatalog.Load(directory)));
    }

    [Fact]
    public void A_malformed_external_file_names_the_file_in_the_error()
    {
        Write("casse.yaml", Extra.Replace("severity: medium", "severity: enorme"));

        var ex = Assert.Throws<RuleFormatException>(() => RuleCatalog.Load(directory));

        Assert.Contains("casse.yaml", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void External_rules_are_held_to_the_protected_component_list()
    {
        // This is where the guardrail matters most: an external rule was never
        // reviewed in a pull request.
        Write("dangereux.yaml", Extra
            .Replace(@"HKLM\SOFTWARE\Interne", @"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv")
            + """

              remediation:
                reversibility: trivial
                breaks: Les mises à jour de sécurité cessent d'être installées.
                affects: Toutes les machines, sans exception ni cas particulier.
            """);

        var ex = Assert.Throws<RuleFormatException>(() => RuleCatalog.Load(directory));

        Assert.Contains("protégé", ex.Message, StringComparison.Ordinal);
    }

    private void Write(string name, string content) =>
        File.WriteAllText(Path.Combine(directory, name), content);
}
