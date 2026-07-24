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
        Assert.Throws<RuleFormatException>(() => RuleCatalog.Load(directory));
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
