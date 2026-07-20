using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// Le chargeur refuse tout fichier douteux plutôt que d'en ignorer une partie.
/// Une règle silencieusement écartée produirait un audit qui paraît complet en
/// ayant sauté un contrôle — le pire mode de défaillance pour cet outil.
/// </summary>
public sealed class RuleLoaderTests
{
    private const string Valid = """
        - id: TEST-001
          title: Un contrôle
          severity: high
          domain: test
          rationale: Parce que.
          references: [CIS-1.2.3]
          check:
            type: registry
            path: HKLM\SOFTWARE\Test
            value: Flag
            operator: equals
            expect: "1"
            windowsDefault: "0"
        """;

    [Fact]
    public void Reads_a_complete_rule()
    {
        var rule = Assert.Single(RuleLoader.Load(Valid));

        Assert.Equal("TEST-001", rule.Id);
        Assert.Equal(Severity.High, rule.Severity);
        Assert.Equal("test", rule.Domain);
        Assert.Equal(["CIS-1.2.3"], rule.References);
        Assert.Equal(CheckKind.Registry, rule.Check.Kind);
        Assert.Equal(CheckOperator.Equals, rule.Check.Operator);
        Assert.Equal("1", rule.Check.Expected);
        Assert.Equal("0", rule.Check.WindowsDefault);
    }

    [Fact]
    public void Defaults_to_equality_when_no_operator_is_given()
    {
        var yaml = Valid.Replace("    operator: equals\n", string.Empty);

        Assert.Equal(CheckOperator.Equals, RuleLoader.Load(yaml)[0].Check.Operator);
    }

    [Theory]
    [InlineData("id")]
    [InlineData("title")]
    [InlineData("severity")]
    [InlineData("domain")]
    [InlineData("rationale")]
    public void Rejects_a_rule_missing_a_required_field(string field)
    {
        // La clé est conservée et sa valeur vidée. Supprimer la ligne « id » entière
        // détruirait la séquence YAML : on testerait la détection d'un document
        // malformé, pas celle d'un champ manquant.
        var yaml = string.Join('\n', Valid.Split('\n').Select(line =>
            line.TrimStart('-', ' ').StartsWith($"{field}:", StringComparison.Ordinal)
                ? line[..(line.IndexOf(':') + 1)]
                : line));

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml));
        Assert.Contains(field, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_an_unknown_severity_and_lists_the_valid_ones()
    {
        var yaml = Valid.Replace("severity: high", "severity: critique");

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml));

        // Le message doit permettre de corriger sans consulter la documentation.
        Assert.Contains("critique", ex.Message, StringComparison.Ordinal);
        Assert.Contains("critical", ex.Message, StringComparison.Ordinal);
        Assert.Contains("TEST-001", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_duplicate_identifiers()
    {
        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(Valid + '\n' + Valid));

        Assert.Contains("double", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_a_comparison_without_expected_value()
    {
        var yaml = Valid.Replace("    expect: \"1\"\n", string.Empty);

        Assert.Contains("expect", Assert.Throws<RuleFormatException>(
            () => RuleLoader.Load(yaml)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_a_comparison_without_a_declared_windows_default()
    {
        // L'exigence est le coeur de la justesse des regles : sur le registre Windows,
        // une cle absente est le cas courant, pas l'exception.
        var yaml = Valid.Replace("    windowsDefault: \"0\"", string.Empty);

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml));

        Assert.Contains("windowsDefault", ex.Message, StringComparison.Ordinal);
        Assert.Contains("absente", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Presence_checks_need_no_expected_value_nor_default()
    {
        var yaml = """
            - id: TEST-002
              title: Une clé qui ne doit pas exister
              severity: medium
              domain: test
              rationale: Parce que.
              check:
                type: registryKey
                path: HKLM\SOFTWARE\Test
                operator: absent
            """;

        Assert.Equal(CheckOperator.Absent, RuleLoader.Load(yaml)[0].Check.Operator);
    }

    [Fact]
    public void Rejects_a_registry_value_check_without_a_value_name()
    {
        var yaml = Valid.Replace("    value: Flag\n", string.Empty);

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml));

        // Le message doit orienter vers le bon type plutôt que constater l'absence.
        Assert.Contains("registryKey", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Reports_the_origin_and_the_rule_in_error_messages()
    {
        var yaml = Valid.Replace("severity: high", "severity: enorme");

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml, "credentials.yaml"));

        Assert.Contains("credentials.yaml", ex.Message, StringComparison.Ordinal);
        Assert.Contains("TEST-001", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Reads_remediation_metadata_when_present()
    {
        var yaml = Valid + """

              remediation:
                reversibility: restorePointOnly
                breaks: Le partage de fichiers avec les périphériques anciens.
                affects: Les postes reliés à un NAS d'avant 2010.
                verifyBefore: Activer l'audit et observer pendant une semaine.
            """;

        var remediation = RuleLoader.Load(yaml)[0].Remediation;

        Assert.NotNull(remediation);
        Assert.Equal(Reversibility.RestorePointOnly, remediation.Reversibility);
        Assert.StartsWith("Le partage", remediation.Breaks, StringComparison.Ordinal);
        Assert.StartsWith("Les postes", remediation.Affects, StringComparison.Ordinal);
        Assert.NotNull(remediation.VerifyBefore);
    }

    [Fact]
    public void Rejects_the_old_free_text_impact_field()
    {
        // Le champ unique attirait les generalites -- « peut avoir des effets de bord »
        // -- sur lesquelles aucune decision ne se prend. Echouer explicitement vaut
        // mieux que d'ignorer en silence une remediation redigee a l'ancienne.
        var yaml = Valid + """

              remediation:
                reversibility: trivial
                impact: Peut casser des choses.
            """;

        var ex = Assert.Throws<RuleFormatException>(() => RuleLoader.Load(yaml));

        Assert.Contains("breaks", ex.Message, StringComparison.Ordinal);
        Assert.Contains("affects", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_document_yields_no_rules()
    {
        Assert.Empty(RuleLoader.Load(string.Empty));
    }
}
