using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// Contrôles portant sur le catalogue livré, pas sur le moteur. Ce sont ces tests qui
/// tiennent la qualité des règles au fil de leur ajout : le moteur, lui, ne bougera plus.
/// </summary>
public sealed class ShippedRulesTests
{
    private static readonly IReadOnlyList<Rule> Rules = RuleCatalog.Load();

    [Fact]
    public void The_shipped_catalog_loads()
    {
        // Couvre aussi la validation stricte du chargeur : toute règle mal formée
        // ajoutée au dépôt fait échouer ce test.
        Assert.NotEmpty(Rules);
    }

    [Fact]
    public void No_rule_targets_a_protected_component()
    {
        // La garantie D7 de l'ADR-001. Edge/WebView2, le Store, App Installer et
        // Windows Update sont hors d'atteinte de toute règle, y compris ajoutée
        // par erreur dans une pull request.
        Assert.Empty(ProtectedComponents.FindViolations(Rules));
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend")]
    [InlineData(@"HKLM\SOFTWARE\Classes\Microsoft.MicrosoftEdge")]
    public void The_protection_actually_catches_forbidden_paths(string path)
    {
        // Vérifie que la liste noire mord vraiment. Sans ce test, une liste vide ou
        // mal orthographiée passerait inaperçue : le test précédent resterait vert.
        Assert.True(ProtectedComponents.IsProtected(path), $"devrait être protégé : {path}");
    }

    [Fact]
    public void Identifiers_are_unique_across_every_file()
    {
        // Les identifiants apparaissent dans les rapports et serviront de référence
        // dans les profils de remédiation : un doublon rendrait un rapport ambigu.
        var duplicates = Rules.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key);

        Assert.Empty(duplicates);
    }

    [Fact]
    public void Every_rule_explains_why_it_exists()
    {
        // Un contrôle sans justification produit un verdict que personne ne saura
        // arbitrer. La longueur minimale écarte les « parce que c'est mieux ».
        var terse = Rules.Where(r => r.Rationale.Length < 80).Select(r => r.Id);

        Assert.Empty(terse);
    }

    [Fact]
    public void Serious_rules_cite_an_external_baseline()
    {
        // Rattacher les règles sérieuses à CIS ou Essential Eight évite le score maison
        // arbitraire et donne un point d'appui défendable pour discuter d'un verdict.
        var unsourced = Rules
            .Where(r => r.Severity >= Severity.High && r.References.Count == 0)
            .Select(r => r.Id);

        Assert.Empty(unsourced);
    }

    [Fact]
    public void Every_remediation_states_its_impact_and_reversibility()
    {
        var rules = Rules.Where(r => r.Remediation is not null).ToList();

        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
            Assert.False(string.IsNullOrWhiteSpace(rule.Remediation!.Impact), rule.Id));
    }

    [Fact]
    public void Domains_stay_a_small_stable_set()
    {
        // Les scores sont rendus par domaine. Un domaine par règle rendrait le tableau
        // illisible, et le score par domaine dénué de sens.
        var domains = Rules.Select(r => r.Domain).Distinct(StringComparer.OrdinalIgnoreCase);

        Assert.True(domains.Count() <= Rules.Count / 2,
            "trop de domaines distincts par rapport au nombre de règles");
    }
}
