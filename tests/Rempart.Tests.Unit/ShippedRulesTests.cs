using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// Checks on the shipped catalog, not on the engine. These tests maintain rule
/// quality as rules are added over time; the engine itself is stable.
/// </summary>
public sealed class ShippedRulesTests
{
    private static readonly IReadOnlyList<Rule> Rules = RuleCatalog.Load();

    [Fact]
    public void The_shipped_catalog_loads()
    {
        // Also covers the loader's strict validation: any malformed rule added to
        // the repository fails this test.
        Assert.NotEmpty(Rules);
    }

    [Fact]
    public void No_rule_targets_a_protected_component()
    {
        // Guarantee D7 of ADR-001. Edge/WebView2, the Store, App Installer and
        // Windows Update are out of reach of any rule, including one added by
        // mistake in a pull request.
        Assert.Empty(ProtectedComponents.FindViolations(Rules));
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend")]
    [InlineData(@"HKLM\SOFTWARE\Classes\Microsoft.MicrosoftEdge")]
    public void The_protection_actually_catches_forbidden_paths(string path)
    {
        // Verifies the blocklist actually matches. Without this test, an empty or
        // misspelled list would go unnoticed: the previous test would stay green.
        Assert.True(ProtectedComponents.IsProtected(path), $"devrait être protégé : {path}");
    }

    [Fact]
    public void Identifiers_are_unique_across_every_file()
    {
        // Identifiers appear in reports and will be referenced by remediation
        // profiles: a duplicate would make a report ambiguous.
        var duplicates = Rules.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key);

        Assert.Empty(duplicates);
    }

    [Fact]
    public void Every_rule_explains_why_it_exists()
    {
        // A check without a rationale produces a verdict nobody can arbitrate.
        // The minimum length rejects placeholders like "because it is better".
        var terse = Rules.Where(r => r.Rationale.Length < 80).Select(r => r.Id);

        Assert.Empty(terse);
    }

    [Fact]
    public void Serious_rules_cite_an_external_baseline()
    {
        // Tying serious rules to CIS or Essential Eight avoids an arbitrary
        // home-grown score and gives a defensible basis to discuss a verdict.
        var unsourced = Rules
            .Where(r => r.Severity >= Severity.High && r.References.Count == 0)
            .Select(r => r.Id);

        Assert.Empty(unsourced);
    }

    [Fact]
    public void Every_remediation_says_what_breaks_and_who_is_affected()
    {
        // In M9 these two fields will decide whether an action is safe to apply.
        // A single free-text field would fill up with generalities; the minimum
        // length rejects unverified "no known impact" entries.
        var rules = Rules.Where(r => r.Remediation is not null).ToList();

        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.True(rule.Remediation!.Breaks.Length > 40, $"{rule.Id} : « breaks » trop vague");
            Assert.True(rule.Remediation.Affects.Length > 40, $"{rule.Id} : « affects » trop vague");
        });
    }

    [Fact]
    public void Risky_remediations_explain_how_to_check_beforehand()
    {
        // Beyond trivially reversible changes, a remediation must tell the user
        // how to assess the risk before applying it.
        var unchecked_ = Rules
            .Where(r => r.Remediation is { Reversibility: not Reversibility.Trivial })
            .Where(r => string.IsNullOrWhiteSpace(r.Remediation!.VerifyBefore))
            .Select(r => r.Id);

        Assert.Empty(unchecked_);
    }

    [Fact]
    public void Domains_stay_a_small_stable_set()
    {
        // Scores are reported per domain. One domain per rule would make the table
        // unreadable and the per-domain score meaningless.
        var domains = Rules.Select(r => r.Domain).Distinct(StringComparer.OrdinalIgnoreCase);

        Assert.True(domains.Count() <= Rules.Count / 2,
            "trop de domaines distincts par rapport au nombre de règles");
    }
}
