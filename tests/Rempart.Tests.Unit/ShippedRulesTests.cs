using System.Globalization;
using System.Text.RegularExpressions;
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

    /// <summary>
    /// The figures the documents give for the catalog are the figures the catalog has.
    ///
    /// <para>
    /// Same guard as the one holding the line count of <c>Program.cs</c>, over the other set of
    /// numbers this repository writes into prose, and written for the same reason: three
    /// passages said « 29 non-empty lines » long after the file reached forty, and
    /// <c>CONTRIBUTING</c> said « 827 tests » long after the suite passed a thousand. The second
    /// of those has been deleted rather than held — a test count cannot be read from a checkout
    /// and moves on nearly every pull request, and the reasoning is written where the line was.
    /// The catalog's size is the opposite on both counts: it is read from <c>rules/security/</c>,
    /// it is the same on every machine, and it changes when somebody decides to change it.
    /// </para>
    ///
    /// <para>
    /// <b>« checks » here means catalog rules.</b> These documents use the two words for the
    /// same thing — « 82 checks across 13 domains », « the 82 shipped rules » — so the pattern
    /// reads both. The five checks CI runs are spelled out in words in <c>CONTRIBUTING</c>,
    /// which is what keeps them out of this reading.
    /// </para>
    ///
    /// <para>
    /// The count of examined claims is asserted before the claims themselves. A guard that finds
    /// nothing to check passes on any number whatsoever, which is the state a reworded sentence
    /// would leave this one in, and it is the failure mode the whole file exists against.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_document_that_counts_the_shipped_rules_counts_them_right()
    {
        (string Pattern, int Measured, string Subject)[] claims =
        [
            (@"(\d+) (?:shipped )?(?:rules|checks)\b", Rules.Count, "règles du catalogue"),

            (@"(\d+) of the \d+ shipped rules legitimately carry none",
                Rules.Count(rule => rule.Check.WindowsDefault is null),
                "règles sans windowsDefault"),

            (@"(\d+) domains\b",
                Rules.Select(rule => rule.Domain).Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count(),
                "domaines distincts"),
        ];

        var wrong = new List<string>();

        foreach (var (pattern, measured, subject) in claims)
        {
            var examined = 0;

            foreach (var document in Describing)
            {
                // Read as one line: every claim below spans a line break in at least one of
                // these files, and a sentence held together only by where it happens to wrap
                // is a sentence this guard would stop reading the day someone reflowed it.
                var text = Regex.Replace(RepositoryFiles.Read(document), @"\s+", " ");

                foreach (Match claim in Regex.Matches(text, pattern))
                {
                    examined++;

                    if (int.Parse(claim.Groups[1].Value, CultureInfo.InvariantCulture) != measured)
                    {
                        wrong.Add($"{document} → « {claim.Value.Trim()} », mesuré {measured}");
                    }
                }
            }

            Assert.True(examined > 0,
                $"Aucun des documents qui décrivent l'outil tel qu'il est ne chiffre les "
                + $"{subject}, ou plus dans une forme que cette garde reconnaît : elle passerait "
                + "au vert quel que soit le chiffre écrit.");
        }

        Assert.True(wrong.Count == 0,
            "La documentation chiffre le catalogue autrement qu'il n'est : "
            + string.Join(" ; ", wrong)
            + ". Un chiffre que personne ne remesure décrit un dossier que tout le monde peut "
            + "compter.");
    }

    /// <summary>
    /// The documents that describe the tool <em>as it stands</em>, and are therefore falsified by
    /// a rule being added rather than merely dated by one. <c>docs/adr/</c> and
    /// <c>docs/ROADMAP.md</c> stay out for the reason #180 fixed: an ADR records what a decision
    /// did on the day it was taken, and correcting a dated record to today's figure falsifies it.
    /// </summary>
    private static readonly string[] Describing =
        ["README.md", "CONTRIBUTING.md", "docs/ARCHITECTURE.md", "docs/DEBT.md"];
}
