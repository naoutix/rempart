using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Reports;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Rendering a comparison, and the fleet page.
///
/// The same two properties as the scan report — machine-supplied strings are escaped,
/// and nothing is fetched from outside the file — plus one specific to this batch: the
/// console, the HTML and the Markdown must not disagree on the verdict, or none of the
/// three can be trusted.
/// </summary>
public sealed class DiffReportTests
{
    private const string Payload = "<script>alert('xss')</script>";

    [Fact]
    public void The_three_formats_state_the_same_headline()
    {
        var diff = Regressed();
        var headline = DiffReport.Headline(diff);

        Assert.Contains("1 régression(s)", headline, StringComparison.Ordinal);
        Assert.Contains(headline, DiffReport.Html(diff), StringComparison.Ordinal);
        Assert.Contains(headline, DiffReport.Markdown(diff), StringComparison.Ordinal);
    }

    /// <summary>
    /// The comparison is built from the same machine-chosen strings the report is, and
    /// gets read in the same browser.
    /// </summary>
    [Fact]
    public void The_comparison_escapes_markup_from_the_machine()
    {
        var diff = ScanDiff.Compare(
            Scan(),
            Scan() with
            {
                Findings =
                [
                    new Finding(Payload, Payload, Payload, FindingSeverity.Suspicious,
                        [Payload], new Dictionary<string, string>()),
                ],
                Collectors = [Inventory(Payload)],
            });

        var html = DiffReport.Html(diff);

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Equal(1, Occurrences(html, "</script>"));
    }

    [Fact]
    public void The_comparison_references_nothing_outside_itself()
    {
        var html = DiffReport.Html(Regressed());

        foreach (var reference in new[] { "<link", "<img", " src=", " href=", "@import", "url(" })
        {
            Assert.DoesNotContain(reference, html, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// A comparison opening on its good news reads as good news. Regressions come first
    /// in every format, and the section order is shared so they cannot drift apart.
    /// </summary>
    [Fact]
    public void What_got_worse_comes_before_what_got_better()
    {
        var html = DiffReport.Html(Regressed());

        var regressions = html.IndexOf("Régressions", StringComparison.Ordinal);
        var corrections = html.IndexOf("Corrections", StringComparison.Ordinal);

        Assert.True(regressions > 0 && corrections > 0);
        Assert.True(regressions < corrections,
            "Les corrections apparaissent avant les régressions.");
    }

    [Fact]
    public void The_bundle_carries_the_three_formats_and_the_json_is_readable()
    {
        var files = DiffReport.Build(Regressed());

        Assert.Equal(
            [DiffReport.HtmlName, DiffReport.MarkdownName, DiffReport.JsonName],
            files.Select(f => f.Name));

        var json = files.Single(f => f.Name == DiffReport.JsonName).Content;
        Assert.Contains("\"regression\"", json.ToLowerInvariant(), StringComparison.Ordinal);
    }

    [Fact]
    public void Rendering_twice_gives_the_same_bytes()
    {
        Assert.Equal(DiffReport.Html(Regressed()), DiffReport.Html(Regressed()));
        Assert.Equal(DiffReport.Markdown(Regressed()), DiffReport.Markdown(Regressed()));
    }

    // ---- fleet page --------------------------------------------------------

    /// <summary>
    /// The page answers "which machine next", so the order is the answer. A report that
    /// could not be scored sits at the top: nothing was measured there, which is a
    /// reason to look rather than a reason to skip.
    /// </summary>
    [Fact]
    public void The_fleet_is_ordered_by_what_is_left_to_do()
    {
        var ordered = FleetIndex.Ordered(
        [
            Entry("POSTE-SAIN", 96),
            Entry("POSTE-MOYEN", 58),
            Entry("POSTE-MUET", null),
            Entry("POSTE-FAIBLE", 31),
        ]).Select(e => e.Machine);

        Assert.Equal(["POSTE-MUET", "POSTE-FAIBLE", "POSTE-MOYEN", "POSTE-SAIN"], ordered);
    }

    /// <summary>
    /// Percentages computed against different catalogs are not on the same scale.
    /// Sorting them silently would rank machines on a number that changes meaning from
    /// one row to the next.
    /// </summary>
    [Fact]
    public void A_fleet_spanning_two_catalogs_says_so()
    {
        var html = FleetIndex.Render(
        [
            Entry("POSTE-01", 58) with { RulesFingerprint = "82:aaaa" },
            Entry("POSTE-02", 91) with { RulesFingerprint = "91:bbbb" },
        ]);

        Assert.Contains("catalogues de règles différents", html, StringComparison.Ordinal);
        Assert.Contains("même échelle", html, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_folder_produces_a_page_that_says_so_rather_than_a_blank_one()
    {
        var html = FleetIndex.Render([]);

        Assert.Contains("Aucun rapport", html, StringComparison.Ordinal);
        Assert.Contains("scan --report", html, StringComparison.Ordinal);
    }

    [Fact]
    public void A_machine_name_carrying_markup_is_escaped_on_the_fleet_page()
    {
        var html = FleetIndex.Render([Entry(Payload, 50)]);

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    // ---- builders ----------------------------------------------------------

    private static FleetEntry Entry(string machine, int? score) =>
        new(machine, "2026-07-24", $"{machine}/rapport.json", score, 4, 1, 2, "82:c3e6", true);

    private static DiffResult Regressed() => ScanDiff.Compare(
        Scan() with
        {
            Verdicts =
            [
                new Verdict("WIN-A-001", "Contrôle A", Severity.High, "réseau",
                    VerdictStatus.Pass, "1", "1"),
                new Verdict("WIN-B-001", "Contrôle B", Severity.Medium, "defender",
                    VerdictStatus.Fail, "0", "1"),
            ],
            Score = new ScoreCard(70, [new DomainScore("réseau", 1, 0, 0, 0, 70)], 0),
        },
        Scan() with
        {
            Verdicts =
            [
                new Verdict("WIN-A-001", "Contrôle A", Severity.High, "réseau",
                    VerdictStatus.Fail, "0", "1"),
                new Verdict("WIN-B-001", "Contrôle B", Severity.Medium, "defender",
                    VerdictStatus.Pass, "1", "1"),
            ],
            Score = new ScoreCard(55, [new DomainScore("réseau", 0, 1, 0, 0, 40)], 0),
        });

    private static CollectorResult Inventory(string machine) =>
        new("inventory", CollectorStatus.Ok,
            new Dictionary<string, string?> { ["machine.name"] = machine }, []);

    private static ScanResult Scan() => new(
        ToolVersion: "0.6.0",
        StartedAtUtc: "2026-07-24T09:15:00Z",
        Collectors: [Inventory("POSTE-01")],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "82:c3e6e3029b12",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));

    private static int Occurrences(string haystack, string needle)
    {
        var count = 0;
        var index = haystack.IndexOf(needle, StringComparison.Ordinal);

        while (index >= 0)
        {
            count++;
            index = haystack.IndexOf(needle, index + needle.Length, StringComparison.Ordinal);
        }

        return count;
    }
}
