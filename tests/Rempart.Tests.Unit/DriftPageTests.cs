using Rempart.Core.Reports;

namespace Rempart.Tests.Unit;

/// <summary>
/// What a series looks like to whoever reads it.
///
/// The page is built from strings the audited machine chose — machine names, rule titles —
/// so escaping is pinned here for the same reason M6 pins it on the report: this is the one
/// place in the project where a formatting mistake becomes a vulnerability.
/// </summary>
public sealed class DriftPageTests
{
    [Fact]
    public void Everything_the_machine_chose_is_escaped()
    {
        var html = DriftPage.Render([DriftFixtures.Clean("<script>alert(1)</script>")]);

        Assert.DoesNotContain("<script>alert(1)</script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    /// <summary>
    /// A rule title travels from a YAML file into the page just as a machine name does, and
    /// a catalog loaded from a stick's <c>rules/</c> folder is not written by this
    /// repository. Escaped on the same footing.
    /// </summary>
    [Fact]
    public void A_rule_title_is_escaped_like_everything_else()
    {
        var html = DriftPage.Render([DriftFixtures.Drifted("<img src=x onerror=alert(1)>")]);

        Assert.DoesNotContain("<img src=x", html);
        Assert.Contains("&lt;img", html);
    }

    /// <summary>
    /// A stale series opens on what limits it, before any figure — the rule M6 set for a
    /// non-elevated scan, for the same reason: a number read without its caveat is worse
    /// than no number.
    /// </summary>
    [Fact]
    public void A_stale_series_says_so_before_any_figure()
    {
        var html = DriftPage.Render([DriftFixtures.Stale()]);

        Assert.True(
            html.IndexOf("dernière capture", StringComparison.Ordinal)
            < html.IndexOf("<table", StringComparison.Ordinal),
            "la péremption doit être dite avant le premier tableau");
    }

    [Fact]
    public void A_fresh_series_carries_no_staleness_banner()
    {
        Assert.DoesNotContain("dernière capture", DriftPage.Render([DriftFixtures.Clean()]));
    }

    [Fact]
    public void An_empty_folder_says_so_rather_than_rendering_an_empty_table()
    {
        var html = DriftPage.Render([]);

        Assert.Contains("Aucun rapport", html);
        Assert.DoesNotContain("<table", html);
    }

    /// <summary>
    /// Nobody prunes, so the page owes the reader the cost of that choice: how far back the
    /// series goes, how many reports it read, and what they weigh on disk. The sentence is
    /// what stands in for an automatic deletion — spec §4.
    /// </summary>
    [Fact]
    public void The_window_the_count_and_the_disk_cost_are_said()
    {
        var console = ConsoleReport.Drift(
            [DriftFixtures.Clean()], "derive.html", unreadable: 0, bytesOnDisk: 4_194_304);

        Assert.Contains("3 rapport", console);
        Assert.Contains("2026-01-01", console);
        Assert.Contains("4 Mio", console);
    }

    /// <summary>
    /// An unreadable report is counted and said, never dropped in silence: a folder where
    /// half the reports failed to parse must not read like a folder with half as many scans.
    /// </summary>
    [Fact]
    public void Unreadable_reports_are_counted_out_loud()
    {
        var console = ConsoleReport.Drift(
            [DriftFixtures.Clean()], "derive.html", unreadable: 2, bytesOnDisk: 1024);

        Assert.Contains("2 illisible", console);
    }

    /// <summary>
    /// Three trial runs a minute apart are the first thing anyone does with this command,
    /// and they produced « cadence 0 jours » — arithmetically true, and unreadable on the
    /// one screen that is a reader's first contact with it. Measured on a real folder, not
    /// imagined.
    /// </summary>
    [Theory]
    [InlineData(0.0005, "moins d'un jour")]
    [InlineData(0.9, "moins d'un jour")]
    [InlineData(1, "1 jour")]
    [InlineData(7, "7 jours")]
    [InlineData(3.5, "3.5 jours")]   // point décimal, comme ReportLabels.Bytes ailleurs
    public void A_cadence_shorter_than_a_day_is_said_in_words(double days, string expected)
    {
        var console = ConsoleReport.Drift(
            [DriftFixtures.WithCadence(days)], "derive.html", unreadable: 0, bytesOnDisk: 1024);

        Assert.Contains(expected, console, StringComparison.Ordinal);
    }

    [Fact]
    public void An_open_regression_is_named_with_the_date_it_started()
    {
        var console = ConsoleReport.Drift(
            [DriftFixtures.Drifted()], "derive.html", unreadable: 0, bytesOnDisk: 1024);

        Assert.Contains("WIN-FW-001", console);
        Assert.Contains("2026-01-08", console);
    }

    /// <summary>
    /// The signal a pair of scans cannot produce: said once, with how many times it fell,
    /// rather than recounted by every comparison that crosses it.
    /// </summary>
    [Fact]
    public void An_unstable_control_is_said_once_with_its_count()
    {
        var console = ConsoleReport.Drift(
            [DriftFixtures.Unstable()], "derive.html", unreadable: 0, bytesOnDisk: 1024);

        Assert.Contains("WIN-DEF-002", console);
        Assert.Contains("2 fois", console);
    }
}
