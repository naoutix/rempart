using System.Text;
using Rempart.Core.Drift;

namespace Rempart.Core.Reports;

/// <summary>
/// One machine's trajectory, on a page that opens itself.
///
/// <para>
/// Standalone like every other report this tool writes — one file, CSS and script inline,
/// no external resource — so it survives being copied off the stick onto a machine with no
/// network. The inline script receives <em>no</em> data from the scan: it filters nodes
/// already present, which removes the second injection path instead of securing it.
/// </para>
///
/// <para>
/// What limits the reading is said before anything is measured. A series nobody has fed for
/// three times its own cadence describes a machine as it was months ago, and a percentage
/// read without that sentence is worse than no percentage — the same rule M6 applies to a
/// non-elevated scan.
/// </para>
/// </summary>
public static class DriftPage
{
    public const string FileName = "derive.html";

    public static string Render(IReadOnlyList<DriftReport> reports)
    {
        var html = new StringBuilder(16 * 1024);

        HtmlReport.OpenDocument(html, "Rempart — dérive");

        html.Append("<header>\n");
        HtmlReport.WriteBrandBar(html, "dérive");
        html.Append("<h1>Dérive</h1>\n");
        html.Append($"<p class=\"meta\">{reports.Count} machine(s), "
                    + $"{reports.Sum(report => report.Points)} rapport(s)</p>\n</header>\n");

        if (reports.Count == 0)
        {
            html.Append("<section><p class=\"banner info\">Aucun rapport trouvé. "
                        + "« rempart scan --report » en produit un.</p></section>\n");
            HtmlReport.CloseDocument(html);
            return html.ToString();
        }

        Banners(html, reports);

        foreach (var report in reports)
        {
            Machine(html, report);
        }

        html.Append("<footer>\n<p>");
        html.Append(Escape(
            "Rien n'est élagué : cette page lit les rapports déjà écrits et n'en supprime "
            + "aucun. Le plus ancien fixe le début de la fenêtre — le supprimer raccourcit "
            + "la pente, et l'« avant » d'une correction ne se refait pas."));
        html.Append("</p>\n</footer>\n");

        HtmlReport.CloseDocument(html);
        return html.ToString();
    }

    /// <summary>
    /// What limits the reading, before the first figure. A series that stopped being fed is
    /// the one thing a reader cannot infer from the curve — the curve looks exactly the
    /// same, it simply ends.
    /// </summary>
    private static void Banners(StringBuilder html, IReadOnlyList<DriftReport> reports)
    {
        var stale = reports.Where(report => report.Freshness.Stale).ToList();
        var partial = reports.Where(report => report.LastPointPartial).ToList();

        if (stale.Count == 0 && partial.Count == 0)
        {
            return;
        }

        html.Append("<section class=\"banners\">\n");

        foreach (var report in stale)
        {
            html.Append("<p class=\"banner warn\">");
            html.Append(Escape(
                $"{report.Machine} : dernière capture il y a {report.Freshness.DaysSinceLast} "
                + $"jours, pour une cadence observée de {Cadence(report)}. La trajectoire "
                + "décrit la machine telle qu'elle était alors — vérifier que le suivi tourne "
                + "encore."));
            html.Append("</p>\n");
        }

        foreach (var report in partial)
        {
            html.Append("<p class=\"banner warn\">");
            html.Append(Escape(
                $"{report.Machine} : le dernier scan a laissé des contrôles inévaluables. "
                + "Le dernier point de la courbe répond pour moins de machine qu'il n'y "
                + "paraît."));
            html.Append("</p>\n");
        }

        html.Append("</section>\n");
    }

    private static void Machine(StringBuilder html, DriftReport report)
    {
        html.Append("<section>\n");
        html.Append($"<h2>{Escape(report.Machine)}</h2>\n");
        html.Append($"<p class=\"meta\">{report.Points} rapport(s) du {Day(report.First)} au "
                    + $"{Day(report.Last)} — cadence {Cadence(report)}</p>\n");

        if (report.Segments.Count > 1)
        {
            html.Append("<p class=\"banner info\">");
            html.Append(Escape(
                $"{report.Segments.Count} catalogues de règles sur cette série. La pente est "
                + "coupée à chaque changement : deux pourcentages produits par des catalogues "
                + "différents ne sont pas sur la même échelle."));
            html.Append("</p>\n");
        }

        Trajectory(html, report);
        Regressions(html, report);
        Unstable(html, report);

        html.Append("</section>\n");
    }

    private static void Trajectory(StringBuilder html, DriftReport report)
    {
        html.Append("<table class=\"domains\">\n<thead><tr>");
        html.Append("<th>Date</th><th>Score</th><th>Catalogue</th>");
        html.Append("</tr></thead>\n<tbody>\n");

        foreach (var segment in report.Segments)
        {
            foreach (var point in segment.Trajectory)
            {
                html.Append("<tr>");
                html.Append($"<td>{Day(point.At)}</td>");
                html.Append("<td class=\"gauge\">");

                if (point.Overall is { } score)
                {
                    html.Append($"<span class=\"track\"><span class=\"bar {FleetIndex.Band(score)}\" "
                                + $"style=\"width:{score}%\"></span></span>");
                    html.Append($"<span class=\"pct\">{score} %</span>");
                }
                else
                {
                    // A machine nobody could score keeps its place on the curve. Dropping the
                    // row would join the two scores on either side into a slope that skipped it.
                    html.Append("<span class=\"track\"></span><span class=\"pct none\">n/d</span>");
                }

                html.Append("</td>");
                html.Append($"<td><code>{Escape(segment.RulesFingerprint)}</code></td>");
                html.Append("</tr>\n");
            }
        }

        html.Append("</tbody>\n</table>\n");
    }

    private static void Regressions(StringBuilder html, DriftReport report)
    {
        if (report.OpenRegressions.Count == 0)
        {
            html.Append("<p class=\"meta\">Aucune régression ouverte au dernier point.</p>\n");
            return;
        }

        html.Append("<h3>Régressions ouvertes</h3>\n");
        html.Append("<table class=\"domains\">\n<thead><tr>");
        html.Append("<th>Règle</th><th>Contrôle</th><th>Domaine</th><th>Depuis</th>"
                    + "<th class=\"num\">Jours observés</th>");
        html.Append("</tr></thead>\n<tbody>\n");

        foreach (var open in report.OpenRegressions)
        {
            html.Append("<tr>");
            html.Append($"<td><code>{Escape(open.RuleId)}</code></td>");
            html.Append($"<td>{Escape(open.Title)}</td>");
            html.Append($"<td>{Escape(open.Domain)}</td>");
            html.Append($"<td>{Day(open.Since)}</td>");
            html.Append($"<td class=\"num\">{open.DaysObserved}</td>");
            html.Append("</tr>\n");
        }

        html.Append("</tbody>\n</table>\n");
    }

    private static void Unstable(StringBuilder html, DriftReport report)
    {
        if (report.Unstable.Count == 0)
        {
            return;
        }

        html.Append("<h3>Contrôles instables</h3>\n");
        html.Append("<p class=\"meta\">");
        html.Append(Escape(
            "Tombés puis réparés puis retombés : c'est la seconde chute qui fait le motif, "
            + "et aucune comparaison de deux rapports ne peut la voir."));
        html.Append("</p>\n<ul>\n");

        foreach (var control in report.Unstable)
        {
            html.Append("<li>");
            html.Append($"<code>{Escape(control.RuleId)}</code> — {Escape(control.Title)}, ");
            html.Append(Escape(
                $"tombé {control.Regressions} fois : "
                + string.Join(", ", control.At.Select(Day))));
            html.Append("</li>\n");
        }

        html.Append("</ul>\n");
    }

    /// <summary>
    /// The cadence, or the sentence that replaces it. Below three points nothing is claimed:
    /// two captures establish one interval, which is a gap and not a rhythm.
    /// </summary>
    internal static string Cadence(DriftReport report) =>
        report.Freshness.CadenceDays is { } days
            ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{days:0.#} jours")
            : "non observable";

    internal static string Day(DateTimeOffset at) => at.ToString("yyyy-MM-dd");

    private static string Escape(string text) => HtmlReport.Escape(text);
}
