using System.Text;
using Rempart.Core.Engine;
using Rempart.Core.Rules;

namespace Rempart.Core.Reports;

/// <summary>One report, reduced to the line it occupies in the fleet index.</summary>
public sealed record FleetEntry(
    string Machine,
    string Date,
    string Location,
    int? Score,
    int Failures,
    int Unverifiable,
    int FlaggedFindings,
    string RulesFingerprint,
    bool Elevated)
{
    public static FleetEntry From(ScanResult result, string location)
    {
        var view = ReportView.From(result);

        return new FleetEntry(
            view.MachineName,
            view.ScanDate,
            location,
            result.Score?.Overall,
            view.Failures.Count,
            view.Unverifiable.Count,
            view.FlaggedFindings,
            result.RulesFingerprint,
            view.Elevated);
    }
}

/// <summary>
/// The fleet at a glance: one page listing every report found, worst first.
///
/// <para>
/// Its job is to answer "which machine do I look at next", so the ordering is the
/// answer: lowest score first, and a report that could not be scored at all sits at the
/// top rather than at the bottom — an unscored machine is not a good machine.
/// </para>
///
/// <para>
/// Reports built from different catalogs are listed together but flagged, because their
/// percentages are not on the same scale. Sorting them silently would rank machines on a
/// number that does not mean the same thing from one row to the next.
/// </para>
/// </summary>
public static class FleetIndex
{
    public const string FileName = "index.html";

    public static string Render(IReadOnlyList<FleetEntry> entries)
    {
        var html = new StringBuilder(16 * 1024);

        HtmlReport.OpenDocument(html, "Rempart — parc");

        html.Append("<header>\n");
        HtmlReport.WriteBrandBar(html, "parc");
        html.Append("<h1>Parc</h1>\n");
        html.Append($"<p class=\"meta\">{entries.Count} rapport(s)</p>\n</header>\n");

        if (entries.Count == 0)
        {
            html.Append("<section><p class=\"banner info\">Aucun rapport trouvé. "
                        + "« rempart scan --report » en produit un.</p></section>\n");
            HtmlReport.CloseDocument(html);
            return html.ToString();
        }

        var catalogs = entries.Select(e => e.RulesFingerprint).Distinct(StringComparer.Ordinal)
            .ToList();

        if (catalogs.Count > 1)
        {
            html.Append("<section class=\"banners\">\n<p class=\"banner warn\">");
            html.Append(Escape(
                $"{catalogs.Count} catalogues de règles différents dans ce dossier. Les "
                + "pourcentages ne sont pas sur la même échelle d'une ligne à l'autre : "
                + "rescanner les machines en retard avant de les comparer."));
            html.Append("</p>\n</section>\n");
        }

        html.Append("<section>\n<table class=\"domains\">\n<thead><tr>");
        html.Append("<th>Machine</th><th>Date</th><th>Score</th>"
                    + "<th class=\"num\">Échecs</th><th class=\"num\">Non vérifiés</th>"
                    + "<th class=\"num\">À examiner</th><th>Catalogue</th>");
        html.Append("</tr></thead>\n<tbody>\n");

        foreach (var entry in Ordered(entries))
        {
            html.Append("<tr>");
            html.Append($"<td>{Escape(entry.Machine)}");
            if (!entry.Elevated)
            {
                html.Append("<span class=\"dom\">scan non élevé — score partiel</span>");
            }

            html.Append($"<span class=\"dom\">{Escape(entry.Location)}</span></td>");
            html.Append($"<td>{Escape(entry.Date)}</td>");
            html.Append("<td class=\"gauge\">");

            if (entry.Score is { } score)
            {
                html.Append($"<span class=\"track\"><span class=\"bar {Band(score)}\" "
                            + $"style=\"width:{score}%\"></span></span>");
                html.Append($"<span class=\"pct\">{score} %</span>");
            }
            else
            {
                html.Append("<span class=\"track\"></span><span class=\"pct none\">n/d</span>");
            }

            html.Append("</td>");
            html.Append($"<td class=\"num\">{entry.Failures}</td>");
            html.Append($"<td class=\"num\">{entry.Unverifiable}</td>");
            html.Append($"<td class=\"num\">{entry.FlaggedFindings}</td>");
            html.Append($"<td><code>{Escape(entry.RulesFingerprint)}</code></td>");
            html.Append("</tr>\n");
        }

        html.Append("</tbody>\n</table>\n</section>\n");
        html.Append("<footer>\n<p>Ordonné par ce qu'il reste à faire : score le plus bas "
                    + "d'abord, et un rapport sans score en tête — une machine qu'on n'a pas "
                    + "pu noter n'est pas une machine saine.</p>\n</footer>\n");

        HtmlReport.CloseDocument(html);
        return html.ToString();
    }

    /// <summary>
    /// Worst first. A null score sorts ahead of every number: nothing could be measured
    /// there, which is a reason to look, not a reason to skip.
    /// </summary>
    public static IEnumerable<FleetEntry> Ordered(IReadOnlyList<FleetEntry> entries) =>
        entries
            .OrderBy(e => e.Score is null ? 0 : 1)
            .ThenBy(e => e.Score ?? 0)
            .ThenByDescending(e => e.Failures)
            .ThenBy(e => e.Machine, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Date, StringComparer.Ordinal);

    private static string Band(int score) => score switch
    {
        >= 90 => "good",
        >= 60 => "warn",
        _ => "bad",
    };

    private static string Escape(string text) => HtmlReport.Escape(text);
}
