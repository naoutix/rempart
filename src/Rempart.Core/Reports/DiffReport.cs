using System.Text;
using Rempart.Core.Diff;
using Rempart.Core.Json;

namespace Rempart.Core.Reports;

/// <summary>
/// Renders a comparison, in the three formats a scan already produces.
///
/// <para>
/// The exit criterion for this milestone is that the posture gap between two machines be
/// readable at a glance, so the layout is opinionated: what got worse comes first, what
/// the tool stopped being able to see comes second, and everything reassuring — fixes,
/// expected disappearances, inventory context — comes after. A comparison that opened on
/// its good news would be read as good news.
/// </para>
/// </summary>
public static class DiffReport
{
    public const string HtmlName = "comparaison.html";
    public const string MarkdownName = "comparaison.md";
    public const string JsonName = "comparaison.json";

    public static IReadOnlyList<ReportFile> Build(DiffResult diff) =>
    [
        new ReportFile(HtmlName, Html(diff)),
        new ReportFile(MarkdownName, Markdown(diff)),
        new ReportFile(JsonName, RempartJson.Serialise(diff)),
    ];

    /// <summary>
    /// The headline sentence. Written once and used by every format, because the
    /// console, the HTML and the Markdown disagreeing on the verdict would be the
    /// easiest way to make all three untrustworthy.
    /// </summary>
    public static string Headline(DiffResult diff)
    {
        var regressions = diff.Of(VerdictShift.Regression).Count();
        var blinded = diff.Of(VerdictShift.VisibilityLost).Count();
        var appeared = diff.Findings.Count(f => f.Change == ChangeKind.Appeared);
        var changed = diff.Findings.Count(f => f.Change == ChangeKind.Changed);

        if (diff.NothingToReport)
        {
            return diff.Transients.Count > 0
                ? $"Aucun écart de posture. {diff.Transients.Count} mouvement(s) attendu(s)."
                : "Aucun écart de posture.";
        }

        var parts = new List<string>();

        if (regressions > 0)
        {
            parts.Add($"{regressions} régression(s)");
        }

        if (blinded > 0)
        {
            parts.Add($"{blinded} contrôle(s) devenu(s) illisible(s)");
        }

        if (appeared > 0)
        {
            parts.Add($"{appeared} constat(s) apparu(s)");
        }

        if (changed > 0)
        {
            parts.Add($"{changed} constat(s) modifié(s)");
        }

        return parts.Count > 0
            ? string.Join(", ", parts) + "."
            : "Des écarts, aucun défavorable.";
    }

    /// <summary>
    /// Sections of verdict moves, worst first. Shared with the console rendering so the
    /// three formats present the same order and the same headings.
    /// </summary>
    public static readonly IReadOnlyList<(VerdictShift Shift, string Title, string Level)> Sections =
    [
        (VerdictShift.Regression, "Régressions — était conforme, ne l'est plus", "bad"),
        (VerdictShift.VisibilityLost, "Devenus illisibles — l'audit y voit moins", "warn"),
        (VerdictShift.Appeared, "Contrôles apparus au catalogue", "info"),
        (VerdictShift.Disappeared, "Contrôles disparus du catalogue", "info"),
        (VerdictShift.Other, "Changements de périmètre", "info"),
        (VerdictShift.VisibilityGained, "Redevenus lisibles", "good"),
        (VerdictShift.Correction, "Corrections", "good"),
    ];

    // ---- HTML --------------------------------------------------------------

    public static string Html(DiffResult diff)
    {
        var html = new StringBuilder(48 * 1024);
        var title = diff.SameMachine
            ? $"Rempart — {diff.AfterMachine} — évolution"
            : $"Rempart — {diff.BeforeMachine} contre {diff.AfterMachine}";

        HtmlReport.OpenDocument(html, title);

        html.Append("<header>\n");
        HtmlReport.WriteBrandBar(html, "comparaison");
        html.Append($"<h1>{E(title)}</h1>\n");
        html.Append("<p class=\"meta\">");
        html.Append($"{E(diff.BeforeMachine)} au {E(Date(diff.BeforeAtUtc))}");
        html.Append($" → {E(diff.AfterMachine)} au {E(Date(diff.AfterAtUtc))}");
        html.Append("</p>\n</header>\n");

        if (!diff.Comparable)
        {
            html.Append("<section class=\"banners\">\n");
            html.Append($"<p class=\"banner warn\">{E(diff.ComparabilityNote)}</p>\n");
            html.Append("</section>\n");
        }

        WriteHtmlSummary(html, diff);
        WriteHtmlVerdicts(html, diff);
        WriteHtmlFindings(html, diff);
        WriteHtmlTransients(html, diff);
        WriteHtmlFields(html, diff);

        html.Append("<footer>\n<p>Comparaison de deux rapports. Rempart ne relit aucune "
                    + "machine pour la produire : tout vient des JSON fournis.</p>\n</footer>\n");

        HtmlReport.CloseDocument(html);
        return html.ToString();
    }

    private static void WriteHtmlSummary(StringBuilder html, DiffResult diff)
    {
        html.Append("<section id=\"synthese\">\n<h2>Synthèse</h2>\n");
        html.Append($"<p class=\"banner {(diff.NothingToReport ? "info" : "bad")}\">"
                    + $"{E(Headline(diff))}</p>\n");

        html.Append("<div class=\"tiles\">\n");

        var delta = diff.ScoreDelta;
        html.Append("<div class=\"tile big\"><span class=\"num\">");
        html.Append(E($"{Percent(diff.ScoreBefore)} → {Percent(diff.ScoreAfter)}"));
        html.Append("</span><span class=\"cap\">conformité globale");
        if (delta is { } value && value != 0)
        {
            html.Append($" ({(value > 0 ? "+" : string.Empty)}{value} pts)");
        }

        html.Append("</span></div>\n");

        Tile(html, diff.Of(VerdictShift.Regression).Count(), "régressions", "bad");
        Tile(html, diff.Of(VerdictShift.VisibilityLost).Count(), "devenus illisibles", "warn");
        Tile(html, diff.Findings.Count(f => f.Change != ChangeKind.Disappeared),
            "constats apparus ou modifiés", "warn");
        Tile(html, diff.Of(VerdictShift.Correction).Count(), "corrections", "good");

        html.Append("</div>\n");

        var moved = diff.Domains.Where(d => d.Before != d.After).ToList();

        if (moved.Count > 0)
        {
            html.Append("<table class=\"domains\">\n<thead><tr><th>Domaine</th>"
                        + "<th class=\"num\">Avant</th><th class=\"num\">Après</th>"
                        + "<th class=\"num\">Écart</th></tr></thead>\n<tbody>\n");

            foreach (var domain in moved)
            {
                var change = domain.Before is { } was && domain.After is { } now
                    ? $"{(now - was > 0 ? "+" : string.Empty)}{now - was}"
                    : "—";

                html.Append($"<tr><td>{E(domain.Domain)}</td>");
                html.Append($"<td class=\"num\">{E(Percent(domain.Before))}</td>");
                html.Append($"<td class=\"num\">{E(Percent(domain.After))}</td>");
                html.Append($"<td class=\"num\">{E(change)}</td></tr>\n");
            }

            html.Append("</tbody>\n</table>\n");
        }

        html.Append("</section>\n");
    }

    private static void Tile(StringBuilder html, int count, string caption, string level)
    {
        html.Append($"<div class=\"tile {(count > 0 ? level : "plain")}\">"
                    + $"<span class=\"num\">{count}</span>"
                    + $"<span class=\"cap\">{E(caption)}</span></div>\n");
    }

    private static void WriteHtmlVerdicts(StringBuilder html, DiffResult diff)
    {
        if (diff.Verdicts.Count == 0)
        {
            return;
        }

        html.Append("<section id=\"posture\">\n<h2>Posture — configuration</h2>\n");

        foreach (var (shift, title, level) in Sections)
        {
            var changes = diff.Of(shift).ToList();

            if (changes.Count == 0)
            {
                continue;
            }

            html.Append($"<h3 class=\"family\">{E(title)} "
                        + $"<span class=\"count {(level is "bad" or "warn" ? "warn" : string.Empty)}\">"
                        + $"{changes.Count}</span></h3>\n");

            html.Append("<table class=\"rules\">\n<thead><tr><th>Contrôle</th><th>Avant</th>"
                        + "<th>Après</th></tr></thead>\n<tbody>\n");

            foreach (var change in changes)
            {
                html.Append("<tr>");
                html.Append($"<td><code>{E(change.RuleId)}</code> {E(change.Title)}"
                            + $"<span class=\"dom\">{E(change.Domain)} · "
                            + $"{E(ReportLabels.Of(change.Severity))}</span></td>");
                html.Append($"<td class=\"obs\">{E(Status(change.Before))}</td>");
                html.Append($"<td class=\"obs\">{E(Status(change.After))}</td>");
                html.Append("</tr>\n");
            }

            html.Append("</tbody>\n</table>\n");
        }

        html.Append("</section>\n");
    }

    private static void WriteHtmlFindings(StringBuilder html, DiffResult diff)
    {
        if (diff.Findings.Count == 0)
        {
            return;
        }

        html.Append("<section id=\"constats\">\n<h2>Constats — ce qui est présent</h2>\n");

        foreach (var change in diff.Findings)
        {
            html.Append($"<article class=\"finding\" data-severity=\""
                        + $"{E(ReportLabels.Of(change.After ?? change.Before ?? default))}\">\n");
            html.Append("<div class=\"fhead\">");
            html.Append($"<span class=\"sev {Level(change.Change)}\">{E(Verb(change.Change))}</span>");
            html.Append($"<span class=\"target\">{E(change.Target)}</span></div>\n");
            html.Append($"<div class=\"source\">{E(ReportLabels.Family(change.Kind))} · "
                        + $"{E(change.Source)}</div>\n");

            if (change.Notes.Count > 0)
            {
                html.Append("<ul class=\"reasons\">\n");
                foreach (var note in change.Notes)
                {
                    html.Append($"<li>{E(note)}</li>\n");
                }

                html.Append("</ul>\n");
            }

            html.Append("</article>\n");
        }

        html.Append("</section>\n");
    }

    private static void WriteHtmlTransients(StringBuilder html, DiffResult diff)
    {
        if (diff.Transients.Count == 0)
        {
            return;
        }

        html.Append("<section id=\"transitoires\">\n<h2>Mouvements attendus</h2>\n");
        html.Append("<p class=\"hint\">Le système en est la cause, pas la machine : une entrée "
                    + "<code>RunOnce</code> est consommée au démarrage, une tâche réglée pour "
                    + "être supprimée après expiration s'efface seule, et un port de la plage "
                    + "dynamique change de numéro à chaque ouverture. Hors de l'écart de "
                    + "posture, listés pour que rien ne bouge en silence.</p>\n");
        html.Append("<details>\n<summary>Les voir "
                    + $"<span class=\"count\">{diff.Transients.Count}</span></summary>\n");
        html.Append("<ul class=\"plainlist\">\n");

        foreach (var change in diff.Transients)
        {
            html.Append($"<li><code>{E(change.Source)}</code> — {E(change.Target)} "
                        + $"<span class=\"dom\">{E(Verb(change.Change))}</span></li>\n");
        }

        html.Append("</ul>\n</details>\n</section>\n");
    }

    private static void WriteHtmlFields(StringBuilder html, DiffResult diff)
    {
        if (diff.Fields.Count == 0)
        {
            return;
        }

        html.Append("<section id=\"inventaire\">\n<h2>Inventaire</h2>\n");
        html.Append(diff.SameMachine
            ? "<p class=\"hint\">La même machine a changé sur ces points.</p>\n"
            : "<p class=\"hint\">Deux machines différentes : ces écarts sont du contexte, "
              + "pas des événements.</p>\n");

        html.Append($"<details>\n<summary>Détail <span class=\"count\">{diff.Fields.Count}"
                    + "</span></summary>\n");
        html.Append("<table class=\"fields\">\n<tbody>\n");

        foreach (var field in diff.Fields)
        {
            html.Append($"<tr><th>{E(field.Field)}</th><td>{E(field.Before ?? "—")} → "
                        + $"{E(field.After ?? "—")}</td></tr>\n");
        }

        html.Append("</tbody>\n</table>\n</details>\n</section>\n");
    }

    // ---- Markdown ----------------------------------------------------------

    public static string Markdown(DiffResult diff)
    {
        var md = new StringBuilder(16 * 1024);

        md.Append(diff.SameMachine
            ? $"# Rempart — {diff.AfterMachine}, évolution\n\n"
            : $"# Rempart — {diff.BeforeMachine} contre {diff.AfterMachine}\n\n");

        md.Append($"- **Avant** : {diff.BeforeMachine}, {diff.BeforeAtUtc}\n");
        md.Append($"- **Après** : {diff.AfterMachine}, {diff.AfterAtUtc}\n");
        md.Append($"- **Conformité** : {Percent(diff.ScoreBefore)} → {Percent(diff.ScoreAfter)}");

        if (diff.ScoreDelta is { } delta && delta != 0)
        {
            md.Append($" ({(delta > 0 ? "+" : string.Empty)}{delta} pts)");
        }

        md.Append("\n\n");

        if (!diff.Comparable)
        {
            md.Append($"> {diff.ComparabilityNote}\n>\n\n");
        }

        md.Append($"**{Headline(diff)}**\n\n");

        var moved = diff.Domains.Where(d => d.Before != d.After).ToList();

        if (moved.Count > 0)
        {
            md.Append("| Domaine | Avant | Après |\n|---|---:|---:|\n");
            foreach (var domain in moved)
            {
                md.Append($"| {MarkdownReport.Cell(domain.Domain)} | {Percent(domain.Before)} "
                          + $"| {Percent(domain.After)} |\n");
            }

            md.Append('\n');
        }

        foreach (var (shift, title, _) in Sections)
        {
            var changes = diff.Of(shift).ToList();

            if (changes.Count == 0)
            {
                continue;
            }

            md.Append($"## {title} ({changes.Count})\n\n");
            md.Append("| Contrôle | Domaine | Avant | Après |\n|---|---|---|---|\n");

            foreach (var change in changes)
            {
                md.Append($"| `{MarkdownReport.Cell(change.RuleId)}` "
                          + $"{MarkdownReport.Cell(change.Title)} "
                          + $"| {MarkdownReport.Cell(change.Domain)} "
                          + $"| {Status(change.Before)} | {Status(change.After)} |\n");
            }

            md.Append('\n');
        }

        if (diff.Findings.Count > 0)
        {
            md.Append($"## Constats ({diff.Findings.Count})\n\n");

            foreach (var change in diff.Findings)
            {
                md.Append($"**{Verb(change.Change)}** — {MarkdownReport.Cell(change.Target)}\n\n");
                md.Append($"- {ReportLabels.Family(change.Kind)} : "
                          + $"{MarkdownReport.Cell(change.Source)}\n");

                foreach (var note in change.Notes)
                {
                    md.Append($"- {MarkdownReport.Cell(note)}\n");
                }

                md.Append('\n');
            }
        }

        if (diff.Transients.Count > 0)
        {
            md.Append($"## Mouvements attendus ({diff.Transients.Count})\n\n");
            md.Append("Le système en est la cause, pas la machine : entrées consommées, tâches "
                      + "expirées, ports de la plage dynamique renumérotés. Hors de l'écart de "
                      + "posture, listés pour que rien ne bouge en silence.\n\n");

            foreach (var change in diff.Transients)
            {
                md.Append($"- {MarkdownReport.Cell(change.Source)}\n");
            }

            md.Append('\n');
        }

        if (diff.Fields.Count > 0)
        {
            md.Append($"## Inventaire ({diff.Fields.Count})\n\n");
            md.Append(diff.SameMachine
                ? "La même machine a changé sur ces points.\n\n"
                : "Deux machines différentes : du contexte, pas des événements.\n\n");
            md.Append("| Champ | Avant | Après |\n|---|---|---|\n");

            foreach (var field in diff.Fields)
            {
                md.Append($"| {MarkdownReport.Cell(field.Field)} "
                          + $"| {MarkdownReport.Cell(field.Before ?? "—")} "
                          + $"| {MarkdownReport.Cell(field.After ?? "—")} |\n");
            }

            md.Append('\n');
        }

        return md.ToString();
    }

    // ---- shared ------------------------------------------------------------

    private static string E(string text) => HtmlReport.Escape(text);

    private static string Date(string iso) => ReportView.DateOf(iso);

    private static string Percent(int? score) => score is { } value ? $"{value} %" : "n/d";

    private static string Status(Rules.VerdictStatus? status) => status switch
    {
        Rules.VerdictStatus.Pass => "conforme",
        Rules.VerdictStatus.Fail => "échec",
        Rules.VerdictStatus.Unknown => "non vérifié",
        Rules.VerdictStatus.NotApplicable => "hors périmètre",
        _ => "absent du catalogue",
    };

    private static string Verb(ChangeKind change) => change switch
    {
        ChangeKind.Appeared => "apparu",
        ChangeKind.Disappeared => "disparu",
        _ => "modifié",
    };

    private static string Level(ChangeKind change) => change switch
    {
        ChangeKind.Appeared => "s-susp",
        ChangeKind.Disappeared => "s-info",
        _ => "s-note",
    };
}
