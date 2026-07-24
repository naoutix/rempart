using System.Text;
using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Core.Reports;

/// <summary>
/// The standalone HTML report: one file, no companion folder, no request to anything.
///
/// <para>
/// <b>Everything is inlined</b> — stylesheet, script, glyphs. A report is read on the
/// audited machine, which may be offline, then sent by mail or carried back on the
/// stick. A single external reference (a font, a stylesheet, an icon) would turn
/// opening the report into a network call from the machine of whoever reads it, and
/// would leak the fact that it was opened. A test asserts that no <c>http</c> URL
/// survives in the output.
/// </para>
///
/// <para>
/// <b>Everything machine-supplied is escaped.</b> A report is built from command
/// lines, file paths and extension names — strings an attacker on the audited machine
/// chooses. A service named <c>&lt;script&gt;</c> must appear as text, not run in the
/// browser of the person auditing. This is the one place in the project where a
/// formatting mistake becomes a vulnerability, hence <see cref="Escape"/> on every
/// interpolation and a test that plants markup in every field.
/// </para>
///
/// <para>
/// <b>The script never receives data.</b> It filters nodes already in the document and
/// switches the theme; nothing from the scan is serialised into it. So the escaping
/// above is the whole of the defence — there is no second, JavaScript-side injection
/// path to get right.
/// </para>
/// </summary>
public static class HtmlReport
{
    public static string Render(ScanResult result)
    {
        var view = ReportView.From(result);
        var html = new StringBuilder(64 * 1024);

        html.Append("<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n");
        html.Append("<meta charset=\"utf-8\">\n");
        html.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        html.Append($"<title>Rempart — {Escape(view.MachineName)} — {Escape(view.ScanDate)}</title>\n");
        html.Append("<style>\n").Append(Style).Append("</style>\n</head>\n<body>\n");

        WriteHeader(html, view);
        WriteBanners(html, view);
        WriteScore(html, view);
        WritePosture(html, view);
        WriteFindings(html, view);
        WriteDnsProbe(html, view);
        WriteReclaimable(html, view);
        WriteInventory(html, view);
        WriteFooter(html, view);

        html.Append("<script>\n").Append(Script).Append("</script>\n</body>\n</html>\n");
        return html.ToString();
    }

    private static void WriteHeader(StringBuilder html, ReportView view)
    {
        var result = view.Result;

        html.Append("<header>\n<div class=\"bar\">\n");
        html.Append($"<span class=\"brand\">Rempart <span class=\"ver\">{Escape(result.ToolVersion)}</span></span>\n");
        html.Append("<button type=\"button\" id=\"theme\" title=\"Basculer le thème clair / sombre\">"
                    + "◐ thème</button>\n");
        html.Append("</div>\n");
        html.Append($"<h1>{Escape(view.MachineName)}</h1>\n");
        html.Append("<p class=\"meta\">");
        html.Append($"scan du {Escape(result.StartedAtUtc)}");
        html.Append($" · règles <code>{Escape(result.RulesFingerprint)}</code>");
        html.Append($" · {Escape(DescribeAge(result.DataAge))}");
        html.Append("</p>\n</header>\n");
    }

    /// <summary>
    /// What qualifies everything that follows: missing privileges, a partial score, an
    /// update applied or refused, a broken seal. Placed before the numbers, because a
    /// score read without its caveat is a score that misleads.
    /// </summary>
    private static void WriteBanners(StringBuilder html, ReportView view)
    {
        var banners = new List<(string Level, string Text)>();

        if (!view.Elevated)
        {
            banners.Add(("warn",
                "Scan non élevé. Les contrôles hors de portée sont marqués « non vérifié », "
                + "jamais comptés comme conformes. Relancer en administrateur pour un audit complet."));
        }

        if (view.Result.Score is { IsPartial: true } partial)
        {
            banners.Add(("warn",
                $"Score partiel : {partial.TotalUnknown} contrôle(s) n'ont pas pu être lus. "
                + "Ils sont exclus du calcul — le pourcentage porte sur ce qui a été vérifié."));
        }

        foreach (var collector in view.DegradedCollectors)
        {
            banners.Add((collector.Status == CollectorStatus.Failed ? "bad" : "warn",
                $"Collecteur « {collector.Name} » : {ReportLabels.Of(collector.Status)}. "
                + "Ce que ce collecteur aurait remonté est absent de ce rapport."));
        }

        if (view.Result.UpdateNote is { } update)
        {
            banners.Add(("info", update));
        }

        if (view.Result.IntegrityNote is { } integrity)
        {
            banners.Add(("info", integrity));
        }

        if (view.Result.RulesNote is { } rulesNote)
        {
            banners.Add(("info", rulesNote));
        }

        if (banners.Count == 0)
        {
            return;
        }

        html.Append("<section class=\"banners\">\n");
        foreach (var (level, text) in banners)
        {
            html.Append($"<p class=\"banner {level}\">{Escape(text)}</p>\n");
        }

        html.Append("</section>\n");
    }

    private static void WriteScore(StringBuilder html, ReportView view)
    {
        if (view.Result.Score is not { } score)
        {
            return;
        }

        html.Append("<section id=\"synthese\">\n<h2>Synthèse</h2>\n<div class=\"tiles\">\n");

        html.Append("<div class=\"tile big\">");
        html.Append($"<span class=\"num\">{(score.Overall is { } o ? $"{o} %" : "n/d")}</span>");
        html.Append("<span class=\"cap\">conformité globale</span></div>\n");

        Tile(html, view.Failures.Count.ToString(), "contrôles en échec",
            view.Failures.Count > 0 ? "bad" : "good");
        Tile(html, view.Unverifiable.Count.ToString(), "non vérifiables",
            view.Unverifiable.Count > 0 ? "warn" : "good");
        Tile(html, view.FlaggedFindings.ToString(), "constats à examiner",
            view.FlaggedFindings > 0 ? "warn" : "good");
        Tile(html, view.TotalFindings.ToString(), "éléments énumérés", "plain");

        html.Append("</div>\n");

        html.Append("<table class=\"domains\">\n<thead><tr><th>Domaine</th><th>Score</th>"
                    + "<th class=\"num\">Conformes</th><th class=\"num\">Échecs</th>"
                    + "<th class=\"num\">Non vérifiés</th><th class=\"num\">Hors périmètre</th>"
                    + "</tr></thead>\n<tbody>\n");

        foreach (var domain in score.Domains)
        {
            html.Append("<tr>");
            html.Append($"<td>{Escape(domain.Domain)}</td>");
            html.Append("<td class=\"gauge\">");
            if (domain.Score is { } value)
            {
                // The bar fills a fixed-width track, so its length is the score and
                // nothing else. An earlier version sized it against the table cell and
                // capped it, which rendered 67 %, 88 % and 100 % at the same width —
                // a chart that made a mediocre domain look perfect.
                html.Append("<span class=\"track\">");
                html.Append($"<span class=\"bar {Band(value)}\" style=\"width:{value}%\"></span>");
                html.Append("</span>");
                html.Append($"<span class=\"pct\">{value} %</span>");
            }
            else
            {
                html.Append("<span class=\"track\"></span>");
                html.Append("<span class=\"pct none\">n/d</span>");
            }

            html.Append("</td>");
            html.Append($"<td class=\"num\">{domain.Passed}</td>");
            html.Append($"<td class=\"num\">{domain.Failed}</td>");
            html.Append($"<td class=\"num\">{domain.Unknown}</td>");
            html.Append($"<td class=\"num\">{domain.NotApplicable}</td>");
            html.Append("</tr>\n");
        }

        html.Append("</tbody>\n</table>\n</section>\n");
    }

    private static void Tile(StringBuilder html, string number, string caption, string level)
    {
        html.Append($"<div class=\"tile {level}\"><span class=\"num\">{Escape(number)}</span>");
        html.Append($"<span class=\"cap\">{Escape(caption)}</span></div>\n");
    }

    private static void WritePosture(StringBuilder html, ReportView view)
    {
        if (view.Failures.Count == 0 && view.Unverifiable.Count == 0)
        {
            return;
        }

        html.Append("<section id=\"posture\">\n<h2>Posture — configuration</h2>\n");

        if (view.Failures.Count > 0)
        {
            html.Append("<div class=\"toolbar\" data-scope=\"posture\">\n");
            html.Append("<label class=\"search\"><input type=\"search\" data-filter=\"posture\" "
                        + "placeholder=\"filtrer par identifiant ou intitulé…\"></label>\n");
            foreach (var severity in new[] { "critique", "élevée", "moyenne", "faible", "info" })
            {
                html.Append($"<label class=\"chip s-{Slug(severity)}\">"
                            + $"<input type=\"checkbox\" data-severity=\"{Escape(severity)}\" checked>"
                            + $"{Escape(severity)}</label>\n");
            }

            html.Append("</div>\n");

            html.Append("<table class=\"rules\" data-list=\"posture\">\n<thead><tr><th>Sévérité</th>"
                        + "<th>Contrôle</th><th>Observé</th><th>Attendu</th></tr></thead>\n<tbody>\n");

            foreach (var verdict in view.Failures)
            {
                var label = ReportLabels.Of(verdict.Severity);
                html.Append($"<tr class=\"row\" data-severity=\"{Escape(label)}\">");
                html.Append($"<td><span class=\"sev s-{Slug(label)}\">{Escape(label)}</span></td>");
                html.Append($"<td><code>{Escape(verdict.RuleId)}</code> {Escape(verdict.Title)}"
                            + $"<span class=\"dom\">{Escape(verdict.Domain)}</span></td>");
                html.Append($"<td class=\"obs\">{Escape(verdict.Observed ?? "absent")}</td>");
                html.Append($"<td class=\"obs\">{Escape(verdict.Expected ?? "—")}</td>");
                html.Append("</tr>\n");
            }

            html.Append("</tbody>\n</table>\n");
            html.Append("<p class=\"hint\">« rempart explain &lt;ID&gt; » détaille une règle, "
                        + "sa justification et ce que coûte sa correction.</p>\n");
        }

        if (view.Unverifiable.Count > 0)
        {
            html.Append($"<details>\n<summary>Non vérifiables — accès refusé "
                        + $"<span class=\"count\">{view.Unverifiable.Count}</span></summary>\n");
            html.Append("<p class=\"hint\">Ni conformes ni non conformes : exclus du score. "
                        + "Un scan élevé les tranche.</p>\n<ul class=\"plainlist\">\n");
            foreach (var verdict in view.Unverifiable)
            {
                html.Append($"<li><code>{Escape(verdict.RuleId)}</code> {Escape(verdict.Title)}</li>\n");
            }

            html.Append("</ul>\n</details>\n");
        }

        html.Append("</section>\n");
    }

    private static void WriteFindings(StringBuilder html, ReportView view)
    {
        if (view.Groups.Count == 0)
        {
            return;
        }

        html.Append("<section id=\"constats\">\n<h2>Constats — ce qui est présent</h2>\n");
        html.Append("<p class=\"hint\">Les constats ne se mélangent pas au score : une "
                    + "configuration à 94 % ne doit pas masquer un binaire non signé lancé au "
                    + "démarrage.</p>\n");

        html.Append("<div class=\"toolbar\" data-scope=\"constats\">\n");
        html.Append("<label class=\"search\"><input type=\"search\" data-filter=\"constats\" "
                    + "placeholder=\"filtrer les constats…\"></label>\n");
        foreach (var severity in new[] { "suspect", "notable" })
        {
            html.Append($"<label class=\"chip s-{Slug(severity)}\">"
                        + $"<input type=\"checkbox\" data-severity=\"{Escape(severity)}\" checked>"
                        + $"{Escape(severity)}</label>\n");
        }

        html.Append("<button type=\"button\" class=\"expand\">déplier tout</button>\n");
        html.Append("</div>\n");

        foreach (var group in view.Groups)
        {
            WriteFindingGroup(html, group);
        }

        html.Append("</section>\n");
    }

    private static void WriteFindingGroup(StringBuilder html, FindingGroup group)
    {
        var family = ReportLabels.Family(group.Kind);

        html.Append($"<h3 class=\"family\">{Escape(family)} ");
        html.Append($"<span class=\"count\">{group.Total} énumérés</span>");
        if (group.Flagged.Count > 0)
        {
            html.Append($"<span class=\"count warn\">{group.Flagged.Count} à examiner</span>");
        }

        html.Append("</h3>\n");

        if (group.Flagged.Count == 0)
        {
            html.Append("<p class=\"hint ok\">Rien à signaler dans cette famille.</p>\n");
            return;
        }

        html.Append("<div data-list=\"constats\">\n");
        foreach (var finding in group.Flagged)
        {
            var label = ReportLabels.Of(finding.Severity);
            html.Append($"<article class=\"finding row\" data-severity=\"{Escape(label)}\">\n");
            html.Append($"<div class=\"fhead\"><span class=\"sev s-{Slug(label)}\">{Escape(label)}"
                        + $"</span><span class=\"target\">{Escape(finding.Target)}</span></div>\n");
            html.Append($"<div class=\"source\">{Escape(finding.Source)}</div>\n");

            if (finding.Reasons.Count > 0)
            {
                html.Append("<ul class=\"reasons\">\n");
                foreach (var reason in finding.Reasons)
                {
                    html.Append($"<li>{Escape(reason)}</li>\n");
                }

                html.Append("</ul>\n");
            }

            if (finding.Details.Count > 0)
            {
                html.Append("<details class=\"det\"><summary>détails</summary>\n<dl>\n");
                foreach (var (key, value) in finding.Details.OrderBy(d => d.Key, StringComparer.Ordinal))
                {
                    html.Append($"<dt>{Escape(key)}</dt><dd>{Escape(value)}</dd>\n");
                }

                html.Append("</dl>\n</details>\n");
            }

            html.Append("</article>\n");
        }

        html.Append("</div>\n");
    }

    private static void WriteDnsProbe(StringBuilder html, ReportView view)
    {
        if (view.Result.DnsProbe is not { } probe)
        {
            return;
        }

        html.Append("<section id=\"dns\">\n<h2>Résolveurs chiffrés — mesure ponctuelle</h2>\n");
        html.Append("<p class=\"hint\">Latence mesurée depuis ce réseau, au moment du scan. "
                    + "Cette section est un avis : elle reste <strong>hors du score</strong>.</p>\n");
        html.Append("<table class=\"rules\">\n<thead><tr><th>Résolveur</th><th>Protocole</th>"
                    + "<th>État</th></tr></thead>\n<tbody>\n");

        foreach (var probed in probe.Results)
        {
            html.Append("<tr>");
            html.Append($"<td>{Escape(probed.Resolver)}</td>");
            html.Append($"<td>{Escape(probed.Protocol.ToString())}</td>");
            html.Append(probed.Reachable
                ? $"<td class=\"obs\">{probed.LatencyMs} ms</td>"
                : $"<td class=\"obs bad\">bloqué — {Escape(probed.Error ?? "sans détail")}</td>");
            html.Append("</tr>\n");
        }

        html.Append("</tbody>\n</table>\n");

        html.Append(probe.RecommendedResolver is { } resolver
            ? $"<p class=\"hint\">Suggestion : {Escape(resolver)} en "
              + $"{Escape(probe.RecommendedProtocol?.ToString() ?? "?")} "
              + $"({probe.RecommendedLatencyMs} ms) est le plus rapide joignable.</p>\n"
            : "<p class=\"hint\">Aucun résolveur chiffré joignable depuis ce réseau.</p>\n");

        html.Append("</section>\n");
    }

    /// <summary>
    /// Reclaimable space, by layer.
    ///
    /// The breakdown is the point. Most of the component store is shared with the running
    /// Windows installation and cannot be freed, which is why the usual advice to "empty
    /// WinSxS" quotes a figure that is mostly the files Windows is running on. Showing
    /// the layers separately is what turns a scary number into a decision.
    /// </summary>
    private static void WriteReclaimable(StringBuilder html, ReportView view)
    {
        if (view.ComponentStore is not { } store)
        {
            return;
        }

        html.Append("<section id=\"espace\">\n<h2>Espace récupérable</h2>\n");
        html.Append("<p class=\"hint\">Mesuré par la pile de maintenance de Windows. "
                    + "Rempart <strong>ne supprime rien</strong> : il indique ce qu'un "
                    + "nettoyage libérerait.</p>\n");

        html.Append("<table class=\"fields\">\n<tbody>\n");

        foreach (var (label, field) in ReportView.ComponentStoreLayers)
        {
            if (store.TryGetValue(field, out var raw) && long.TryParse(raw, out var bytes))
            {
                html.Append($"<tr><th>{Escape(label)}</th>"
                            + $"<td>{Escape(ReportLabels.Bytes(bytes))}</td></tr>\n");
            }
        }

        if (store.TryGetValue("store.lastCleanup", out var cleaned) && cleaned is not null)
        {
            html.Append($"<tr><th>dernier nettoyage</th><td>{Escape(cleaned)}</td></tr>\n");
        }

        if (store.TryGetValue("store.cleanupRecommended", out var recommended)
            && recommended is not null)
        {
            html.Append("<tr><th>nettoyage recommandé par Windows</th>"
                        + $"<td>{Escape(recommended)}</td></tr>\n");
        }

        html.Append("</tbody>\n</table>\n");
        html.Append("<p class=\"hint\">La part partagée avec Windows n'est pas récupérable : "
                    + "ce sont les fichiers sur lesquels le système tourne, vus depuis le "
                    + "magasin.</p>\n</section>\n");
    }

    /// <summary>
    /// The inventory closes the report. It is context, and twenty-three lines of context
    /// before the first finding mean the finding never gets read.
    /// </summary>
    private static void WriteInventory(StringBuilder html, ReportView view)
    {
        html.Append("<section id=\"inventaire\">\n<h2>Inventaire</h2>\n");

        foreach (var collector in view.Result.Collectors)
        {
            var open = collector.Status == CollectorStatus.Ok ? string.Empty : " open";
            html.Append($"<details{open}>\n<summary>{Escape(collector.Name)} "
                        + $"<span class=\"count\">{Escape(ReportLabels.Of(collector.Status))}"
                        + "</span></summary>\n");

            foreach (var diagnostic in collector.Diagnostics)
            {
                html.Append($"<p class=\"banner warn\">{Escape(diagnostic)}</p>\n");
            }

            html.Append("<table class=\"fields\">\n<tbody>\n");
            foreach (var (key, value) in collector.Fields)
            {
                html.Append($"<tr><th>{Escape(key)}</th><td>{Escape(value ?? "—")}</td></tr>\n");
            }

            html.Append("</tbody>\n</table>\n</details>\n");
        }

        // The full enumeration, benign included. Kept collapsed: it is what makes the
        // report auditable, not what makes it readable.
        foreach (var group in view.Groups.OrderBy(g => g.Kind, StringComparer.Ordinal))
        {
            var findings = view.Result.Findings
                .Where(f => f.Kind == group.Kind)
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Target, StringComparer.Ordinal)
                .ToList();

            html.Append($"<details>\n<summary>{Escape(ReportLabels.Family(group.Kind))} "
                        + $"<span class=\"count\">{findings.Count} énumérés</span></summary>\n");
            html.Append("<table class=\"fields\">\n<tbody>\n");

            foreach (var finding in findings)
            {
                var label = ReportLabels.Of(finding.Severity);
                html.Append($"<tr><th><span class=\"sev s-{Slug(label)}\">{Escape(label)}</span></th>");
                html.Append($"<td>{Escape(finding.Target)}<span class=\"dom\">"
                            + $"{Escape(finding.Source)}</span></td></tr>\n");
            }

            html.Append("</tbody>\n</table>\n</details>\n");
        }

        html.Append("</section>\n");
    }

    private static void WriteFooter(StringBuilder html, ReportView view)
    {
        html.Append("<footer>\n");
        html.Append($"<p>Rempart {Escape(view.Result.ToolVersion)} — audit en lecture seule : "
                    + "cette version ne modifie rien sur la machine.</p>\n");
        html.Append("<p>Rapport autonome : aucun appel réseau, aucune ressource externe. "
                    + "Le JSON produit à côté porte la donnée complète.</p>\n");
        html.Append("</footer>\n");
    }

    /// <summary>Same wording as the console header — one source of truth for the reader.</summary>
    private static string DescribeAge(DataAge age)
    {
        if (age.Unknown)
        {
            return "date de référence illisible";
        }

        var asOf = ReportView.DateOf(age.AsOfUtc);
        var summary = age.Days == 0
            ? $"catalogue au {asOf}, à jour"
            : $"catalogue au {asOf}, {age.Days} jour{(age.Days > 1 ? "s" : "")}";

        return age.Stale ? $"{summary} — au-delà de {age.ThresholdDays} j" : summary;
    }

    private static string Band(int score) => score switch
    {
        >= 90 => "good",
        >= 60 => "warn",
        _ => "bad",
    };

    /// <summary>
    /// Class-name form of a label. Accented French words make poor CSS class names, and
    /// the mapping is closed: an unknown label lands on a neutral class rather than
    /// producing an attribute that would need escaping in its own right.
    /// </summary>
    private static string Slug(string label) => label switch
    {
        "critique" => "crit",
        "élevée" => "high",
        "moyenne" => "med",
        "faible" => "low",
        "suspect" => "susp",
        "notable" => "note",
        _ => "info",
    };

    /// <summary>
    /// Escapes text for HTML.
    ///
    /// Applied to every single interpolation, including strings that "obviously" cannot
    /// contain markup: the value of a registry key, the name of a service and the
    /// command line of a process are all chosen by whoever is on the audited machine.
    /// Quotes are escaped too — several of these values land in attributes.
    /// </summary>
    internal static string Escape(string text)
    {
        // Fast path: reports carry thousands of strings and almost none need work.
        if (text.AsSpan().IndexOfAny("&<>\"'") < 0)
        {
            return text;
        }

        var escaped = new StringBuilder(text.Length + 16);
        foreach (var character in text)
        {
            switch (character)
            {
                case '&': escaped.Append("&amp;"); break;
                case '<': escaped.Append("&lt;"); break;
                case '>': escaped.Append("&gt;"); break;
                case '"': escaped.Append("&quot;"); break;
                case '\'': escaped.Append("&#39;"); break;
                default: escaped.Append(character); break;
            }
        }

        return escaped.ToString();
    }

    /// <summary>
    /// Inline stylesheet. System fonts only: a downloaded font would be a network call
    /// from the reader's machine, and the report promises none.
    /// </summary>
    private const string Style = """
        :root {
          color-scheme: light dark;
          --bg: #f6f7f9; --panel: #ffffff; --ink: #16181d; --dim: #5c6370;
          --line: #dfe3e8; --accent: #2f5d8c;
          --good: #1f7a4d; --warn: #a86300; --bad: #b3261e;
          --good-bg: #e6f4ec; --warn-bg: #fdf1de; --bad-bg: #fbeae9;
        }
        @media (prefers-color-scheme: dark) {
          :root {
            --bg: #14161a; --panel: #1c1f25; --ink: #e6e8ec; --dim: #99a1ae;
            --line: #2d323b; --accent: #7fb0e0;
            --good: #5cc98d; --warn: #e0a24a; --bad: #f0736a;
            --good-bg: #17301f; --warn-bg: #33260f; --bad-bg: #331a19;
          }
        }
        :root[data-theme="light"] {
          color-scheme: light;
          --bg: #f6f7f9; --panel: #ffffff; --ink: #16181d; --dim: #5c6370;
          --line: #dfe3e8; --accent: #2f5d8c;
          --good: #1f7a4d; --warn: #a86300; --bad: #b3261e;
          --good-bg: #e6f4ec; --warn-bg: #fdf1de; --bad-bg: #fbeae9;
        }
        :root[data-theme="dark"] {
          color-scheme: dark;
          --bg: #14161a; --panel: #1c1f25; --ink: #e6e8ec; --dim: #99a1ae;
          --line: #2d323b; --accent: #7fb0e0;
          --good: #5cc98d; --warn: #e0a24a; --bad: #f0736a;
          --good-bg: #17301f; --warn-bg: #33260f; --bad-bg: #331a19;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0; padding: 0 1.5rem 4rem; background: var(--bg); color: var(--ink);
          font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
        }
        header, section, footer { max-width: 68rem; margin: 0 auto; }
        .bar { display: flex; align-items: center; justify-content: space-between;
               padding: 1.25rem 0 0.5rem; }
        .brand { font-weight: 700; letter-spacing: .02em; color: var(--accent); }
        .ver { font-weight: 400; color: var(--dim); }
        h1 { margin: .25rem 0; font-size: 1.9rem; word-break: break-word; }
        h2 { margin: 2.5rem 0 .75rem; font-size: 1.15rem; text-transform: uppercase;
             letter-spacing: .08em; color: var(--dim); }
        h3 { margin: 1.75rem 0 .5rem; font-size: 1rem; }
        .meta { margin: 0 0 .5rem; color: var(--dim); font-size: .875rem; }
        code { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: .9em; }
        button { font: inherit; cursor: pointer; border: 1px solid var(--line);
                 background: var(--panel); color: var(--ink); border-radius: 6px;
                 padding: .3rem .7rem; }
        button:hover { border-color: var(--accent); }
        .banners { margin-top: 1rem; }
        .banner { margin: .4rem 0; padding: .65rem .85rem; border-radius: 6px;
                  border-left: 4px solid var(--dim); background: var(--panel); }
        .banner.warn { border-color: var(--warn); background: var(--warn-bg); }
        .banner.bad  { border-color: var(--bad);  background: var(--bad-bg); }
        .banner.info { border-color: var(--accent); }
        .tiles { display: flex; flex-wrap: wrap; gap: .75rem; }
        .tile { flex: 1 1 8rem; background: var(--panel); border: 1px solid var(--line);
                border-radius: 8px; padding: .9rem 1rem; display: flex;
                flex-direction: column; gap: .15rem; }
        .tile .num { font-size: 1.75rem; font-weight: 700; line-height: 1.1; }
        .tile .cap { color: var(--dim); font-size: .8rem; }
        .tile.big { flex: 1 1 12rem; border-color: var(--accent); }
        .tile.good .num { color: var(--good); }
        .tile.warn .num { color: var(--warn); }
        .tile.bad  .num { color: var(--bad); }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem;
                background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
        th, td { text-align: left; padding: .5rem .7rem; border-bottom: 1px solid var(--line);
                 vertical-align: top; }
        thead th { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em;
                   color: var(--dim); }
        tbody tr:last-child th, tbody tr:last-child td { border-bottom: 0; }
        td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
        .obs { font-family: ui-monospace, Consolas, monospace; font-size: .85rem;
               word-break: break-word; }
        .obs.bad { color: var(--bad); }
        /* Fixed track, so the bar's length is the score and nothing else. Never cap
           the bar: a cap flattens the top of the scale and makes 67 % look like
           100 %, which is the one reading a posture report must not allow. */
        .gauge { white-space: nowrap; }
        .track { display: inline-block; width: 9rem; height: .5rem; border-radius: 3px;
                 background: var(--line); vertical-align: middle; overflow: hidden; }
        .track .bar { display: block; height: 100%; border-radius: 3px;
                      background: var(--dim); }
        .track .bar.good { background: var(--good); }
        .track .bar.warn { background: var(--warn); }
        .track .bar.bad  { background: var(--bad); }
        .gauge .pct { margin-left: .5rem; font-variant-numeric: tabular-nums;
                      font-size: .85rem; color: var(--dim); }
        .sev { display: inline-block; padding: .05rem .45rem; border-radius: 999px;
               font-size: .72rem; text-transform: uppercase; letter-spacing: .05em;
               border: 1px solid currentColor; white-space: nowrap; }
        .s-crit, .s-susp { color: var(--bad); }
        .s-high, .s-note { color: var(--warn); }
        .s-med { color: var(--warn); }
        .s-low, .s-info { color: var(--dim); }
        .dom { display: block; color: var(--dim); font-size: .8rem; word-break: break-all; }
        .toolbar { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center;
                   margin-top: .75rem; }
        .toolbar .search { flex: 1 1 16rem; }
        .toolbar input[type=search] { width: 100%; font: inherit; padding: .35rem .6rem;
                   border: 1px solid var(--line); border-radius: 6px;
                   background: var(--panel); color: var(--ink); }
        .chip { display: inline-flex; align-items: center; gap: .3rem; padding: .25rem .6rem;
                border: 1px solid currentColor; border-radius: 999px; font-size: .8rem;
                cursor: pointer; user-select: none; }
        .family { display: flex; flex-wrap: wrap; align-items: baseline; gap: .5rem; }
        .count { font-size: .78rem; font-weight: 400; color: var(--dim);
                 border: 1px solid var(--line); border-radius: 999px; padding: .05rem .5rem; }
        .count.warn { color: var(--warn); border-color: currentColor; }
        .finding { background: var(--panel); border: 1px solid var(--line);
                   border-left: 4px solid var(--dim); border-radius: 8px;
                   padding: .7rem .9rem; margin-top: .6rem; }
        .finding[data-severity="suspect"] { border-left-color: var(--bad); }
        .finding[data-severity="notable"] { border-left-color: var(--warn); }
        .fhead { display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline; }
        .target { font-weight: 600; word-break: break-all; }
        .source { color: var(--dim); font-size: .85rem; word-break: break-all;
                  font-family: ui-monospace, Consolas, monospace; }
        .reasons { margin: .5rem 0 0; padding-left: 1.1rem; }
        .reasons li { margin: .15rem 0; }
        details { background: var(--panel); border: 1px solid var(--line);
                  border-radius: 8px; padding: .5rem .8rem; margin-top: .6rem; }
        details.det { border: 0; background: none; padding: .3rem 0 0; margin: 0; }
        summary { cursor: pointer; font-weight: 600; }
        details.det summary { font-weight: 400; color: var(--dim); font-size: .85rem; }
        dl { display: grid; grid-template-columns: minmax(6rem, auto) 1fr; gap: .1rem .8rem;
             margin: .4rem 0 0; font-size: .85rem; }
        dt { color: var(--dim); }
        dd { margin: 0; word-break: break-all;
             font-family: ui-monospace, Consolas, monospace; }
        .plainlist { margin: .5rem 0 0; padding-left: 1.1rem; }
        .hint { color: var(--dim); font-size: .85rem; margin: .5rem 0 0; }
        .hint.ok { color: var(--good); }
        .fields th { width: 14rem; color: var(--dim); font-weight: 400; }
        .fields td { word-break: break-word; }
        footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
                 color: var(--dim); font-size: .8rem; }
        .hidden { display: none !important; }
        @media print {
          .toolbar, #theme { display: none; }
          body { background: #fff; color: #000; }
          .finding, details, table { break-inside: avoid; }
        }
        """;

    /// <summary>
    /// Inline script — the whole of it.
    ///
    /// It reads no scan data: it toggles a theme attribute and hides nodes already in
    /// the document. That is deliberate. Serialising findings into a script would open
    /// a second injection path with its own escaping rules, right next to the one that
    /// matters; there is nothing to get wrong here because there is nothing here.
    /// </summary>
    private const string Script = """
        (function () {
          var root = document.documentElement;
          var stored = null;
          // Opened from a file, storage can be denied outright: the theme is then not
          // remembered, which is not a reason to stop rendering the rest.
          try { stored = localStorage.getItem('rempart-theme'); } catch (e) { }
          if (stored) { root.setAttribute('data-theme', stored); }

          var toggle = document.getElementById('theme');
          if (toggle) {
            toggle.addEventListener('click', function () {
              var dark = root.getAttribute('data-theme') === 'dark'
                || (!root.hasAttribute('data-theme')
                    && window.matchMedia('(prefers-color-scheme: dark)').matches);
              var next = dark ? 'light' : 'dark';
              root.setAttribute('data-theme', next);
              try { localStorage.setItem('rempart-theme', next); } catch (e) { }
            });
          }

          document.querySelectorAll('.toolbar').forEach(function (toolbar) {
            var scope = toolbar.getAttribute('data-scope');
            var rows = Array.prototype.slice.call(
              document.querySelectorAll('[data-list="' + scope + '"] .row'));
            var search = toolbar.querySelector('input[type=search]');
            var boxes = Array.prototype.slice.call(
              toolbar.querySelectorAll('input[data-severity]'));

            function apply() {
              var needle = search ? search.value.trim().toLowerCase() : '';
              var kept = {};
              boxes.forEach(function (box) { kept[box.getAttribute('data-severity')] = box.checked; });

              rows.forEach(function (row) {
                var severity = row.getAttribute('data-severity');
                var bySeverity = !(severity in kept) || kept[severity];
                var byText = needle === ''
                  || (row.textContent || '').toLowerCase().indexOf(needle) !== -1;
                row.classList.toggle('hidden', !(bySeverity && byText));
              });
            }

            if (search) { search.addEventListener('input', apply); }
            boxes.forEach(function (box) { box.addEventListener('change', apply); });

            var expand = toolbar.querySelector('.expand');
            if (expand) {
              expand.addEventListener('click', function () {
                var open = expand.getAttribute('data-open') !== 'yes';
                document.querySelectorAll('details.det').forEach(function (node) {
                  node.open = open;
                });
                expand.setAttribute('data-open', open ? 'yes' : 'no');
                expand.textContent = open ? 'replier tout' : 'déplier tout';
              });
            }
          });
        })();
        """;
}
