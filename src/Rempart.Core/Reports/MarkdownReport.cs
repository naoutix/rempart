using System.Text;
using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Updates;

namespace Rempart.Core.Reports;

/// <summary>
/// The same report in Markdown: what gets pasted into a ticket, a mail or a wiki.
///
/// <para>
/// Deliberately not a downgraded HTML. Markdown is read as plain text as often as it
/// is rendered, so the layout has to survive both: no collapsed sections that would
/// hide content from a text reader, and the full enumeration left to the JSON rather
/// than dumped here. What a reader would fold away in HTML simply does not belong in
/// this format.
/// </para>
///
/// <para>
/// Machine-supplied strings meet a different hazard here than in HTML: a pipe in a
/// service path silently breaks a table row, a report whose rows shift by one column
/// attributes a finding to the wrong binary, and an extension named
/// <c>[Rapport complet](…)</c> turns an audit report into a link someone clicks. Hence
/// <see cref="Cell"/> on every value the scan carries — in a table or not — and never a
/// code span around one, for the reason given there.
/// </para>
/// </summary>
public static class MarkdownReport
{
    public static string Render(ScanResult result)
    {
        var view = ReportView.From(result);
        var md = new StringBuilder(32 * 1024);

        md.Append($"# Rempart — {Cell(view.MachineName)}\n\n");
        md.Append($"- **Scan** : {result.StartedAtUtc}\n");
        md.Append($"- **Version** : {result.ToolVersion}\n");
        md.Append($"- **Règles** : `{result.RulesFingerprint}`\n");
        md.Append($"- **Données** : {Age(result.DataAge)}\n");

        if (result.UpdateNote is { } update)
        {
            md.Append($"- **Mise à jour** : {update}\n");
        }

        if (result.IntegrityNote is { } integrity)
        {
            md.Append($"- **Intégrité** : {integrity}\n");
        }

        if (result.RulesNote is { } rulesNote)
        {
            md.Append($"- **Catalogue** : {rulesNote}\n");
        }

        md.Append('\n');

        WriteCaveats(md, view);
        WriteScore(md, view);
        WritePosture(md, view);
        WriteFindings(md, view);
        WriteDnsProbe(md, view);
        WriteReclaimable(md, view);
        WriteInventory(md, view);

        md.Append("\n---\n\n");
        md.Append($"Rempart {result.ToolVersion} — audit en lecture seule : cette version ne "
                  + "modifie rien sur la machine. Le JSON produit à côté porte la donnée "
                  + "complète, constats bénins compris.\n");

        return md.ToString();
    }

    private static void WriteCaveats(StringBuilder md, ReportView view)
    {
        var caveats = new List<string>();

        if (!view.Elevated)
        {
            caveats.Add("**Scan non élevé.** Les contrôles hors de portée sont marqués « non "
                        + "vérifié », jamais comptés comme conformes. Relancer en administrateur "
                        + "pour un audit complet.");
        }

        if (view.Result.Score is { IsPartial: true } partial)
        {
            caveats.Add($"**Score partiel** : {partial.TotalUnknown} contrôle(s) n'ont pas pu être "
                        + "lus et sont exclus du calcul.");
        }

        foreach (var collector in view.DegradedCollectors)
        {
            caveats.Add($"**Collecteur « {Cell(collector.Name)} »** : {ReportLabels.Of(collector.Status)}. "
                        + "Ce qu'il aurait remonté est absent de ce rapport.");
        }

        if (caveats.Count == 0)
        {
            return;
        }

        md.Append("## Ce qui limite ce rapport\n\n");
        foreach (var caveat in caveats)
        {
            md.Append($"> {caveat}\n>\n");
        }

        md.Append('\n');
    }

    private static void WriteScore(StringBuilder md, ReportView view)
    {
        if (view.Result.Score is not { } score)
        {
            return;
        }

        md.Append("## Synthèse\n\n");
        md.Append($"| Conformité globale | {(score.Overall is { } o ? $"**{o} %**" : "n/d")} |\n");
        md.Append("|---|---|\n");
        md.Append($"| Contrôles en échec | {view.Failures.Count} |\n");
        md.Append($"| Non vérifiables | {view.Unverifiable.Count} |\n");
        md.Append($"| Constats à examiner | {view.FlaggedFindings} |\n");
        md.Append($"| Éléments énumérés | {view.TotalFindings} |\n\n");

        md.Append("| Domaine | Score | Conformes | Échecs | Non vérifiés | Hors périmètre |\n");
        md.Append("|---|---:|---:|---:|---:|---:|\n");
        foreach (var domain in score.Domains)
        {
            md.Append($"| {Cell(domain.Domain)} | {(domain.Score is { } s ? $"{s} %" : "n/d")} "
                      + $"| {domain.Passed} | {domain.Failed} | {domain.Unknown} "
                      + $"| {domain.NotApplicable} |\n");
        }

        md.Append('\n');
    }

    private static void WritePosture(StringBuilder md, ReportView view)
    {
        if (view.Failures.Count == 0 && view.Unverifiable.Count == 0)
        {
            return;
        }

        md.Append("## Posture — configuration\n\n");

        if (view.Failures.Count > 0)
        {
            md.Append("| Sévérité | Contrôle | Domaine | Observé | Attendu |\n");
            md.Append("|---|---|---|---|---|\n");
            foreach (var verdict in view.Failures)
            {
                // No code span around a value, here or anywhere below: one that fails to
                // close spills its formatting into the next cell, and a report where a
                // value appears to belong to another column is worse than an unstyled
                // one. Cell says why the two cannot be combined either way.
                md.Append($"| {ReportLabels.Of(verdict.Severity)} "
                          + $"| {Cell(verdict.RuleId)} {Cell(verdict.Title)} "
                          + $"| {Cell(verdict.Domain)} "
                          + $"| {Cell(verdict.Observed ?? "absent")} "
                          + $"| {Cell(verdict.Expected ?? "—")} |\n");
            }

            md.Append("\n`rempart explain <ID>` détaille une règle, sa justification et ce que "
                      + "coûte sa correction.\n\n");
        }

        if (view.Unverifiable.Count > 0)
        {
            // No « accès refusé » in the heading, for the reason the two sibling renderers
            // dropped it: it labelled a failure as a permission, and elevating answers only
            // one of the two. The reason belongs to the verdict and is printed there.
            md.Append($"### Non vérifiables ({view.Unverifiable.Count})\n\n");
            // Any, not All, and not elevated: see the console, which carries the argument for
            // all three.
            md.Append("Ni conformes ni non conformes : exclus du score."
                      + (!view.Elevated && view.Unverifiable.Any(v => v.Observed is null)
                          ? $" {ReportLabels.UnexplainedAdvice}"
                          : string.Empty)
                      + "\n\n");
            foreach (var verdict in view.Unverifiable)
            {
                // Cell on the reason as on everything else the machine chose: it is a
                // provider diagnostic, and a pipe or a bracket in it would shift a row or
                // form a link exactly as one in a service path would.
                md.Append($"- {Cell(verdict.RuleId)} {Cell(verdict.Title)}"
                          + (verdict.Observed is { } reason ? $" — {Cell(reason)}" : string.Empty)
                          + "\n");
            }

            md.Append('\n');
        }
    }

    private static void WriteFindings(StringBuilder md, ReportView view)
    {
        if (view.Groups.Count == 0)
        {
            return;
        }

        md.Append("## Constats — ce qui est présent\n\n");
        md.Append("Les constats ne se mélangent pas au score : une configuration à 94 % ne doit "
                  + "pas masquer un binaire non signé lancé au démarrage.\n\n");

        md.Append("| Famille | Énumérés | À examiner |\n|---|---:|---:|\n");
        foreach (var group in view.Groups)
        {
            md.Append($"| {Cell(ReportLabels.Family(group.Kind))} | {group.Total} "
                      + $"| {group.Flagged.Count} |\n");
        }

        md.Append('\n');

        foreach (var group in view.Groups.Where(g => g.Flagged.Count > 0))
        {
            md.Append($"### {Cell(ReportLabels.Family(group.Kind))}\n\n");

            foreach (var finding in group.Flagged)
            {
                md.Append($"**{ReportLabels.Of(finding.Severity)}** — {Cell(finding.Target)}\n\n");
                md.Append($"- source : {Cell(finding.Source)}\n");

                foreach (var reason in finding.Reasons)
                {
                    md.Append($"- {Cell(reason)}\n");
                }

                foreach (var (key, value) in finding.Details.OrderBy(d => d.Key, StringComparer.Ordinal))
                {
                    md.Append($"- {Cell(key)} : {Cell(value)}\n");
                }

                md.Append('\n');
            }
        }
    }

    private static void WriteDnsProbe(StringBuilder md, ReportView view)
    {
        if (view.Result.DnsProbe is not { } probe)
        {
            return;
        }

        md.Append("## Résolveurs chiffrés — mesure ponctuelle\n\n");
        md.Append("Latence mesurée depuis ce réseau, au moment du scan. Cette section est un "
                  + "avis : elle reste **hors du score**.\n\n");
        md.Append("| Résolveur | Protocole | État |\n|---|---|---|\n");

        foreach (var probed in probe.Results)
        {
            var state = probed.Reachable
                ? $"{probed.LatencyMs} ms"
                : $"bloqué — {Cell(probed.Error ?? "sans détail")}";
            md.Append($"| {Cell(probed.Resolver)} | {probed.Protocol} | {state} |\n");
        }

        md.Append('\n');
        md.Append(probe.RecommendedResolver is { } resolver
            ? $"Suggestion : {Cell(resolver)} en {probe.RecommendedProtocol} "
              + $"({probe.RecommendedLatencyMs} ms) est le plus rapide joignable.\n\n"
            : "Aucun résolveur chiffré joignable depuis ce réseau.\n\n");
    }

    /// <summary>
    /// Reclaimable space, by layer. The breakdown matters more than the total: most of
    /// the store is shared with the running Windows and cannot be freed.
    /// </summary>
    private static void WriteReclaimable(StringBuilder md, ReportView view)
    {
        if (view.ComponentStore is not { } store)
        {
            return;
        }

        md.Append("## Espace récupérable\n\n");
        md.Append("Mesuré par la pile de maintenance de Windows. Rempart **ne supprime "
                  + "rien** : il indique ce qu'un nettoyage libérerait.\n\n");
        md.Append("| Couche | Taille |\n|---|---:|\n");

        foreach (var (label, field) in ReportView.ComponentStoreLayers)
        {
            if (store.TryGetValue(field, out var raw) && long.TryParse(raw, out var bytes))
            {
                md.Append($"| {Cell(label)} | {ReportLabels.Bytes(bytes)} |\n");
            }
        }

        if (store.TryGetValue("store.lastCleanup", out var cleaned) && cleaned is not null)
        {
            md.Append($"| dernier nettoyage | {Cell(cleaned)} |\n");
        }

        if (store.TryGetValue("store.cleanupRecommended", out var recommended)
            && recommended is not null)
        {
            md.Append($"| nettoyage recommandé par Windows | {Cell(recommended)} |\n");
        }

        md.Append("\nLa part partagée avec Windows n'est pas récupérable : ce sont les "
                  + "fichiers sur lesquels le système tourne, vus depuis le magasin.\n\n");
    }

    private static void WriteInventory(StringBuilder md, ReportView view)
    {
        md.Append("## Inventaire\n\n");

        foreach (var collector in view.Result.Collectors)
        {
            md.Append($"### {Cell(collector.Name)} — {ReportLabels.Of(collector.Status)}\n\n");

            foreach (var diagnostic in collector.Diagnostics)
            {
                md.Append($"> {Cell(diagnostic)}\n>\n");
            }

            if (collector.Diagnostics.Count > 0)
            {
                md.Append('\n');
            }

            md.Append("| Champ | Valeur |\n|---|---|\n");
            foreach (var (key, value) in collector.Fields)
            {
                md.Append($"| {Cell(key)} | {Cell(value ?? "—")} |\n");
            }

            md.Append('\n');
        }
    }

    private static string Age(DataAge age)
    {
        if (age.Unknown)
        {
            return "date de référence illisible";
        }

        var summary = age.Days == 0
            ? $"catalogue au {ReportView.DateOf(age.AsOfUtc)}, à jour"
            : $"catalogue au {ReportView.DateOf(age.AsOfUtc)}, {age.Days} jour"
              + (age.Days > 1 ? "s" : string.Empty);

        return age.Stale ? $"{summary} — au-delà de {age.ThresholdDays} j" : summary;
    }

    /// <summary>
    /// Makes a value the audited machine chose inert. Applied to every one of them,
    /// wherever it lands — a table cell, a heading, a bullet, a quoted diagnostic.
    ///
    /// <para>
    /// Each character below carries structure a value must not be able to seize. A pipe
    /// does not break the render, it shifts every following column by one, so the row
    /// stays plausible while naming the wrong binary. A newline ends the row, or the
    /// bullet, outright. A backtick closes a code span early and spills its formatting
    /// over what follows. A <c>[</c> is the only way to open a link or an image, which
    /// is how an extension named <c>[Rapport complet](javascript:…)</c> becomes one
    /// click in a report about that very extension — GitHub neutralises the scheme,
    /// several previews and wiki importers do not. A <c>&lt;</c> opens an autolink or a
    /// raw HTML tag, which Markdown hands through untouched. Service paths, registry
    /// values and extension names carry all five routinely.
    /// </para>
    ///
    /// <para>
    /// Emphasis markers are deliberately left alone. They can make a value bold; they
    /// cannot make it look like another value or become a link. Escaping every
    /// underscore of every registry path would cost the reader more than the stray
    /// italics do — this format is read as plain text as often as it is rendered.
    /// </para>
    ///
    /// <para>
    /// A backslash is doubled only when it guards one of those characters, so that a
    /// backslash already in the value cannot swallow the one we add and hand the
    /// character back live. Left alone everywhere else, which is what keeps
    /// <c>C:\Windows\System32</c> readable.
    /// </para>
    ///
    /// <para>
    /// The result must never be wrapped in a code span. Backslash escapes are inert
    /// inside one, so fencing an escaped value hands every character back and adds a
    /// delimiter the value can close early: fencing and escaping are alternatives, and
    /// only escaping survives a value that is chosen against us. A test walks the whole
    /// rendered document for both mistakes rather than naming the sites, because the
    /// naming is what failed here.
    /// </para>
    /// </summary>
    internal static string Cell(string text)
    {
        // Fast path: a report carries thousands of strings and almost none need work.
        if (text.AsSpan().IndexOfAny(Structural) < 0)
        {
            return text;
        }

        var escaped = new StringBuilder(text.Length + 16);

        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];

            switch (character)
            {
                case '\r':
                    // CRLF is one break, not two.
                    if (index + 1 < text.Length && text[index + 1] == '\n')
                    {
                        index++;
                    }

                    escaped.Append(' ');
                    break;

                case '\n':
                    escaped.Append(' ');
                    break;

                case '\\' when index + 1 < text.Length && Structural.Contains(text[index + 1]):
                    escaped.Append(@"\\");
                    break;

                case '|':
                case '`':
                case '[':
                case '<':
                    escaped.Append('\\').Append(character);
                    break;

                default:
                    escaped.Append(character);
                    break;
            }
        }

        return escaped.ToString();
    }

    /// <summary>
    /// What <see cref="Cell"/> has to look at: the characters it escapes, plus the
    /// backslash that could neutralise an escape and the two line breaks it flattens.
    /// One list, so the fast path and the backslash rule cannot drift apart.
    /// </summary>
    private const string Structural = "|`[<\\\r\n";
}
