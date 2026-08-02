using System.Text;
using Rempart.Core.Diff;
using Rempart.Core.Drift;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Core.Reports;

/// <summary>
/// Renders a scan for the console: <c>ScanResult</c> in, text out.
///
/// <para>
/// Pure, and that is the whole point of it existing. M6 gave the HTML, Markdown and JSON
/// reports this treatment, which is how the score gauges capped at 70 % and the HTML
/// escaping were caught by tests rather than by a reader. The console output never got it:
/// it wrote straight to <see cref="Console"/>, so nothing could observe it, and CI checked
/// an exit code. A change in what the tool says was invisible until someone read it.
/// </para>
///
/// <para>
/// <see cref="StringBuilder.AppendLine()"/> is used rather than <c>'\n'</c> so the text
/// carries <see cref="Environment.NewLine"/> exactly as <c>Console.WriteLine</c> did: the
/// extraction has to leave the bytes on stdout unchanged, and a golden test compares them.
/// </para>
/// </summary>
public static class ConsoleReport
{
    /// <summary>
    /// What the reader comes for first: the problems. The inventory closes the report —
    /// it is context, and twenty-three lines of context before the first finding mean
    /// the finding never gets read.
    /// </summary>
    public static string HumanReadable(ScanResult result)
    {
        var text = new StringBuilder();

        text.AppendLine($"Rempart {result.ToolVersion} — scan du {result.StartedAtUtc}");
        text.AppendLine($"règles : {result.RulesFingerprint}");
        text.AppendLine($"données : {Age(result.DataAge)}");

        // Data provenance — applied or rejected — is always stated, never silent
        // (ADR-002, D14 and D17).
        if (result.UpdateNote is { } note)
        {
            text.AppendLine($"mise à jour : {note}");
        }

        if (result.IntegrityNote is { } integrity)
        {
            text.AppendLine($"intégrité : {integrity}");
        }

        if (result.RulesNote is { } rulesNote)
        {
            text.AppendLine($"catalogue : {rulesNote}");
        }

        if (result.Score is { } score)
        {
            Posture(text, result, score);
        }

        Findings(text, result.Findings);

        if (result.DnsProbe is { } probe)
        {
            DnsProbe(text, probe);
        }

        text.AppendLine();
        foreach (var collector in result.Collectors)
        {
            text.AppendLine($"[{collector.Name}] {collector.Status}");

            foreach (var (key, value) in collector.Fields)
            {
                text.AppendLine($"  {key,-32} {value ?? "—"}");
            }

            foreach (var diagnostic in collector.Diagnostics)
            {
                text.AppendLine($"  ! {diagnostic}");
            }
        }

        return text.ToString();
    }

    /// <summary>
    /// Renders the data age in one line. An unreadable date is stated as such, never
    /// silenced: "unknown" must not read as "up to date".
    ///
    /// <para>
    /// The age is read from the result, not computed here: Core establishes it at scan
    /// time (ADR-002, D15). That is what lets this renderer stay pure — nothing in it
    /// consults a clock, so the same result always renders the same text.
    /// </para>
    /// </summary>
    public static string Age(DataAge age)
    {
        if (age.Unknown)
        {
            return "date de référence illisible — impossible d'en juger l'ancienneté";
        }

        var asOf = age.AsOfUtc.Length >= 10 ? age.AsOfUtc[..10] : age.AsOfUtc;

        var summary = age.Days == 0
            ? $"catalogue au {asOf}, à jour"
            : $"catalogue au {asOf}, {age.Days} jour{(age.Days > 1 ? "s" : "")}";

        if (age.Stale)
        {
            summary += $" — au-delà de {age.ThresholdDays} j, envisager « rempart update »";
        }

        return summary;
    }

    /// <summary>
    /// Active DoH/DoT probe: advice, not a finding. Shown separately, outside the score,
    /// and clearly presented as a one-off measurement and a suggestion.
    /// </summary>
    private static void DnsProbe(StringBuilder text, Dns.DnsProbeReport probe)
    {
        text.AppendLine();
        text.AppendLine("[résolveurs chiffrés] latence mesurée (ponctuelle, depuis ce réseau) :");

        foreach (var result in probe.Results)
        {
            var state = result.Reachable ? $"{result.LatencyMs} ms" : $"bloqué ({result.Error})";
            text.AppendLine($"  {result.Resolver,-12} {result.Protocol,-4} {state}");
        }

        if (probe.RecommendedResolver is { } resolver)
        {
            text.AppendLine(
                $"  → suggestion : {resolver} en {probe.RecommendedProtocol} "
                + $"({probe.RecommendedLatencyMs} ms) est le plus rapide joignable.");
        }
        else
        {
            text.AppendLine("  → aucun résolveur chiffré joignable — voir le constat ci-dessus.");
        }
    }

    /// <summary>
    /// Findings do not blend into the score: a configuration at 94 % must not mask an
    /// unsigned binary launched at startup.
    /// </summary>
    private static void Findings(StringBuilder text, IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return;
        }

        var flagged = findings.Where(f => f.Severity != FindingSeverity.Benign).ToList();

        text.AppendLine();
        var byKind = string.Join(", ", findings
            .GroupBy(f => f.Kind)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => $"{g.Count()} {g.Key}"));

        text.AppendLine($"[constats] {byKind} — {flagged.Count} à examiner");

        foreach (var finding in flagged.OrderByDescending(f => f.Severity))
        {
            text.AppendLine();
            text.AppendLine($"  {finding.Severity.ToString().ToUpperInvariant(),-11} {finding.Source}");
            text.AppendLine($"              {finding.Target}");

            foreach (var reason in finding.Reasons)
            {
                text.AppendLine($"              → {reason}");
            }

            if (finding.Details.TryGetValue("éditeur", out var publisher))
            {
                text.AppendLine($"              éditeur : {publisher}");
            }

            if (finding.Details.TryGetValue("virustotal", out var virusTotal))
            {
                text.AppendLine($"              virustotal : {virusTotal}");
            }
        }
    }

    /// <summary>
    /// The comparison on the console. What got worse first: a reader who stops after the
    /// first screen must have seen the bad news, not the corrections.
    /// </summary>
    public static string Diff(DiffResult diff)
    {
        var text = new StringBuilder();

        text.AppendLine(diff.SameMachine
            ? $"{diff.AfterMachine} — évolution"
            : $"{diff.BeforeMachine} contre {diff.AfterMachine}");
        text.AppendLine($"  avant : {diff.BeforeAtUtc}");
        text.AppendLine($"  après : {diff.AfterAtUtc}");

        if (!diff.Comparable)
        {
            text.AppendLine();
            text.AppendLine($"! {diff.ComparabilityNote}");
        }

        text.AppendLine();
        text.AppendLine($"[synthèse] {DiffReport.Headline(diff)}");

        var scoreLine = $"  conformité {Percent(diff.ScoreBefore)} → {Percent(diff.ScoreAfter)}";
        text.AppendLine(diff.ScoreDelta is { } delta && delta != 0
            ? $"{scoreLine}  ({(delta > 0 ? "+" : string.Empty)}{delta} pts)"
            : scoreLine);

        foreach (var (shift, title, _) in DiffReport.Sections)
        {
            var changes = diff.Of(shift).ToList();

            if (changes.Count == 0)
            {
                continue;
            }

            text.AppendLine();
            text.AppendLine($"[{title.ToLowerInvariant()}]");

            foreach (var change in changes)
            {
                text.AppendLine($"  {change.RuleId,-14} {change.Title}");
                text.AppendLine($"                 {DescribeStatus(change.Before)} → " +
                                  $"{DescribeStatus(change.After)}");
            }
        }

        if (diff.Findings.Count > 0)
        {
            text.AppendLine();
            text.AppendLine($"[constats] {diff.Findings.Count} écart(s)");

            foreach (var change in diff.Findings)
            {
                text.AppendLine();
                text.AppendLine($"  {DescribeChange(change.Change),-9} {change.Target}");
                text.AppendLine($"            {change.Source}");

                foreach (var note in change.Notes)
                {
                    text.AppendLine($"            → {note}");
                }
            }
        }

        if (diff.Transients.Count > 0)
        {
            text.AppendLine();
            text.AppendLine(
                $"[mouvements attendus] {diff.Transients.Count} — Windows les retire ou les " +
                "renumérote de lui-même, hors de l'écart de posture");
        }

        if (diff.Fields.Count > 0)
        {
            text.AppendLine();
            text.AppendLine(diff.SameMachine
                ? $"[inventaire] {diff.Fields.Count} champ(s) modifié(s)"
                : $"[inventaire] {diff.Fields.Count} écart(s) — deux machines, c'est du contexte");

            foreach (var field in diff.Fields)
            {
                text.AppendLine($"  {field.Field,-32} {field.Before ?? "—"} → {field.After ?? "—"}");
            }
        }

        return text.ToString();
    }

    /// <summary>
    /// The fleet page, announced on the console. The command's real deliverable is the
    /// HTML file; this is the receipt — where it landed, how many reports it covers, and
    /// the same worst-first order the page uses, so a reader who never opens a browser
    /// still knows which machine to look at next.
    /// </summary>
    /// <param name="outputPath">
    /// Where the page was written. Passed in rather than computed: building it needs
    /// <c>Path.Combine</c>, which belongs to the CLI and to Windows. Taking it as data is
    /// what keeps this renderer pure, and replayable on the Linux job.
    /// </param>
    /// <param name="unreadable">
    /// Reports the caller could not parse. Counted and stated, never silent: a page built
    /// from nine of eleven machines must not read like a page built from all of them.
    /// </param>
    public static string Fleet(IReadOnlyList<FleetEntry> entries, string outputPath, int unreadable)
    {
        var text = new StringBuilder();

        text.AppendLine($"Parc écrit dans {outputPath} — {entries.Count} rapport(s)"
                        + (unreadable > 0 ? $", {unreadable} illisible(s)" : string.Empty));

        foreach (var entry in FleetIndex.Ordered(entries))
        {
            text.AppendLine($"  {entry.Machine,-24} {entry.Date}  " +
                            $"{(entry.Score is { } s ? $"{s,3} %" : "  n/d")}  " +
                            $"échecs {entry.Failures}, à examiner {entry.FlaggedFindings}");
        }

        return text.ToString();
    }

    /// <summary>
    /// What a drift run says to whoever is watching it run — and, in a scheduled run, to
    /// the transcript nobody reads until something looks wrong.
    ///
    /// <para>
    /// <paramref name="bytesOnDisk"/> is not decoration. Nothing prunes the report folder,
    /// and that choice is only defensible if the page says what it costs: the window it
    /// covers, how many reports it read, and what they weigh. A retention policy the tool
    /// refuses to enforce is one the reader has to be handed the numbers for.
    /// </para>
    /// </summary>
    public static string Drift(
        IReadOnlyList<DriftReport> reports, string outputPath, int unreadable, long bytesOnDisk)
    {
        var text = new StringBuilder();

        text.AppendLine($"Dérive écrite dans {outputPath} — {reports.Count} machine(s), "
                        + $"{reports.Sum(report => report.Points)} rapport(s) lus, "
                        + $"{ReportLabels.Bytes(bytesOnDisk)} sur le disque"
                        + (unreadable > 0 ? $", {unreadable} illisible(s)" : string.Empty));

        foreach (var report in reports)
        {
            text.AppendLine($"  {report.Machine,-24} {DriftPage.Day(report.First)} → "
                            + $"{DriftPage.Day(report.Last)}, {report.Points} point(s), "
                            + $"cadence {DriftPage.Cadence(report)}");

            if (report.Freshness.Stale)
            {
                text.AppendLine($"    dernière capture il y a {report.Freshness.DaysSinceLast} "
                                + "jours — vérifier que le suivi tourne encore");
            }

            if (report.LastPointPartial)
            {
                text.AppendLine("    le dernier scan a laissé des contrôles inévaluables");
            }

            foreach (var open in report.OpenRegressions)
            {
                text.AppendLine($"    régression ouverte {open.RuleId} — {open.Title}, "
                                + $"depuis le {DriftPage.Day(open.Since)} "
                                + $"({open.DaysObserved} jours observés)");
            }

            foreach (var control in report.Unstable)
            {
                text.AppendLine($"    instable {control.RuleId} — {control.Title}, "
                                + $"tombé {control.Regressions} fois");
            }

            if (report.OpenRegressions.Count == 0 && !report.Freshness.Stale)
            {
                text.AppendLine("    aucune régression ouverte");
            }
        }

        return text.ToString();
    }

    private static string Percent(int? score) => score is { } value ? $"{value} %" : "n/d";

    private static string DescribeStatus(VerdictStatus? status) => status switch
    {
        VerdictStatus.Pass => "conforme",
        VerdictStatus.Fail => "échec",
        VerdictStatus.Unknown => "non vérifié",
        VerdictStatus.NotApplicable => "hors périmètre",
        _ => "absent du catalogue",
    };

    private static string DescribeChange(ChangeKind change) => change switch
    {
        ChangeKind.Appeared => "apparu",
        ChangeKind.Disappeared => "disparu",
        _ => "modifié",
    };

    private static void Posture(StringBuilder text, ScanResult result, ScoreCard score)
    {
        // Satisfied rules are not listed, only counted: a report that drowns three
        // problems in a hundred green lines will not be read.
        var failures = result.Verdicts
            .Where(v => v.Status == VerdictStatus.Fail)
            .OrderByDescending(v => v.Severity)
            .ToList();

        if (failures.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("[posture] à corriger");
            foreach (var verdict in failures)
            {
                text.AppendLine(
                    $"  {verdict.Severity.ToString().ToUpperInvariant(),-8} " +
                    $"{verdict.RuleId}  {verdict.Title}");
                text.AppendLine($"           observé : {verdict.Observed ?? "absent"}" +
                                  (verdict.Expected is null ? "" : $"   attendu : {verdict.Expected}"));
            }
        }

        var unknown = result.Verdicts.Where(v => v.Status == VerdictStatus.Unknown).ToList();
        if (unknown.Count > 0)
        {
            text.AppendLine();

            // No « accès refusé » in the heading any more. Every Unknown verdict passed under
            // it whatever its cause, so a WMI repository that had stopped serving and a
            // service control manager that would not open were both announced as missing
            // privileges — the one remedy that cannot help. The cause belongs to the verdict,
            // and that is where it is printed.
            text.AppendLine("[posture] non vérifiable");
            foreach (var verdict in unknown)
            {
                text.AppendLine($"  {verdict.RuleId}  {verdict.Title}");

                // On an Unknown verdict, Observed carries what CheckReader put there: the
                // provider's diagnostic, or null for a plain refusal that has nothing to
                // explain. It reached the JSON report and stopped there.
                if (verdict.Observed is { } reason)
                {
                    text.AppendLine($"      {reason}");
                }
            }

            // Any, not All: a section holding one control that explained itself and one that
            // did not still owes its reader the remedy for the second. All reads the same on
            // every section the tests had — each carried a single Unknown — so the mutation
            // survived all three renderings and the guard guarded nothing.
            //
            // And only where elevation is still available to try. The remedy is elevation, so
            // on a scan that already had it the sentence is noise at best, which is what two
            // committed goldens printed over captures recording isElevated: true.
            if (!ReportView.ElevatedIn(result) && unknown.Any(v => v.Observed is null))
            {
                text.AppendLine();
                text.AppendLine($"  {ReportLabels.UnexplainedAdvice}");
            }
        }

        text.AppendLine();
        text.AppendLine("[score] par domaine");
        foreach (var domain in score.Domains)
        {
            var value = domain.Score is { } s ? $"{s,3} %" : "  n/d";
            text.AppendLine(
                $"  {domain.Domain,-18} {value}   " +
                $"conformes {domain.Passed}, échecs {domain.Failed}, non vérifiés {domain.Unknown}" +
                (domain.NotApplicable > 0 ? $", hors périmètre {domain.NotApplicable}" : string.Empty));
        }

        text.AppendLine();
        text.AppendLine($"  {"GLOBAL",-18} {(score.Overall is { } o ? $"{o,3} %" : "  n/d")}");

        if (score.IsPartial)
        {
            text.AppendLine();
            // « sans élévation » is gone from this line for the reason the section above
            // dropped it from its heading: it is the answer to a refusal and to nothing else,
            // and this counter does not know which of the two it is counting.
            text.AppendLine(
                $"  Score partiel : {score.TotalUnknown} contrôle(s) non vérifiable(s).");
            text.AppendLine(
                "  Les contrôles non vérifiés sont exclus du calcul, jamais comptés comme conformes.");
        }

        if (failures.Count > 0 || unknown.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("  « rempart explain <ID> » détaille une règle et ce que coûte sa correction.");
        }
    }
}
