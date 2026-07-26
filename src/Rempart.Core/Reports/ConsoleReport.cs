using System.Text;
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
            text.AppendLine("[posture] non vérifiable — accès refusé");
            foreach (var verdict in unknown)
            {
                text.AppendLine($"  {verdict.RuleId}  {verdict.Title}");
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
            text.AppendLine(
                $"  Score partiel : {score.TotalUnknown} contrôle(s) non vérifiable(s) sans élévation.");
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
