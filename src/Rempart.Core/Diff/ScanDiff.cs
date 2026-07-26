using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Rules;

namespace Rempart.Core.Diff;

/// <summary>How a rule's verdict moved between the two scans.</summary>
public enum VerdictShift
{
    /// <summary>Was compliant, is not any more. The reason this command exists.</summary>
    Regression,

    /// <summary>Was failing, now passes.</summary>
    Correction,

    /// <summary>Had a verdict, no longer readable. Not a regression — an audit that got blinder.</summary>
    VisibilityLost,

    /// <summary>Could not be read, now can. Usually an elevated re-run.</summary>
    VisibilityGained,

    /// <summary>Evaluated only in the later scan: the catalog gained this rule.</summary>
    Appeared,

    /// <summary>Evaluated only in the earlier scan.</summary>
    Disappeared,

    /// <summary>A move none of the above describes — reported rather than dropped.</summary>
    Other,
}

public sealed record VerdictChange(
    string RuleId,
    string Title,
    Severity Severity,
    string Domain,
    VerdictStatus? Before,
    VerdictStatus? After,
    VerdictShift Shift);

public enum ChangeKind
{
    Appeared,
    Disappeared,
    Changed,
}

public sealed record FindingChange(
    string Kind,
    string Source,
    string Target,
    ChangeKind Change,
    FindingSeverity? Before,
    FindingSeverity? After,

    /// <summary>What moved, in words: severity, target, fingerprint.</summary>
    IReadOnlyList<string> Notes);

public sealed record FieldChange(string Collector, string Field, string? Before, string? After);

public sealed record DomainScoreChange(string Domain, int? Before, int? After);

public sealed record DiffResult(
    string BeforeMachine,
    string AfterMachine,
    string BeforeAtUtc,
    string AfterAtUtc,

    /// <summary>
    /// Same machine on both sides, decided on the machine name. Changes the reading:
    /// between two machines an inventory difference is context, on one machine over time
    /// it is an event.
    /// </summary>
    bool SameMachine,

    /// <summary>Both scans evaluated the same catalog. Otherwise the comparison still
    /// happens, and says so.</summary>
    bool Comparable,
    string ComparabilityNote,

    int? ScoreBefore,
    int? ScoreAfter,
    IReadOnlyList<DomainScoreChange> Domains,
    IReadOnlyList<VerdictChange> Verdicts,
    IReadOnlyList<FindingChange> Findings,

    /// <summary>
    /// Disappearances Windows causes by itself. Kept out of the posture delta, and
    /// listed rather than dropped.
    /// </summary>
    IReadOnlyList<FindingChange> Transients,

    IReadOnlyList<FieldChange> Fields)
{
    public IEnumerable<VerdictChange> Of(VerdictShift shift) =>
        Verdicts.Where(v => v.Shift == shift);

    public int? ScoreDelta => ScoreBefore is { } before && ScoreAfter is { } after
        ? after - before
        : null;

    /// <summary>
    /// Nothing moved that anyone should act on. Transients and inventory context do not
    /// count: they are shown, but they are not news.
    /// </summary>
    public bool NothingToReport => Verdicts.Count == 0 && Findings.Count == 0;
}

/// <summary>
/// Compares two scans.
///
/// <para>
/// Pure, and fed by the JSON report of M6 rather than by a machine: comparing two
/// postures never requires either machine to be present, and the comparison is testable
/// without Windows.
/// </para>
///
/// <para>
/// Three concepts, compared three ways, because they answer different questions.
/// <b>Verdicts</b> are keyed by rule identifier and classified by how they moved — a
/// rule that became unreadable is not a rule that started failing, and confusing the two
/// would hide an audit that simply went blind. <b>Findings</b> are keyed by what they
/// designate, and a fingerprint change on an otherwise identical entry is the strongest
/// signal here: same startup key, same path, different binary. <b>Inventory fields</b>
/// are context, minus the volatile ones — an uptime differs on every run.
/// </para>
/// </summary>
public static class ScanDiff
{
    public static DiffResult Compare(ScanResult before, ScanResult after)
    {
        var beforeMachine = MachineName(before);
        var afterMachine = MachineName(after);
        var comparable = string.Equals(
            before.RulesFingerprint, after.RulesFingerprint, StringComparison.Ordinal);

        var (findings, transients) = CompareFindings(before.Findings, after.Findings);

        return new DiffResult(
            BeforeMachine: beforeMachine,
            AfterMachine: afterMachine,
            BeforeAtUtc: before.StartedAtUtc,
            AfterAtUtc: after.StartedAtUtc,
            SameMachine: string.Equals(beforeMachine, afterMachine, StringComparison.OrdinalIgnoreCase),
            Comparable: comparable,
            ComparabilityNote: comparable
                ? $"Même catalogue des deux côtés ({before.RulesFingerprint})."
                : $"Catalogues différents : {before.RulesFingerprint} puis "
                  + $"{after.RulesFingerprint}. La comparaison est faite quand même — "
                  + "refuser rendrait l'outil inutilisable dès la première mise à jour — "
                  + "mais les règles n'existant que d'un côté sont listées comme telles, "
                  + "et un écart de score peut ne venir que du catalogue.",
            ScoreBefore: before.Score?.Overall,
            ScoreAfter: after.Score?.Overall,
            Domains: CompareDomains(before.Score, after.Score),
            Verdicts: CompareVerdicts(before.Verdicts, after.Verdicts),
            Findings: findings,
            Transients: transients,
            Fields: CompareFields(before.Collectors, after.Collectors));
    }

    private static string MachineName(ScanResult result) =>
        result.Collectors
            .FirstOrDefault(c => c.Name == "inventory")
            ?.Fields.GetValueOrDefault("machine.name")
        ?? "machine inconnue";

    private static IReadOnlyList<VerdictChange> CompareVerdicts(
        IReadOnlyList<Verdict> before, IReadOnlyList<Verdict> after)
    {
        var earlier = before.ToDictionary(v => v.RuleId, StringComparer.OrdinalIgnoreCase);
        var later = after.ToDictionary(v => v.RuleId, StringComparer.OrdinalIgnoreCase);

        var changes = new List<VerdictChange>();

        foreach (var id in earlier.Keys.Union(later.Keys, StringComparer.OrdinalIgnoreCase))
        {
            var was = earlier.GetValueOrDefault(id);
            var now = later.GetValueOrDefault(id);

            if (was?.Status == now?.Status)
            {
                continue;
            }

            // Whichever side exists describes the rule; the later one wins, since its
            // wording is the one a reader can act on today.
            var described = now ?? was!;

            changes.Add(new VerdictChange(
                described.RuleId, described.Title, described.Severity, described.Domain,
                was?.Status, now?.Status, Shift(was?.Status, now?.Status)));
        }

        // Worst first, then by identifier so two runs order ties identically.
        return
        [
            .. changes
                .OrderBy(c => c.Shift)
                .ThenByDescending(c => c.Severity)
                .ThenBy(c => c.RuleId, StringComparer.Ordinal),
        ];
    }

    private static VerdictShift Shift(VerdictStatus? before, VerdictStatus? after) =>
        (before, after) switch
        {
            (null, _) => VerdictShift.Appeared,
            (_, null) => VerdictShift.Disappeared,

            // A check that became unreadable is not a check that started failing. An
            // audit losing sight of something calls for elevation; a failure calls for
            // a fix. Merging them would hide the first behind the second.
            (not VerdictStatus.Unknown, VerdictStatus.Unknown) => VerdictShift.VisibilityLost,
            (VerdictStatus.Unknown, not VerdictStatus.Unknown) => VerdictShift.VisibilityGained,

            (VerdictStatus.Pass, VerdictStatus.Fail) => VerdictShift.Regression,
            (VerdictStatus.Fail, VerdictStatus.Pass) => VerdictShift.Correction,

            // NotApplicable on either side: the machine changed context — joined a
            // domain, enabled RDP. Real, but neither a regression nor a fix.
            _ => VerdictShift.Other,
        };

    private static IReadOnlyList<DomainScoreChange> CompareDomains(
        ScoreCard? before, ScoreCard? after)
    {
        var earlier = (before?.Domains ?? []).ToDictionary(
            d => d.Domain, d => d.Score, StringComparer.OrdinalIgnoreCase);
        var later = (after?.Domains ?? []).ToDictionary(
            d => d.Domain, d => d.Score, StringComparer.OrdinalIgnoreCase);

        return
        [
            .. earlier.Keys.Union(later.Keys, StringComparer.OrdinalIgnoreCase)
                .OrderBy(domain => domain, StringComparer.OrdinalIgnoreCase)
                .Select(domain => new DomainScoreChange(
                    domain,
                    earlier.GetValueOrDefault(domain),
                    later.GetValueOrDefault(domain))),
        ];
    }

    /// <summary>Identity of a finding: what it designates, not what it says about it.</summary>
    private static (string Kind, string Source, string Target) Key(Finding finding) =>
        (finding.Kind, finding.Source, finding.Target);

    private static (IReadOnlyList<FindingChange> Posture, IReadOnlyList<FindingChange> Transient)
        CompareFindings(IReadOnlyList<Finding> before, IReadOnlyList<Finding> after)
    {
        var earlier = Index(before);
        var later = Index(after);

        var changes = new List<FindingChange>();

        foreach (var key in earlier.Keys.Union(later.Keys))
        {
            var was = earlier.GetValueOrDefault(key);
            var now = later.GetValueOrDefault(key);

            if (was is null)
            {
                changes.Add(Appeared(now!));
            }
            else if (now is null)
            {
                changes.Add(Disappeared(was));
            }
            else if (Notes(was, now) is { Count: > 0 } notes)
            {
                changes.Add(new FindingChange(
                    now.Kind, now.Source, now.Target, ChangeKind.Changed,
                    was.Severity, now.Severity, notes));
            }
        }

        var merged = MergeRetargets(changes, before, after);

        // Two kinds of expected movement, and they are not symmetric.
        //
        // Something Windows removes by itself only justifies its disappearance: a
        // RunOnce entry appearing is news, since that is how code gets run at the next
        // boot. Something whose identity churns by design justifies both ends — the
        // ephemeral socket that vanished and the one that showed up are the same fact
        // under another number, and suppressing one side only would halve the noise
        // while keeping the report wrong.
        bool Marked(FindingChange change, string key)
        {
            var identity = (change.Kind, change.Source, change.Target);
            var finding = earlier.GetValueOrDefault(identity) ?? later.GetValueOrDefault(identity);
            return finding?.Details.ContainsKey(key) == true;
        }

        var isExpected = (FindingChange change) =>
            (change.Change == ChangeKind.Disappeared && Marked(change, FindingDetails.Transient))
            || (change.Change != ChangeKind.Changed && Marked(change, FindingDetails.Ephemeral));

        return (Order([.. merged.Where(c => !isExpected(c))]),
            Order([.. merged.Where(isExpected)]));
    }

    private static Dictionary<(string, string, string), Finding> Index(
        IReadOnlyList<Finding> findings)
    {
        var index = new Dictionary<(string, string, string), Finding>();

        // A duplicate key would mean two findings designating the same thing; the first
        // wins rather than throwing — a diff must not fail on an oddity of the data.
        foreach (var finding in findings)
        {
            index.TryAdd(Key(finding), finding);
        }

        return index;
    }

    private static FindingChange Appeared(Finding finding) =>
        new(finding.Kind, finding.Source, finding.Target, ChangeKind.Appeared,
            null, finding.Severity, finding.Reasons);

    private static FindingChange Disappeared(Finding finding) =>
        new(finding.Kind, finding.Source, finding.Target, ChangeKind.Disappeared,
            finding.Severity, null, []);

    /// <summary>
    /// What moved on a finding that still designates the same thing.
    ///
    /// The fingerprint is the one that matters: same startup key, same path, a different
    /// binary behind it. Nothing else in a report says that as plainly, and a diff
    /// comparing only severities would let it through in silence.
    /// </summary>
    private static IReadOnlyList<string> Notes(Finding before, Finding after)
    {
        var notes = new List<string>();

        if (before.Severity != after.Severity)
        {
            notes.Add($"Sévérité : {before.Severity} → {after.Severity}.");
        }

        var wasHash = before.Details.GetValueOrDefault("sha256");
        var nowHash = after.Details.GetValueOrDefault("sha256");

        if (wasHash != nowHash && (wasHash ?? nowHash) is not null)
        {
            notes.Add($"Empreinte du binaire : {Short(wasHash)} → {Short(nowHash)}. "
                      + "Même emplacement, fichier différent.");
        }

        var wasPublisher = before.Details.GetValueOrDefault("éditeur");
        var nowPublisher = after.Details.GetValueOrDefault("éditeur");

        if (wasPublisher != nowPublisher)
        {
            notes.Add($"Éditeur : {wasPublisher ?? "—"} → {nowPublisher ?? "—"}.");
        }

        return notes;
    }

    private static string Short(string? hash) =>
        hash is { Length: >= 12 } ? hash[..12] : hash ?? "absent";

    /// <summary>
    /// Turns a disappearance and an appearance at the same place into one change.
    ///
    /// A startup key repointed at another binary produces two unrelated-looking lines
    /// otherwise, and the interesting fact — <em>this entry now launches something
    /// else</em> — has to be reconstructed by the reader.
    ///
    /// <para>
    /// Merged only when the source designates exactly one thing on each side. Some
    /// families share a source across every element they enumerate — every loaded driver
    /// comes from <c>Win32_SystemDriver</c> — and there, a removed driver and an added
    /// one have nothing to do with each other.
    /// </para>
    /// </summary>
    private static List<FindingChange> MergeRetargets(
        List<FindingChange> changes, IReadOnlyList<Finding> before, IReadOnlyList<Finding> after)
    {
        var uniqueBefore = SourcesDesignatingOne(before);
        var uniqueAfter = SourcesDesignatingOne(after);

        var merged = new List<FindingChange>(changes.Count);
        var consumed = new HashSet<FindingChange>();

        foreach (var change in changes)
        {
            if (consumed.Contains(change) || change.Change != ChangeKind.Disappeared
                || !uniqueBefore.Contains((change.Kind, change.Source))
                || !uniqueAfter.Contains((change.Kind, change.Source)))
            {
                continue;
            }

            var replacement = changes.FirstOrDefault(other =>
                other.Change == ChangeKind.Appeared
                && other.Kind == change.Kind
                && other.Source == change.Source);

            if (replacement is null)
            {
                continue;
            }

            consumed.Add(change);
            consumed.Add(replacement);

            merged.Add(new FindingChange(
                change.Kind, change.Source, replacement.Target, ChangeKind.Changed,
                change.Before, replacement.After,
                [
                    $"Cible : {change.Target} → {replacement.Target}. "
                    + "Le même emplacement lance autre chose.",
                    .. change.Before != replacement.After
                        ? new[] { $"Sévérité : {change.Before} → {replacement.After}." }
                        : [],
                ]));
        }

        merged.AddRange(changes.Where(c => !consumed.Contains(c)));
        return merged;
    }

    private static HashSet<(string, string)> SourcesDesignatingOne(IReadOnlyList<Finding> findings)
    {
        var counts = new Dictionary<(string, string), int>();

        foreach (var finding in findings)
        {
            var key = (finding.Kind, finding.Source);
            counts[key] = counts.GetValueOrDefault(key) + 1;
        }

        return [.. counts.Where(entry => entry.Value == 1).Select(entry => entry.Key)];
    }

    private static IReadOnlyList<FindingChange> Order(List<FindingChange> changes) =>
    [
        .. changes
            .OrderByDescending(c => c.After ?? c.Before)
            .ThenBy(c => c.Kind, StringComparer.Ordinal)
            .ThenBy(c => c.Source, StringComparer.Ordinal)
            .ThenBy(c => c.Target, StringComparer.Ordinal),
    ];

    /// <summary>
    /// Inventory differences, minus the fields that differ on every run.
    ///
    /// <see cref="FieldSemantics"/> exists for this: an uptime is not a change, and
    /// reporting it would put a line of noise at the top of every comparison.
    /// </summary>
    private static IReadOnlyList<FieldChange> CompareFields(
        IReadOnlyList<CollectorResult> before, IReadOnlyList<CollectorResult> after)
    {
        var changes = new List<FieldChange>();

        var earlier = before.ToDictionary(c => c.Name, StringComparer.Ordinal);
        var later = after.ToDictionary(c => c.Name, StringComparer.Ordinal);

        foreach (var name in earlier.Keys.Union(later.Keys, StringComparer.Ordinal)
                     .OrderBy(n => n, StringComparer.Ordinal))
        {
            var wasFields = earlier.GetValueOrDefault(name)?.Fields
                ?? new Dictionary<string, string?>();
            var nowFields = later.GetValueOrDefault(name)?.Fields
                ?? new Dictionary<string, string?>();

            foreach (var field in wasFields.Keys.Union(nowFields.Keys, StringComparer.Ordinal)
                         .Where(FieldSemantics.IsComparable)
                         .OrderBy(f => f, StringComparer.Ordinal))
            {
                var was = wasFields.GetValueOrDefault(field);
                var now = nowFields.GetValueOrDefault(field);

                if (!string.Equals(was, now, StringComparison.Ordinal))
                {
                    changes.Add(new FieldChange(name, field, was, now));
                }
            }
        }

        return changes;
    }
}
