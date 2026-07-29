using System.Text.Json.Serialization;

namespace Rempart.Core.Findings;

/// <summary>
/// Severity of a finding. Distinct from rule severity: a rule severity qualifies a
/// configuration deviation, a finding severity qualifies what was found installed.
/// </summary>
public enum FindingSeverity
{
    /// <summary>Nothing abnormal. Enumerated for inventory, not to alert.</summary>
    Benign,

    /// <summary>Worth a look: unusual without being suspicious.</summary>
    Notable,

    /// <summary>Matches a known technique, or contradicts a strong expectation.</summary>
    Suspicious,
}

/// <summary>
/// A hole in what the scan saw, carried by the finding that reports it.
///
/// <para>
/// A finding collector has no <see cref="Collectors.CollectorResult"/> to put a status in:
/// its whole answer is a list of findings. Twelve places had therefore invented the same
/// workaround — a <c>Notable</c> finding with an em dash where the target goes — and the
/// convention held only for as long as the next collector kept copying its neighbour. Named
/// here, it is read by <c>ExitCodes</c>, which is the point: a surface nobody could look at
/// has to reach the one number a scheduler judges the run on.
/// </para>
///
/// <para>
/// Two values because they call for two actions. That is the same ordering the exit-code
/// precedence follows, and the reason both cannot be one flag: telling someone to re-run
/// elevated when the tool itself threw sends them to do the one thing that cannot help.
/// </para>
/// </summary>
public enum AuditGap
{
    /// <summary>
    /// A surface the machine refused. The answer is to re-run elevated — the report has a
    /// hole, nothing is broken and nothing is being accused.
    /// </summary>
    Refused,

    /// <summary>
    /// The collector itself broke. Re-running elevated will not help; this one is a bug,
    /// and the scan carries on so that the rest of the report still exists.
    /// </summary>
    Broken,
}

/// <summary>
/// What was found on the machine, as opposed to what was judged about its
/// configuration.
///
/// A rule compares a value to an expectation and returns a verdict. Persistence does
/// not fit that model: seventeen startup programs, three of them unsigned, cannot be
/// reduced to "3, expected 0" — what matters is which ones. A finding therefore
/// carries its own judgement, and the report enumerates findings.
///
/// The two do not mix in the score: a configuration at 94% must not hide an unsigned
/// binary launched at startup.
/// </summary>
public sealed record Finding(
    /// <summary>Finding family — "autorun", "driver", "wmi-subscription".</summary>
    string Kind,

    /// <summary>Where it comes from: registry key, folder, task name.</summary>
    string Source,

    /// <summary>What executes.</summary>
    string Target,

    FindingSeverity Severity,

    /// <summary>Why this finding is reported. Empty if benign.</summary>
    IReadOnlyList<string> Reasons,

    /// <summary>Observed details — publisher, hash, signature state.</summary>
    IReadOnlyDictionary<string, string> Details,

    /// <summary>
    /// Set when this finding reports a hole in the audit rather than something found on the
    /// machine. Null — the ordinary case — means the finding is a claim about the machine.
    ///
    /// <para>
    /// Omitted from the JSON when null, which is the one exception to the report writing
    /// every field: a line saying « rien à signaler » on each of two hundred findings buries
    /// the dozen that have something to say, and its absence already has to mean exactly
    /// that, since every report written before this field carries none and means no gap.
    /// Reports are re-read — <c>rempart report</c> and <c>rempart diff</c> both start from
    /// one — so that reading is a contract, not a convenience.
    /// </para>
    /// </summary>
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    AuditGap? Gap = null)
{
    /// <summary>
    /// What <see cref="Target"/> holds when nothing executes — a gap names a surface, not a
    /// program. Written out twelve times before, which is eleven chances to write something
    /// else and have the report look, to a reader, like a finding whose target was omitted.
    /// </summary>
    public const string NoTarget = "—";

    /// <summary>
    /// A surface the scan was refused. <see cref="FindingSeverity.Notable"/> and not
    /// suspicious: nothing was observed, so nothing is being accused — what is being said is
    /// that the report has a hole where one of its surfaces should be.
    ///
    /// <para>
    /// The single door in, so that the marker is not something a collector has to remember:
    /// a refusal that spells itself out by hand is invisible to the exit code again, and the
    /// guard in <c>ExitCodeTests</c> that walks the shipped collectors against a machine
    /// refusing everything is what makes that visible rather than discovered later.
    /// </para>
    /// </summary>
    public static Finding Refused(
        string kind, string source, IReadOnlyList<string> reasons,
        IReadOnlyDictionary<string, string>? details = null) =>
        new(kind, source, NoTarget, FindingSeverity.Notable, reasons,
            details ?? new Dictionary<string, string>(), AuditGap.Refused);

    /// <summary>
    /// A collector that threw. Distinct from <see cref="Refused"/> down to the exit code:
    /// the scan continues either way — a partial report that discloses its gaps beats no
    /// report — but one of the two is a bug and the other is a permission.
    /// </summary>
    public static Finding Broken(string kind, string source, string reason) =>
        new(kind, source, NoTarget, FindingSeverity.Notable, [reason],
            new Dictionary<string, string>(), AuditGap.Broken);
}
