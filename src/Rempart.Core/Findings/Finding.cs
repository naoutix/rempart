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
/// Three values because they call for three actions, and each one names <em>who</em> has
/// something to do about it: the caller's rights, the tool's code, the machine itself. That
/// is the same ordering the exit-code precedence follows, and the reason they cannot be one
/// flag: telling someone to re-run elevated when the tool threw — or when the WMI repository
/// is the thing that stopped answering — sends them to do the one thing that cannot help.
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

    /// <summary>
    /// The surface was asked, and what came back was a failure.
    ///
    /// <para>
    /// Not <see cref="Refused"/>: nothing was denied, so no amount of rights changes this
    /// answer — a WMI repository that no longer serves, a service control manager that will
    /// not open, a capture replayed for a surface it never recorded. Re-running elevated is
    /// precisely the advice that wastes the reader's time here, and it is the advice the two
    /// values before this one left as the only thing the report could say.
    /// </para>
    ///
    /// <para>
    /// Not <see cref="Broken"/> either: no code of ours threw, and there is no bug to file
    /// against the tool. The distinction is where the defect sits, and it decides what the
    /// reader does next — repair the machine surface, or re-capture. That is why this one
    /// lands on <c>Partial</c> rather than on the failure rung: the scan ran to the end and
    /// the caller has no lever on the number it got.
    /// </para>
    ///
    /// <para>
    /// Which of the two a read is comes from the read itself and is never a collector's
    /// judgement: every status-carrying read in <c>Providers</c> writes a diagnostic for a
    /// failure and leaves it null for a genuine refusal. <see cref="Finding.Unread"/> is
    /// where that one rule is applied, so a collector cannot get the classification wrong by
    /// copying its neighbour — which is how all twelve of them came to say « accès refusé »
    /// over failures in the first place.
    /// </para>
    /// </summary>
    Unreadable,
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
    /// A surface that answered with a failure. Same shape and same severity as
    /// <see cref="Refused"/> — nothing was observed, so nothing is being accused — and a
    /// different <see cref="AuditGap"/>, which is the whole of the difference: this one does
    /// not repair itself by re-running elevated.
    ///
    /// <para>
    /// For the two callers whose branch is only entered when a diagnostic exists. Every other
    /// site has both cases to answer for and goes through <see cref="Unread"/> instead, which
    /// picks between the two rather than leaving the choice to the collector.
    /// </para>
    /// </summary>
    public static Finding Unreadable(
        string kind, string source, IReadOnlyList<string> reasons,
        IReadOnlyDictionary<string, string>? details = null) =>
        new(kind, source, NoTarget, FindingSeverity.Notable, reasons,
            details ?? new Dictionary<string, string>(), AuditGap.Unreadable);

    /// <summary>
    /// A surface that did not answer, classified rather than assumed.
    ///
    /// <para>
    /// The one door for « je n'ai pas pu regarder », and the reason it exists is that the
    /// twelve collectors that say it were each deciding for themselves — all of them the same
    /// way, all of them wrong for half their inputs. They wrote
    /// <c>Finding.Refused(…, [read.Diagnostic ?? "…relancer en administrateur…"])</c>: the
    /// very expression that proves a failure was in hand chose the value that says a
    /// permission was missing. Here the decision is made from that same expression, once.
    /// </para>
    ///
    /// <para>
    /// <paramref name="diagnostic"/> is the rule, and it is the rule the providers already
    /// hold: <c>WmiRead</c>, <c>ServiceRead</c>, <c>FirewallState</c> and the five
    /// status-carrying reads all document it identically — null for a genuine refusal,
    /// written for a failure, because <c>ReadStatus</c> has no member for the second.
    /// Nothing here re-derives that; it is read where it was decided.
    /// </para>
    /// </summary>
    /// <param name="refusal">
    /// What to say when there is no diagnostic — the bare refusal, which may legitimately
    /// advise elevation because that case is the one elevation answers.
    /// </param>
    /// <param name="alongside">
    /// Further reasons kept beside the first, for the reads that name the individual holes as
    /// well as the whole — the scheduler lists the folders it was refused.
    /// </param>
    public static Finding Unread(
        string kind, string source, string? diagnostic, string refusal,
        IReadOnlyList<string>? alongside = null,
        IReadOnlyDictionary<string, string>? details = null) =>
        diagnostic is null
            ? Refused(kind, source, [refusal, .. alongside ?? []], details)
            : Unreadable(kind, source, [diagnostic, .. alongside ?? []], details);

    /// <summary>
    /// A collector that threw. Distinct from <see cref="Refused"/> down to the exit code:
    /// the scan continues either way — a partial report that discloses its gaps beats no
    /// report — but one of the two is a bug and the other is a permission.
    /// </summary>
    public static Finding Broken(string kind, string source, string reason) =>
        new(kind, source, NoTarget, FindingSeverity.Notable, [reason],
            new Dictionary<string, string>(), AuditGap.Broken);
}
