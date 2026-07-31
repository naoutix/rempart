using System.Text.Json.Serialization;
using Rempart.Core.Providers;

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
    /// answer — a WMI repository that no longer serves, a listening table that answered with
    /// an error on a call needing no privilege, a browser profile whose preferences will not
    /// parse, a capture replayed for a surface it never recorded. Re-running elevated is
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
    /// Which of the two a gap is, the collector says, and it says so because it is the only
    /// thing that knows. There used to be no rule spanning the providers to read it off: a
    /// single <see cref="Providers.ReadStatus.AccessDenied"/> spelled a refusal on one channel
    /// and a failure on the next, and the diagnostic beside it was no better a witness —
    /// <c>WmiRead.Failed</c> carried a reason and was not a denial, <c>WmiRead.AccessDenied</c>
    /// is a genuine refusal and carries none. Deriving the answer from either one is how a
    /// startup folder denied to a non-elevated scan came back as « no amount of rights changes
    /// this », which is the opposite of true and the reason this paragraph replaced the rule
    /// that used to be asserted here.
    /// </para>
    ///
    /// <para>
    /// <b>The first half of that has stopped being true and the second has not.</b> #173 split
    /// <c>DirectoryRead</c> and <c>HostsFileRead</c>; #177 finished the layer, and
    /// <c>ReadFactoryNamingTests</c> now holds by construction that
    /// <see cref="Providers.ReadStatus.AccessDenied"/> is reachable only through a factory
    /// whose name says « refused ». So the status <em>is</em> a witness across the providers,
    /// and every collector here branches on it rather than on prose. The diagnostic still is
    /// not one, and never was: <c>ScheduledTaskRead.PartiallyRefused</c> writes a sentence for
    /// a denial, <c>DirectoryRead.Refused</c> writes one for an ACL, and
    /// <c>WmiRead.AccessDenied</c> refuses in silence.
    /// </para>
    ///
    /// <para>
    /// What that does not settle is which gap a status <em>deserves</em>, which is why the
    /// judgement stays at the call site. A surface can answer <see cref="Providers.ReadStatus.Found"/>
    /// and still be a hole, a collector that threw is neither of the two, and only the caller
    /// knows whether zero is an answer on its own surface. So the judgement is made once per
    /// surface, in the open, and what is enforced centrally is that it is <em>made</em>:
    /// <see cref="Finding.Unread"/> takes the value as a required argument and every other door
    /// names one in its own name, so no site can reach an <see cref="AuditGap"/> without having
    /// chosen it.
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
    /// For the callers whose branch is only entered when a diagnostic exists. Every other site
    /// has a fallback sentence to supply as well and goes through <see cref="Unread"/>, which
    /// takes the same decision as an argument.
    /// </para>
    /// </summary>
    public static Finding Unreadable(
        string kind, string source, IReadOnlyList<string> reasons,
        IReadOnlyDictionary<string, string>? details = null) =>
        new(kind, source, NoTarget, FindingSeverity.Notable, reasons,
            details ?? new Dictionary<string, string>(), AuditGap.Unreadable);

    /// <summary>
    /// A surface that did not answer, saying which kind of not-answering it was.
    ///
    /// <para>
    /// The shared door for « je n'ai pas pu regarder ». What it shares is the shape — the
    /// severity, the missing target, the reason picked between the read's own words and a
    /// fallback — and deliberately <em>not</em> the classification. This door used to decide
    /// that too, from <paramref name="diagnostic"/>, on the belief that every provider writes
    /// one for a failure and leaves it null for a refusal. No provider promises that. Half of
    /// them document the opposite: <c>DirectoryRead.Refused</c> and
    /// <c>HostsFileRead.Refused</c> are written by an ACL denial and always carry a reason,
    /// <c>FirewallState.Diagnostic</c> is « the read was attempted and refused », and
    /// <c>ScheduledTaskRead.PartiallyRefused</c> carries a reason for the <c>E_ACCESSDENIED</c>
    /// its own interface calls « the one HRESULT that means elevate and retry ». Under that
    /// rule a startup folder denied to a non-elevated scan — the commonest gap there is — came
    /// back telling its reader that no amount of rights would change the answer.
    /// </para>
    ///
    /// <para>
    /// So <paramref name="gap"/> is required, and required positionally: a thirteenth site
    /// written tomorrow does not compile until someone has read what its provider documents
    /// and answered. That is the guard, and it is the compiler rather than a test walking the
    /// call sites on disk, because a build error cannot be skipped, cannot drift out of date
    /// with the code it watches, and arrives before the wrong answer is ever written down.
    /// What a required argument cannot check is whether the answer is <em>right</em>; the two
    /// guards in <c>ExitCodeTests</c> that run the shipped collectors against a machine
    /// refusing everything, then against one failing everything, are what check that.
    /// </para>
    /// </summary>
    /// <param name="gap">
    /// Refusal or failure, as the interrogated provider defines it — never as this method
    /// guesses it. The site is where the provider is known, so the site is where it is said.
    /// </param>
    /// <param name="diagnostic">
    /// The read's own account of what happened, printed verbatim when there is one. It decides
    /// the <em>wording</em> and nothing else: a channel can name a denial in prose and a
    /// channel can refuse in silence, so this says what to print, not what it was.
    /// </param>
    /// <param name="unexplained">
    /// What to say when the read named nothing. Whether it may advise elevation is
    /// <paramref name="gap"/>'s business, not this parameter's: a sentence promising a remedy
    /// under <see cref="AuditGap.Unreadable"/> contradicts the value beside it.
    /// </param>
    /// <param name="alongside">
    /// Further reasons kept beside the first, for the reads that name the individual holes as
    /// well as the whole — the scheduler lists the folders it was refused.
    /// </param>
    public static Finding Unread(
        string kind, string source, AuditGap gap, string? diagnostic, string unexplained,
        IReadOnlyList<string>? alongside = null,
        IReadOnlyDictionary<string, string>? details = null) =>
        new(kind, source, NoTarget, FindingSeverity.Notable,
            [diagnostic ?? unexplained, .. alongside ?? []],
            details ?? new Dictionary<string, string>(), gap);

    /// <summary>
    /// What a failed WMI-backed read means, for the one channel that really does document the
    /// rule the shared door used to apply to all of them.
    ///
    /// <para>
    /// <c>WmiRead</c> states it and <c>LiveWmiProvider.Classify</c> implements it: the three
    /// HRESULTs that mean a denial — <c>WBEM_E_ACCESS_DENIED</c>, <c>E_ACCESSDENIED</c>,
    /// <c>WBEM_E_PRIVILEGE_NOT_HELD</c> — return <c>WmiRead.AccessDenied</c>, which carries no
    /// reason; every other code returns <c>Failed</c> or <c>Partial</c>, which carries the
    /// code itself. So on this channel, and only on it, an absent diagnostic <em>is</em> the
    /// refusal, and a present one is a repository that stopped serving or a provider that
    /// faulted — the case #159 was opened over.
    /// </para>
    ///
    /// <para>
    /// Named rather than written out at each of the four WMI-backed sites so that the claim is
    /// stated once and cited, instead of being four look-alike ternaries that the next surface
    /// copies without checking whether its own provider earns it. That copying is how this
    /// rule reached the surfaces that do not.
    /// </para>
    ///
    /// <para>
    /// <paramref name="status"/> is read as well as the reason, because silence alone is not
    /// the denial: <c>Classify</c> answers a bare <c>WmiRead.NotFound</c> — no reason either —
    /// for the three codes that mean « no such namespace, no such class », which is what a
    /// Windows edition without the feature returns. Two of the four sites filter that out
    /// before they get here and two do not, so the rule that read the reason on its own sent
    /// the reader to elevate over a class the machine does not have. Only
    /// <see cref="Providers.ReadStatus.AccessDenied"/> can be a refusal at all.
    /// </para>
    ///
    /// <para>
    /// <b>Since #177 the status alone would answer, and the reason is kept anyway.</b> Every
    /// factory in the provider layer that builds a failure now says <c>Failed</c>, so a live
    /// read reaching here with <see cref="Providers.ReadStatus.AccessDenied"/> was denied
    /// whatever it wrote. A <em>replayed</em> one need not have been: a capture taken before
    /// that split recorded <c>AccessDenied</c> with a reason beside it for a repository that
    /// had merely stopped serving, and reading the reason is what keeps that snapshot
    /// answering what it answered when it was written. Which is also the warning the paragraph
    /// above already carried: a channel that denies <em>and</em> explains itself —
    /// <c>ScheduledTaskRead.PartiallyRefused</c>, <c>DirectoryRead.Refused</c> — must not be
    /// classified through here.
    /// </para>
    /// </summary>
    public static AuditGap WmiGap(ReadStatus status, string? diagnostic) =>
        status is ReadStatus.AccessDenied && diagnostic is null
            ? AuditGap.Refused
            : AuditGap.Unreadable;

    /// <summary>
    /// A collector that threw. Distinct from <see cref="Refused"/> down to the exit code:
    /// the scan continues either way — a partial report that discloses its gaps beats no
    /// report — but one of the two is a bug and the other is a permission.
    /// </summary>
    public static Finding Broken(string kind, string source, string reason) =>
        new(kind, source, NoTarget, FindingSeverity.Notable, [reason],
            new Dictionary<string, string>(), AuditGap.Broken);
}
