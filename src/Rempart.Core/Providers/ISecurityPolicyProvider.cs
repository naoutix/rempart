namespace Rempart.Core.Providers;

/// <summary>
/// Security facts that cannot be read from the registry or the service control manager:
/// password policy, account lockout, local accounts.
///
/// Exposed as a dictionary of named values rather than a typed model. A rule compares a
/// value against an expectation; giving it a list of accounts to iterate would require
/// an expression language in the YAML, which amounts to writing code in a data file.
/// Aggregates — local admin count, guest account enabled — answer the questions an
/// audit actually asks.
/// </summary>
public interface ISecurityPolicyProvider
{
    /// <summary>
    /// Available facts, indexed by name. A missing key means the fact could not be
    /// established: the corresponding rule returns "not verifiable", never a failure —
    /// the tool could not observe the fact, so it makes no judgment.
    /// </summary>
    PolicyFacts Read();
}

public sealed record PolicyFacts(
    IReadOnlyDictionary<string, string> Values,

    /// <summary>
    /// The whole read was refused — nothing established, and the operating system said so.
    ///
    /// <para>
    /// It used to be deduced from a count: an empty dictionary was reported as a denial
    /// whatever the API had answered, so an unreachable <c>netapi32</c> came back as missing
    /// privileges. It is now claimed only where a refusal was actually returned, and
    /// <see cref="Gaps"/> carries every other reason (#160).
    /// </para>
    ///
    /// <para>
    /// Its one reader is <c>CheckReader.ReadPolicy</c>, and it does not today decide anything
    /// there on its own: a denial requires that nothing was established, so <see cref="Find"/>
    /// already answers null for every fact and the same branch is taken either way. Said
    /// plainly rather than left to be discovered — what the flag observably changes is the
    /// <c>denied</c> written into the capture, and the day a rendering distinguishes a refusal
    /// from a failure (#159) it is the field that will carry the distinction.
    /// </para>
    /// </summary>
    bool Denied = false,

    /// <summary>
    /// Why each fact that is missing is missing, keyed by fact name — or null when the read
    /// recorded nothing about it.
    ///
    /// <para>
    /// Facts come from several independent reads filling one dictionary, so a partial answer
    /// is the ordinary shape rather than the exceptional one, and it had no way of being
    /// expressed: one read succeeding was enough for the dictionary to look like an answer,
    /// and the refusals beside it vanished. Same remedy as
    /// <see cref="ScheduledTaskRead.Gaps"/> and <see cref="WmiRead.Partial"/> — what was read
    /// stays, and the gap is named beside it.
    /// </para>
    ///
    /// <para>
    /// Keyed by fact name rather than written as one sentence, because that is what the
    /// consumer asks with: a rule reads one fact, and what it needs is the reason
    /// <em>that</em> one is absent, not the reason some other one is. Added beside the values
    /// and never in their place, so a capture written before this field replays as it did:
    /// its absence means nothing was recorded, which is exactly what such a capture claimed —
    /// and, until this field existed, all it could claim.
    /// </para>
    /// </summary>
    IReadOnlyDictionary<string, string>? Gaps = null)
{
    public static readonly PolicyFacts AccessDenied =
        new(new Dictionary<string, string>(), Denied: true);

    /// <summary>
    /// A read that never happened: nothing established, no refusal claimed, and the same
    /// reason beside every fact a rule can name.
    ///
    /// <para>
    /// The shape the neighbours in <c>ISystemInfoProvider</c> already have —
    /// <c>DriverRead.Failed</c>, <c>ScheduledTaskRead.Failed</c>,
    /// <c>DirectoryRead.Failed</c> — and the one this interface could not have until
    /// <see cref="Gaps"/> existed. A scan wired without a policy provider, and a capture with
    /// no policy block in it, were both answering <see cref="AccessDenied"/>: the six shipped
    /// <c>type: policy</c> controls under « accès refusé » and « relancer en administrateur »,
    /// against an absence no elevation fills.
    /// </para>
    ///
    /// <para>
    /// Every name and not one sentence, because a gap is looked up by the fact a rule asks
    /// for: keyed by anything less, the reason would be recorded and never read. A rule
    /// naming a fact outside <see cref="PolicyFactNames"/> still gets null, which is what it
    /// has always got.
    /// </para>
    /// </summary>
    public static PolicyFacts Unread(string reason) =>
        new(new Dictionary<string, string>(StringComparer.Ordinal),
            Gaps: PolicyFactNames.All.ToDictionary(
                name => name, _ => reason, StringComparer.Ordinal));

    public string? Find(string name) =>
        Values.TryGetValue(name, out var value) ? value : null;

    /// <summary>
    /// What the read says about a fact it did not establish, or null when it says nothing —
    /// which is both the pre-#160 capture and the fact that was simply never asked for.
    /// </summary>
    public string? WhyMissing(string name) =>
        Gaps is not null && Gaps.TryGetValue(name, out var reason) ? reason : null;
}

/// <summary>Fact names, to avoid free-form strings in code.</summary>
public static class PolicyFactNames
{
    public const string PasswordMinLength = "password.minLength";
    public const string PasswordMaxAgeDays = "password.maxAgeDays";
    public const string PasswordHistoryLength = "password.historyLength";
    public const string LockoutThreshold = "lockout.threshold";
    public const string LockoutDurationMinutes = "lockout.durationMinutes";
    public const string LocalAdminCount = "accounts.localAdminCount";
    public const string GuestEnabled = "accounts.guestEnabled";
    public const string AccountsWithoutPassword = "accounts.withoutPassword";
    public const string AccountsPasswordNeverExpires = "accounts.passwordNeverExpires";

    /// <summary>
    /// All of them, for the reads that establish none and have one reason for every one.
    ///
    /// <para>
    /// Written out and not reflected: reading fields at run time is the reflection Native AOT
    /// does not have (ADR-001). A hand-kept list is a list that drifts, so a test holds it
    /// against the constants above in both directions.
    /// </para>
    /// </summary>
    public static readonly IReadOnlyList<string> All =
    [
        PasswordMinLength,
        PasswordMaxAgeDays,
        PasswordHistoryLength,
        LockoutThreshold,
        LockoutDurationMinutes,
        LocalAdminCount,
        GuestEnabled,
        AccountsWithoutPassword,
        AccountsPasswordNeverExpires,
    ];
}
