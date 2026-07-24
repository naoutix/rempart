namespace Rempart.Core.Rules;

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>
/// How to compare the observed value to the expected one. Deliberately minimal:
/// a rule must stay readable by someone who does not write code.
/// </summary>
public enum CheckOperator
{
    /// <summary>Strict equality.</summary>
    Equals,

    /// <summary>Strict inequality.</summary>
    NotEquals,

    /// <summary>Numeric value greater than or equal — configuration floors.</summary>
    AtLeast,

    /// <summary>Numeric value less than or equal — ceilings, such as a local
    /// administrator count.</summary>
    AtMost,

    /// <summary>The value exists, whatever it is.</summary>
    Exists,

    /// <summary>The value does not exist.</summary>
    Absent,
}

public enum CheckKind
{
    /// <summary>Registry value.</summary>
    Registry,

    /// <summary>Existence of a registry key.</summary>
    RegistryKey,

    /// <summary>
    /// State or start mode of a Windows service. <c>path</c> holds the service name,
    /// <c>value</c> is "state" or "startMode".
    /// </summary>
    Service,

    /// <summary>
    /// Local policy fact — password, lockout, accounts. <c>path</c> holds the fact
    /// name, for example "password.minLength".
    /// </summary>
    Policy,

    /// <summary>
    /// WMI property. <c>path</c> holds "namespace:Class", <c>value</c> the property
    /// name. Only way to establish some states — effective encryption of a volume,
    /// current Defender state — that neither the registry nor the Win32 APIs
    /// expose.
    /// </summary>
    Wmi,
}

public sealed record CheckSpec(
    CheckKind Kind,
    string Path,
    string? ValueName,
    CheckOperator Operator,
    string? Expected,

    /// <summary>
    /// Value Windows applies when the key is absent.
    ///
    /// In the Windows registry, absence is not an anomaly: it is the common case, and
    /// the effective behavior depends on a documented default. Treating every absence
    /// as a failure produces false alerts in bulk — WDigest absent means "no cleartext
    /// passwords", NoAutoUpdate absent means "updates enabled". Both are the desired
    /// state.
    ///
    /// Required for every comparison operator: loading fails otherwise. Filling in
    /// this field forces the rule author to know the Windows default, which is
    /// precisely what makes the rule correct.
    /// </summary>
    string? WindowsDefault);

/// <summary>
/// What a remediation costs. Inert in v1: no write provider exists before M9. Filled
/// in now so the information is written while the rule is understood, not
/// reconstructed a year later.
/// </summary>
public enum Reversibility
{
    Trivial,
    Reinstallable,
    RestorePointOnly,
    Irreversible,
}

/// <summary>
/// What applying a rule costs, broken into fields rather than left as free text.
///
/// A single "impact" field quickly fills with generalities — "may have side effects" —
/// that support no decision. The three questions below are the ones actually asked
/// before applying hardening across a fleet: what stops working, who is affected,
/// how to know in advance.
///
/// The first two are required. "Nothing" is an acceptable answer — but it must be
/// written down, not inferred from an empty field.
/// </summary>
public sealed record Remediation(
    Reversibility Reversibility,

    /// <summary>What stops working after application.</summary>
    string Breaks,

    /// <summary>In which cases, and on what kind of machine.</summary>
    string Affects,

    /// <summary>How to check before applying. Optional.</summary>
    string? VerifyBefore);

/// <summary>
/// Conditions under which a rule makes sense.
///
/// Without them, a check that is only valid in a specific context produces noise
/// everywhere else — and noise discredits an audit tool more surely than a missing
/// check. Forbidding local firewall rule merging protects a machine under Group
/// Policy; on a standalone workstation, the same action removes rules created by
/// applications and brings nothing.
///
/// All specified conditions must be true.
/// </summary>
public sealed record Applicability(
    /// <summary>Requires (or excludes) a domain-joined machine.</summary>
    bool? DomainJoined = null,

    /// <summary>
    /// Registry-based condition — typically whether a feature the check depends on
    /// is enabled. NLA only makes sense if RDP is enabled.
    /// </summary>
    CheckSpec? Registry = null)
{
    public bool IsUnconditional => DomainJoined is null && Registry is null;
}

public sealed record Rule(
    string Id,
    string Title,
    Severity Severity,
    string Domain,
    string Rationale,
    IReadOnlyList<string> References,
    CheckSpec Check,
    Remediation? Remediation,
    Applicability? AppliesWhen = null);
