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
    IReadOnlyDictionary<string, string> Details);
