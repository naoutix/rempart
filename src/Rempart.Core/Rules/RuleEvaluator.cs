using Rempart.Core.Providers;

namespace Rempart.Core.Rules;

public enum VerdictStatus
{
    /// <summary>The machine is compliant.</summary>
    Pass,

    /// <summary>The machine is not compliant.</summary>
    Fail,

    /// <summary>
    /// Could not conclude — access denied. Neither compliant nor non-compliant: an audit
    /// counting these cases as passed would lie by omission.
    /// </summary>
    Unknown,

    /// <summary>
    /// The rule does not apply to this machine. Distinct from <see cref="Unknown"/>:
    /// here the answer is known, and it is that there is nothing to check.
    /// </summary>
    NotApplicable,
}

public sealed record Verdict(
    string RuleId,
    string Title,
    Severity Severity,
    string Domain,
    VerdictStatus Status,
    string? Observed,
    string? Expected);

internal sealed class FixedSystemInfo(SystemInfo? info) : ISystemInfoProvider
{
    public SystemInfo Read() => info
        ?? new SystemInfo("inconnue", "0.0", true, false, 1, 0, "unknown");
}

/// <summary>
/// Applies a rule to the machine state. Does not judge beyond the rule: severity,
/// wording, and remediation belong to the YAML.
/// </summary>
public static class RuleEvaluator
{
    /// <summary>
    /// Evaluates a rule that only targets the registry. Service checks then come back
    /// "not verifiable" — no provider can answer them.
    /// </summary>
    public static Verdict Evaluate(Rule rule, IRegistryProvider registry, SystemInfo? system = null) =>
        Evaluate(rule, new ProviderSet(registry, new FixedSystemInfo(system)), system);

    public static Verdict Evaluate(Rule rule, ProviderSet providers, SystemInfo? system = null)
    {
        if (rule.AppliesWhen is { } condition && !Applies(condition, providers, system))
        {
            return new Verdict(
                rule.Id, rule.Title, rule.Severity, rule.Domain,
                VerdictStatus.NotApplicable, null, null);
        }

        var reading = CheckReader.Read(rule.Check, providers);

        var status = reading.Denied
            ? VerdictStatus.Unknown
            : Compare(rule.Check, reading);

        return new Verdict(
            rule.Id, rule.Title, rule.Severity, rule.Domain,
            status, reading.Describe(rule.Check), rule.Check.Expected);
    }

    /// <summary>
    /// A condition that cannot be verified — access denied, system information missing —
    /// is treated as met: better to evaluate the rule and return a verdict than to hide
    /// it over an applicability uncertainty. A silently skipped rule goes unnoticed.
    /// </summary>
    private static bool Applies(Applicability condition, ProviderSet providers, SystemInfo? system)
    {
        if (condition.DomainJoined is { } required && system is { } info
            && info.IsDomainJoined != required)
        {
            return false;
        }

        if (condition.Registry is { } check)
        {
            var reading = CheckReader.Read(check, providers);
            if (!reading.Denied && Compare(check, reading) == VerdictStatus.Fail)
            {
                return false;
            }
        }

        return true;
    }

    private static VerdictStatus Compare(CheckSpec check, CheckReading reading)
    {
        var pass = check.Operator switch
        {
            // These two operators test the very presence of the value: the Windows
            // default is meaningless here.
            CheckOperator.Exists => reading.Found is not null,
            CheckOperator.Absent => reading.Found is null,

            CheckOperator.Equals => Matches(reading.Effective, check.Expected),
            CheckOperator.NotEquals => reading.Effective is not null
                && !Matches(reading.Effective, check.Expected),
            CheckOperator.AtLeast => Compare(reading.Effective, check.Expected, (a, b) => a >= b),
            CheckOperator.AtMost => Compare(reading.Effective, check.Expected, (a, b) => a <= b),

            _ => false,
        };

        return pass ? VerdictStatus.Pass : VerdictStatus.Fail;
    }

    private static bool Matches(string? observed, string? expected) =>
        observed is not null && string.Equals(observed, expected, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A non-numeric value satisfies no ordering comparison. Return false rather than
    /// throw: the rule fails visibly instead of aborting the scan.
    /// </summary>
    private static bool Compare(string? observed, string? expected, Func<long, long, bool> compare) =>
        long.TryParse(observed, out var actual)
        && long.TryParse(expected, out var threshold)
        && compare(actual, threshold);
}
