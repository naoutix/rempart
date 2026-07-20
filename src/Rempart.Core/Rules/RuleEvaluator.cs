using Rempart.Core.Providers;

namespace Rempart.Core.Rules;

public enum VerdictStatus
{
    /// <summary>La machine est conforme.</summary>
    Pass,

    /// <summary>La machine n'est pas conforme.</summary>
    Fail,

    /// <summary>
    /// Impossible de conclure — accès refusé. Ni conforme ni non conforme : un audit
    /// qui compterait ces cas comme réussis mentirait par omission.
    /// </summary>
    Unknown,

    /// <summary>
    /// La règle ne concerne pas cette machine. Distinct de <see cref="Unknown"/> :
    /// ici on sait, et la réponse est qu'il n'y a rien à vérifier.
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
/// Applique une règle à l'état de la machine. Ne juge pas au-delà de la règle :
/// la sévérité, la formulation et la remédiation appartiennent au YAML.
/// </summary>
public static class RuleEvaluator
{
    /// <summary>
    /// Évalue une règle qui ne porte que sur le registre. Les contrôles de service
    /// rendent alors « non vérifiable » — aucun provider ne peut y répondre.
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
    /// Une condition non vérifiable — accès refusé, information système absente — est
    /// tenue pour remplie : mieux vaut évaluer la règle et rendre un verdict que la
    /// masquer sur une incertitude d'applicabilité. Une règle escamotée ne se remarque pas.
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
            // Ces deux opérateurs portent sur la présence même de la valeur : le défaut
            // Windows n'a pas de sens ici.
            CheckOperator.Exists => reading.Found is not null,
            CheckOperator.Absent => reading.Found is null,

            CheckOperator.Equals => Matches(reading.Effective, check.Expected),
            CheckOperator.NotEquals => reading.Effective is not null
                && !Matches(reading.Effective, check.Expected),
            CheckOperator.AtLeast => AtLeast(reading.Effective, check.Expected),

            _ => false,
        };

        return pass ? VerdictStatus.Pass : VerdictStatus.Fail;
    }

    private static bool Matches(string? observed, string? expected) =>
        observed is not null && string.Equals(observed, expected, StringComparison.OrdinalIgnoreCase);

    private static bool AtLeast(string? observed, string? expected) =>
        long.TryParse(observed, out var actual)
        && long.TryParse(expected, out var threshold)
        && actual >= threshold;
}
