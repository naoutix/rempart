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
}

public sealed record Verdict(
    string RuleId,
    string Title,
    Severity Severity,
    string Domain,
    VerdictStatus Status,
    string? Observed,
    string? Expected);

/// <summary>
/// Applique une règle à l'état de la machine. Ne juge pas au-delà de la règle :
/// la sévérité, la formulation et la remédiation appartiennent au YAML.
/// </summary>
public static class RuleEvaluator
{
    public static Verdict Evaluate(Rule rule, IRegistryProvider registry)
    {
        var (status, observed) = rule.Check.Kind switch
        {
            CheckKind.Registry => EvaluateValue(rule.Check, registry),
            CheckKind.RegistryKey => EvaluateKey(rule.Check, registry),
            _ => (VerdictStatus.Unknown, null),
        };

        return new Verdict(
            rule.Id, rule.Title, rule.Severity, rule.Domain, status, observed, rule.Check.Expected);
    }

    private static (VerdictStatus, string?) EvaluateValue(CheckSpec check, IRegistryProvider registry)
    {
        var read = registry.ReadValue(check.Path, check.ValueName!);

        if (read.Status == ReadStatus.AccessDenied)
        {
            return (VerdictStatus.Unknown, null);
        }

        var found = read.Status == ReadStatus.Found ? read.Value?.ToString() : null;

        // Clé absente : le comportement effectif est celui du défaut Windows déclaré
        // par la règle. Le verdict porte donc sur ce que fait réellement la machine,
        // pas sur la présence d'une entrée de registre.
        var effective = found ?? check.WindowsDefault;

        var observed = found is not null
            ? found
            : check.WindowsDefault is { } fallback
                ? $"absent (défaut Windows : {fallback})"
                : "absent";

        return (Compare(check, found, effective), observed);
    }

    private static (VerdictStatus, string?) EvaluateKey(CheckSpec check, IRegistryProvider registry)
    {
        var status = registry.KeyExists(check.Path);

        if (status == ReadStatus.AccessDenied)
        {
            return (VerdictStatus.Unknown, null);
        }

        var present = status == ReadStatus.Found;
        var observed = present ? "present" : "absent";

        var expected = check.Operator switch
        {
            CheckOperator.Absent => !present,
            _ => present,
        };

        return (expected ? VerdictStatus.Pass : VerdictStatus.Fail, observed);
    }

    /// <param name="found">Valeur réellement présente dans le registre, ou null.</param>
    /// <param name="effective">Valeur qui régit le comportement — <paramref name="found"/>
    /// ou, à défaut, le défaut Windows déclaré par la règle.</param>
    private static VerdictStatus Compare(CheckSpec check, string? found, string? effective)
    {
        var pass = check.Operator switch
        {
            // Ces deux opérateurs portent sur la présence même de la valeur : le défaut
            // Windows n'a pas de sens ici.
            CheckOperator.Exists => found is not null,
            CheckOperator.Absent => found is null,

            CheckOperator.Equals => effective is not null && Matches(effective, check.Expected),
            CheckOperator.NotEquals => effective is not null && !Matches(effective, check.Expected),
            CheckOperator.AtLeast => AtLeast(effective, check.Expected),

            _ => false,
        };

        return pass ? VerdictStatus.Pass : VerdictStatus.Fail;
    }

    private static bool Matches(string observed, string? expected) =>
        string.Equals(observed, expected, StringComparison.OrdinalIgnoreCase);

    private static bool AtLeast(string? observed, string? expected) =>
        long.TryParse(observed, out var actual)
        && long.TryParse(expected, out var threshold)
        && actual >= threshold;
}
