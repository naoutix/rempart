using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

public enum CollectorStatus
{
    /// <summary>Complete collection.</summary>
    Ok,

    /// <summary>Partial collection due to missing privileges. Never silent (ADR-001).</summary>
    InsufficientPrivileges,

    /// <summary>The data does not exist on this machine (hardware or edition absent).</summary>
    Unavailable,

    /// <summary>The collector failed. The scan continues: one collector does not block another.</summary>
    Failed,
}

public sealed record CollectorResult(
    string Name,
    CollectorStatus Status,
    Dictionary<string, string?> Fields,
    List<string> Diagnostics);

/// <summary>
/// A collector reads machine state through <see cref="ProviderSet"/> and draws no
/// conclusion from it: evaluation belongs to the rule engine (M1).
/// </summary>
public interface ICollector
{
    string Name { get; }

    CollectorResult Collect(ProviderSet providers);
}
