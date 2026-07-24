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
    bool Denied = false)
{
    public static readonly PolicyFacts AccessDenied =
        new(new Dictionary<string, string>(), Denied: true);

    public string? Find(string name) =>
        Values.TryGetValue(name, out var value) ? value : null;
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
}
