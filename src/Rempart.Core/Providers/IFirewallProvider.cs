namespace Rempart.Core.Providers;

/// <summary>
/// A Windows firewall rule, reduced to what decides a port's reachability.
///
/// <para>
/// Rules are stored as pipe-separated <c>Key=Value</c> strings. Only the fields that
/// bear on the question are kept: does this rule let a connection in to this port, on
/// this profile? The display name, description, and integration context do not affect
/// that.
/// </para>
/// </summary>
public sealed record FirewallRule(
    bool Active,

    /// <summary>"In" or "Out". Only inbound exposes.</summary>
    string Direction,

    /// <summary>"Allow" or "Block". A block wins over an allow.</summary>
    string Action,

    /// <summary>IANA protocol number — 6 for TCP, 17 for UDP. Null = any protocol.</summary>
    int? Protocol,

    /// <summary>Raw local port specification — "445", "80,443", "1000-2000", or a
    /// keyword ("RPC"). Null = any port.</summary>
    string? LocalPorts,

    /// <summary>Profiles where the rule applies. Empty = all profiles.</summary>
    IReadOnlyList<string> Profiles,

    /// <summary>Path of the targeted application, environment variables included.
    /// Null = any application.</summary>
    string? App)
{
    /// <summary>
    /// Parses a rule string from the registry. Returns null when the string is not a
    /// usable rule — version header only, or missing direction field.
    /// </summary>
    public static FirewallRule? Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // The Profile field repeats — "Profile=Domain|Profile=Private|Profile=Public" —
        // instead of combining into a single value. A dictionary would keep only the last
        // one and lose the others, so profiles are accumulated separately.
        var profiles = new List<string>();

        foreach (var part in raw.Split('|'))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            var key = part[..eq];
            var value = part[(eq + 1)..];

            if (key.Equals("Profile", StringComparison.OrdinalIgnoreCase))
            {
                profiles.AddRange(value.Split(
                    ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
            else
            {
                fields[key] = value;
            }
        }

        if (!fields.TryGetValue("Dir", out var direction))
        {
            return null;
        }

        return new FirewallRule(
            Active: fields.TryGetValue("Active", out var active)
                && active.Equals("TRUE", StringComparison.OrdinalIgnoreCase),
            Direction: direction,
            Action: fields.TryGetValue("Action", out var action) ? action : "Allow",
            Protocol: fields.TryGetValue("Protocol", out var proto)
                && int.TryParse(proto, out var protoNum) ? protoNum : null,
            LocalPorts: fields.TryGetValue("LPort", out var lport) ? lport : null,
            Profiles: profiles,
            App: fields.TryGetValue("App", out var app) ? app : null);
    }
}
