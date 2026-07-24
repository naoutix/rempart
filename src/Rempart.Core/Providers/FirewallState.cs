namespace Rempart.Core.Providers;

/// <summary>
/// Reachability verdict for an inbound port through the firewall.
/// </summary>
public enum FirewallReachability
{
    /// <summary>The firewall could not be read: no verdict is made in its place.</summary>
    Unknown,

    /// <summary>An active rule allows inbound traffic, or the firewall is off.</summary>
    Reachable,

    /// <summary>No rule allows inbound traffic, or a block rule wins.</summary>
    Blocked,
}

/// <summary>
/// The firewall state that decides whether a listening port is actually reachable.
///
/// <para>
/// The question of milestone M4: an open port that the firewall blocks is not exposed
/// the way a port the firewall lets in is. The <b>Public</b> profile is the one that
/// matters — the untrusted-network case, which the machine is in as soon as it joins an
/// open Wi-Fi. A port allowed on Public is exposed in every scenario.
/// </para>
///
/// <para>
/// The Windows inbound default is block: without a matching allow rule, a port is not
/// reachable. This is what makes the signal usable — most listening system ports carry
/// no rule and fall back to "blocked".
/// </para>
/// </summary>
public sealed record FirewallState(
    IReadOnlyList<FirewallRule> Rules,
    bool PublicFirewallEnabled,
    bool PublicDefaultInboundAllow)
{
    /// <summary>Empty state: the firewall was not read. Every query returns "unknown".</summary>
    public static readonly FirewallState Unread = new([], PublicFirewallEnabled: false, false)
    {
        Readable = false,
    };

    /// <summary>False when the state comes from <see cref="Unread"/>: no conclusions.</summary>
    public bool Readable { get; init; } = true;

    /// <summary>
    /// Is a listening port reachable inbound on the Public profile?
    ///
    /// <para>
    /// A disabled firewall lets everything through. Otherwise, among the rules that
    /// actually apply to this port — matching direction, profile, protocol, port, and
    /// application — a block rule wins over an allow rule, and the absence of any rule
    /// falls back to the inbound default, block.
    /// </para>
    /// </summary>
    public FirewallReachability InboundReachability(string protocol, int port, string? appPath)
    {
        if (!Readable)
        {
            return FirewallReachability.Unknown;
        }

        if (!PublicFirewallEnabled)
        {
            return FirewallReachability.Reachable;
        }

        var protocolNumber = protocol switch
        {
            "TCP" => 6,
            "UDP" => 17,
            _ => -1,
        };

        var applicable = Rules.Where(rule => Applies(rule, protocolNumber, port, appPath)).ToList();

        if (applicable.Any(rule => rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase)))
        {
            return FirewallReachability.Blocked;
        }

        if (applicable.Any(rule => rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)))
        {
            return FirewallReachability.Reachable;
        }

        return PublicDefaultInboundAllow
            ? FirewallReachability.Reachable
            : FirewallReachability.Blocked;
    }

    private static bool Applies(FirewallRule rule, int protocolNumber, int port, string? appPath)
    {
        if (!rule.Active || !rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Empty profile list = all profiles, including Public.
        if (rule.Profiles.Count > 0
            && !rule.Profiles.Contains("Public", StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        // Null protocol = any protocol.
        if (rule.Protocol is { } ruleProtocol && ruleProtocol != protocolNumber)
        {
            return false;
        }

        // Rule without ports: it applies to any port, but only when tied to a specific
        // application. A rule with neither port nor application is in practice a
        // packaged-app rule — carried by a package identifier that cannot be mapped to a
        // path — and counting it would wrongly open every port. It is therefore only kept
        // when its application matches the known owner of the port.
        if (rule.LocalPorts is null)
        {
            return rule.App is not null && AppMatches(rule.App, appPath);
        }

        if (!PortMatches(rule.LocalPorts, port))
        {
            return false;
        }

        return AppMatches(rule.App, appPath);
    }

    /// <summary>
    /// Does the port fall within the rule's port specification? A null specification
    /// means "any port". Keywords — "RPC", "RPC-EPMap" — designate dynamic ports that
    /// cannot be resolved here: they are not treated as matches, to avoid inventing an
    /// allowance. The actual port is then judged on the other rules, or failing that on
    /// the default block.
    /// </summary>
    private static bool PortMatches(string? spec, int port)
    {
        if (spec is null)
        {
            return true;
        }

        foreach (var token in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = token.IndexOf('-');
            if (dash > 0)
            {
                if (int.TryParse(token[..dash], out var low)
                    && int.TryParse(token[(dash + 1)..], out var high)
                    && port >= low && port <= high)
                {
                    return true;
                }
            }
            else if (int.TryParse(token, out var single) && single == port)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Does the rule target the application that owns the port? A rule without an
    /// application field means "any application". A rule that carries one applies only
    /// to that application: if the owner is unknown — a system port out of reach
    /// without elevation — the match cannot be confirmed, and is not assumed.
    /// </summary>
    private static bool AppMatches(string? ruleApp, string? appPath)
    {
        if (ruleApp is null)
        {
            return true;
        }

        if (appPath is null)
        {
            return false;
        }

        return string.Equals(Expand(ruleApp), appPath, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Expands environment variables in a rule path to fixed values. Done by hand,
    /// without reading the machine's environment: replaying a capture must yield the
    /// same verdict everywhere, not depend on the host that reads it back.
    /// </summary>
    private static string Expand(string path)
    {
        ReadOnlySpan<(string Var, string Value)> table =
        [
            ("%SystemRoot%", @"C:\Windows"),
            ("%windir%", @"C:\Windows"),
            ("%SystemDrive%", "C:"),
            ("%ProgramFiles%", @"C:\Program Files"),
            ("%ProgramFiles(x86)%", @"C:\Program Files (x86)"),
        ];

        foreach (var (name, value) in table)
        {
            if (path.StartsWith(name, StringComparison.OrdinalIgnoreCase))
            {
                return value + path[name.Length..];
            }
        }

        return path;
    }
}

/// <summary>
/// Reads the firewall state. Abstracted like the rest (ADR-001, D5): the cross-check
/// rule — a port both exposed and allowed inbound on Public — is tested against a given
/// state, without touching the machine's firewall.
/// </summary>
public interface IFirewallProvider
{
    FirewallState Read();
}
