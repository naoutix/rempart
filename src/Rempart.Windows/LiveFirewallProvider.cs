using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads the Windows Firewall state from the registry.
///
/// <para>
/// Rules live under <c>SharedAccess</c> for local rules and under <c>Policies</c> for
/// those set by Group Policy — both count, since a GPO adds rules without replacing the
/// local ones. Each value is a <c>Key=Value</c> string the core knows how to parse.
/// Reading the registry instead of the firewall COM interface has a cost — dynamic port
/// keywords stay opaque — but keeps the read replayable offline and free of COM
/// dependencies under AOT.
/// </para>
/// </summary>
public sealed class LiveFirewallProvider : IFirewallProvider
{
    private const string LocalRules =
        @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    private const string PolicyRules =
        @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";

    private const string LocalPublicProfile =
        @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";

    private const string PolicyPublicProfile =
        @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile";

    private readonly IRegistryProvider registry;

    public LiveFirewallProvider()
        : this(new LiveRegistryProvider())
    {
    }

    public LiveFirewallProvider(IRegistryProvider registry) => this.registry = registry;

    public FirewallState Read()
    {
        var rules = new List<FirewallRule>();
        foreach (var key in new[] { LocalRules, PolicyRules })
        {
            foreach (var value in registry.ListValues(key).Values)
            {
                if (value.Text is { } raw && FirewallRule.Parse(raw) is { } rule)
                {
                    rules.Add(rule);
                }
            }
        }

        // Group Policy takes precedence over the local setting when it defines one.
        var enabled = ReadFlag(PolicyPublicProfile, "EnableFirewall")
            ?? ReadFlag(LocalPublicProfile, "EnableFirewall")
            ?? true; // Absent: the firewall is enabled by default.

        var defaultInboundAllow = ReadFlag(PolicyPublicProfile, "DefaultInboundAction")
            ?? ReadFlag(LocalPublicProfile, "DefaultInboundAction")
            ?? false; // Absent: the Windows inbound default is block.

        return new FirewallState(rules, enabled, defaultInboundAllow);
    }

    /// <summary>
    /// Reads a DWORD flag. <c>EnableFirewall</c> is 1 when enabled;
    /// <c>DefaultInboundAction</c> is 1 for "allow", 0 for "block". Null when the value
    /// is absent — the caller then applies the Windows default.
    /// </summary>
    private bool? ReadFlag(string keyPath, string valueName)
    {
        var read = registry.ReadValue(keyPath, valueName);
        return read.Value?.Number is { } number ? number == 1 : null;
    }
}
