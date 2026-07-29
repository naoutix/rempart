using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// A registry key the firewall read depends on, and what its silence means.
/// </summary>
/// <param name="Label">
/// How the surface is named in the diagnostic, in French — it reaches the report. The
/// surface is named, never the values it holds.
/// </param>
/// <param name="Path">Full registry path.</param>
/// <param name="Universal">
/// True when every Windows installation carries this key, so that finding it absent is a
/// failed read rather than a fact about the machine. False for the two Group Policy keys,
/// which exist only where a GPO applies — their absence is the ordinary case.
/// </param>
/// <param name="CarriesRules">
/// True for the two rule containers, whose values are parsed; false for the profile keys,
/// which are read value by value.
/// </param>
internal sealed record FirewallSurface(
    string Label, string Path, bool Universal, bool CarriesRules);

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
///
/// <para>
/// <b>A read that fails says so.</b> Every field this provider gets wrong on a refusal
/// fails towards « the firewall is on and blocks »: no rules read, <c>EnableFirewall</c>
/// absent (default: enabled), <c>DefaultInboundAction</c> absent (default: block). Those
/// three defaults are correct answers about a machine that was read and wrong ones about a
/// machine that was not, and they are indistinguishable afterwards — so the refusal is
/// recorded as it happens and the state comes back <see cref="FirewallState.Failed"/>.
/// </para>
/// </summary>
public sealed class LiveFirewallProvider : IFirewallProvider
{
    private static readonly FirewallSurface LocalRules = new(
        "règles locales",
        @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        Universal: true,
        CarriesRules: true);

    private static readonly FirewallSurface PolicyRules = new(
        "règles de stratégie de groupe",
        @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
        Universal: false,
        CarriesRules: true);

    private static readonly FirewallSurface LocalPublicProfile = new(
        "profil Public local",
        @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        Universal: true,
        CarriesRules: false);

    private static readonly FirewallSurface PolicyPublicProfile = new(
        "profil Public de stratégie de groupe",
        @"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        Universal: false,
        CarriesRules: false);

    /// <summary>
    /// Everything the read touches, in one list, walked by <see cref="Read"/>.
    ///
    /// <para>
    /// Exposed so the refusal test is generated from this list rather than from a copy of
    /// it: a surface added here gains its « refused » case without anyone remembering to
    /// write one. A hand-kept list of cases is right on the day it is written, and the
    /// fifth key added is the one nobody covers.
    /// </para>
    /// </summary>
    internal static readonly IReadOnlyList<FirewallSurface> Surfaces =
        [LocalRules, PolicyRules, LocalPublicProfile, PolicyPublicProfile];

    private readonly IRegistryProvider registry;

    public LiveFirewallProvider()
        : this(new LiveRegistryProvider())
    {
    }

    public LiveFirewallProvider(IRegistryProvider registry) => this.registry = registry;

    public FirewallState Read()
    {
        var unreadable = new List<string>();
        var rules = new List<FirewallRule>();
        var rulesKeyAnswered = false;

        foreach (var surface in Surfaces)
        {
            // KeyExists is the only enumerating read that carries a status today, which is
            // what makes a refused container visible at all: see the note on the rule count
            // below for the half it cannot cover.
            var presence = registry.KeyExists(surface.Path);

            if (presence == ReadStatus.AccessDenied
                || (presence == ReadStatus.NotFound && surface.Universal))
            {
                unreadable.Add(surface.Label);
                continue;
            }

            if (presence != ReadStatus.Found || !surface.CarriesRules)
            {
                continue;
            }

            rulesKeyAnswered = true;
            foreach (var value in registry.ListValues(surface.Path).Values)
            {
                if (value.Text is { } raw && FirewallRule.Parse(raw) is { } rule)
                {
                    rules.Add(rule);
                }
            }
        }

        // Group Policy takes precedence over the local setting when it defines one.
        var enabled = ReadFlag(PolicyPublicProfile, "EnableFirewall", unreadable)
            ?? ReadFlag(LocalPublicProfile, "EnableFirewall", unreadable)
            ?? true; // Absent: the firewall is enabled by default.

        var defaultInboundAllow = ReadFlag(PolicyPublicProfile, "DefaultInboundAction", unreadable)
            ?? ReadFlag(LocalPublicProfile, "DefaultInboundAction", unreadable)
            ?? false; // Absent: the Windows inbound default is block.

        // A rules key that opened and yielded nothing usable. Every Windows installation
        // ships hundreds of built-in rules, so zero is a failure and not a machine without
        // rules — the belief the Windows suite already asserted on the CI runner, moved to
        // where it protects an audited machine instead.
        //
        // This is also, for now, the only thing that catches a refused *enumeration*:
        // IRegistryProvider.ListValues returns the same empty dictionary for « clé vide »
        // and for « accès refusé » (REV-11, #115). When it learns to say which, this count
        // stops being the signal and becomes a redundant safety net.
        if (rulesKeyAnswered && rules.Count == 0)
        {
            unreadable.Add("règles illisibles là où la clé a pourtant répondu");
        }

        if (unreadable.Count > 0)
        {
            return FirewallState.Failed(
                "Pare-feu non lu : "
                + string.Join(", ", unreadable.Distinct(StringComparer.Ordinal))
                + ". La joignabilité des ports en écoute n'est pas tranchée.");
        }

        return new FirewallState(rules, enabled, defaultInboundAllow);
    }

    /// <summary>
    /// Reads a DWORD flag. <c>EnableFirewall</c> is 1 when enabled;
    /// <c>DefaultInboundAction</c> is 1 for "allow", 0 for "block". Null when the value is
    /// absent — the caller then applies the Windows default.
    ///
    /// <para>
    /// A refusal also returns null, because there is no flag to return, but it is recorded
    /// in <paramref name="unreadable"/> first: applying the Windows default to a value
    /// nobody could read is exactly how « je n'ai pas pu lire » became « le pare-feu est
    /// actif et bloque ». The key-level refusal is caught by <see cref="Read"/>; this
    /// catches the value-level one, which a per-value ACL can produce on a key that opens.
    /// </para>
    /// </summary>
    private bool? ReadFlag(FirewallSurface surface, string valueName, List<string> unreadable)
    {
        var read = registry.ReadValue(surface.Path, valueName);

        if (read.Status == ReadStatus.AccessDenied)
        {
            unreadable.Add(surface.Label);
            return null;
        }

        return read.Value?.Number is { } number ? number == 1 : null;
    }
}
