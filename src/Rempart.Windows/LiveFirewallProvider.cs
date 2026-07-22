using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Lit l'état du pare-feu Windows depuis le registre.
///
/// <para>
/// Les règles vivent sous <c>SharedAccess</c> pour les règles locales, et sous
/// <c>Policies</c> pour celles posées par stratégie de groupe — les deux comptent, une
/// GPO ajoute sans remplacer. Chaque valeur est une chaîne <c>Clé=Valeur</c> que le cœur
/// sait analyser. Passer par le registre plutôt que par l'interface COM du pare-feu a un
/// prix — les mots-clés de port dynamique restent opaques — mais garde la lecture
/// rejouable hors-ligne et sans dépendance COM sous AOT.
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

        // La stratégie de groupe prime sur le réglage local quand elle le pose.
        var enabled = ReadFlag(PolicyPublicProfile, "EnableFirewall")
            ?? ReadFlag(LocalPublicProfile, "EnableFirewall")
            ?? true; // Absent : le pare-feu est actif par défaut.

        var defaultInboundAllow = ReadFlag(PolicyPublicProfile, "DefaultInboundAction")
            ?? ReadFlag(LocalPublicProfile, "DefaultInboundAction")
            ?? false; // Absent : le défaut entrant de Windows est le blocage.

        return new FirewallState(rules, enabled, defaultInboundAllow);
    }

    /// <summary>
    /// Lit un drapeau DWORD. <c>EnableFirewall</c> vaut 1 pour actif ;
    /// <c>DefaultInboundAction</c> vaut 1 pour « autoriser », 0 pour « bloquer ». Null quand
    /// la valeur est absente — l'appelant applique alors le défaut Windows.
    /// </summary>
    private bool? ReadFlag(string keyPath, string valueName)
    {
        var read = registry.ReadValue(keyPath, valueName);
        return read.Value?.Number is { } number ? number == 1 : null;
    }
}
