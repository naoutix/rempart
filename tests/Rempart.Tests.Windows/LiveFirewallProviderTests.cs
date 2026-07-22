using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// La lecture du pare-feu passe par des chaînes de registre à analyser. Un chemin de clé
/// faux ou un format mal compris ne se voit pas à la compilation : il rend une liste vide
/// et la règle croisée se tait sans que rien ne le signale. Ces tests exercent la vraie
/// lecture contre la machine.
/// </summary>
public sealed class LiveFirewallProviderTests
{
    private readonly FirewallState state = new LiveFirewallProvider().Read();

    [Fact]
    public void The_firewall_state_is_readable()
    {
        Assert.True(state.Readable);
    }

    [Fact]
    public void Rules_are_read_and_parsed()
    {
        // Toute installation de Windows porte des centaines de règles intégrées. Une liste
        // vide trahit un chemin de clé faux, pas un pare-feu sans règle.
        Assert.NotEmpty(state.Rules);
        Assert.All(state.Rules, rule => Assert.False(string.IsNullOrEmpty(rule.Direction)));
    }

    [Fact]
    public void Reachability_is_answered_without_throwing()
    {
        // La valeur dépend de la machine ; ce qui se teste, c'est que le croisement aboutisse
        // et ne rende jamais « inconnu » sur un état pourtant lu.
        var reach = state.InboundReachability("TCP", 445, null);
        Assert.NotEqual(FirewallReachability.Unknown, reach);
    }
}
