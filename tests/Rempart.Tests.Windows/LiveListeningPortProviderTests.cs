using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Le P/Invoke vers <c>GetExtendedTcpTable</c> lit une table à taille variable par
/// décalages. Une erreur y est invisible à la compilation et rend soit un tampon vide,
/// soit des champs plausibles mais faux — un bogue de passage de taille par
/// <c>ref</c> avait précisément rendu zéro port en silence. Ces tests exercent le vrai
/// appel contre la machine, seul endroit où il se prouve.
/// </summary>
public sealed class LiveListeningPortProviderTests
{
    private readonly IReadOnlyList<Core.Providers.ListeningPort> ports =
        new LiveListeningPortProvider().Enumerate();

    [Fact]
    public void At_least_one_port_is_listening()
    {
        // Toute machine Windows tient au moins le mappeur de points de terminaison RPC
        // (135). Une liste vide trahit un P/Invoke rompu, pas une machine sans service.
        Assert.NotEmpty(ports);
    }

    [Fact]
    public void Every_port_is_structurally_plausible()
    {
        foreach (var port in ports)
        {
            Assert.Contains(port.Protocol, new[] { "TCP", "UDP" });
            Assert.InRange(port.Port, 1, 65535);
            Assert.True(port.Pid >= 0, $"PID négatif : {port.Pid}");

            // Un DWORD mal décodé donnerait une adresse hors des quatre octets — le signe
            // d'un décalage de champ faux dans la lecture de la table.
            var octets = port.LocalAddress.Split('.');
            Assert.Equal(4, octets.Length);
            Assert.All(octets, o => Assert.InRange(int.Parse(o), 0, 255));
        }
    }

    [Fact]
    public void Reading_twice_does_not_throw_or_leak()
    {
        // La liste exacte bouge d'un instant à l'autre ; ce qui se teste, c'est que le
        // second appel aboutisse et libère son tampon natif comme le premier.
        _ = new LiveListeningPortProvider().Enumerate();
    }
}
