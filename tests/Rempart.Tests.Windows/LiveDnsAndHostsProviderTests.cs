using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// La lecture DNS parcourt les interfaces du registre et découpe les listes de résolveurs.
/// Un chemin de clé faux rendrait une liste vide sans que rien ne le signale ; ce test
/// exerce la vraie lecture.
/// </summary>
public sealed class LiveDnsProviderTests
{
    private readonly IReadOnlyList<Core.Providers.DnsInterface> interfaces =
        new LiveDnsProvider().Read();

    [Fact]
    public void Interfaces_carry_an_id_and_plausible_resolvers()
    {
        foreach (var iface in interfaces)
        {
            Assert.False(string.IsNullOrWhiteSpace(iface.Id));

            // Un découpage faux collerait plusieurs adresses en une : chaque résolveur doit
            // ressembler à une adresse isolée, sans séparateur résiduel.
            foreach (var server in iface.StaticServers.Concat(iface.DhcpServers))
            {
                Assert.DoesNotContain(' ', server);
                Assert.DoesNotContain(',', server);
            }
        }
    }
}

/// <summary>
/// Le fichier hosts est à un emplacement fixe. Un chemin faux rendrait « aucune
/// correspondance » là où le fichier existe — ce test vérifie qu'on lit bien le vrai
/// fichier, qui porte toujours son en-tête de commentaires.
/// </summary>
public sealed class LiveHostsFileProviderTests
{
    [Fact]
    public void The_real_hosts_file_is_read()
    {
        var lines = new LiveHostsFileProvider().ReadLines();

        // Le fichier hosts livré par Windows n'est jamais vide : il porte un en-tête de
        // commentaires. Une liste vide trahirait un chemin faux.
        Assert.NotEmpty(lines);
        Assert.Contains(lines, line => line.TrimStart().StartsWith('#'));
    }
}
