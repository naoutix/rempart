using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeDnsProvider(params DnsInterface[] interfaces) : IDnsProvider
{
    public IReadOnlyList<DnsInterface> Read() => interfaces;
}

internal sealed class FakeHostsFileProvider(params string[] lines) : IHostsFileProvider
{
    public IReadOnlyList<string> ReadLines() => lines;
}

public class DnsResolverTests
{
    private static IReadOnlyList<Finding> Collect(params DnsInterface[] interfaces) =>
        new DnsResolverCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            dns: new FakeDnsProvider(interfaces)));

    /// <summary>Un résolveur reçu du DHCP est celui du réseau : inventorié, pas jugé.</summary>
    [Fact]
    public void A_dhcp_resolver_is_benign_inventory()
    {
        var finding = Assert.Single(Collect(new DnsInterface("if0", [], ["192.168.0.1"])));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("DHCP", finding.Details["origine"]);
    }

    /// <summary>Un résolveur statique reconnu — Cloudflare, Google — est un choix délibéré courant.</summary>
    [Fact]
    public void A_well_known_static_resolver_is_benign()
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", ["1.1.1.1"], []))).Severity);
    }

    /// <summary>Un résolveur local — la boucle, un filtre installé exprès — reste bénin.</summary>
    [Fact]
    public void A_loopback_static_resolver_is_benign()
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", ["127.0.0.1"], []))).Severity);
    }

    /// <summary>
    /// Un résolveur statique inconnu est relevé : un serveur posé par-dessus celui du réseau
    /// est le levier même d'un détournement DNS.
    /// </summary>
    [Fact]
    public void An_unrecognised_static_resolver_is_notable()
    {
        var finding = Assert.Single(Collect(new DnsInterface("if0", ["203.0.113.5"], [])));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("203.0.113.5", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// Un mélange de résolveurs, dont un inconnu, est relevé : il suffit d'une adresse non
    /// reconnue pour justifier le regard, et c'est elle que le motif nomme.
    /// </summary>
    [Fact]
    public void A_mix_with_one_unrecognised_resolver_is_notable()
    {
        var finding = Assert.Single(Collect(new DnsInterface("if0", ["1.1.1.1", "203.0.113.5"], [])));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("203.0.113.5", string.Join(" ", finding.Reasons));
        Assert.DoesNotContain("1.1.1.1", finding.Reasons.Single());
    }

    /// <summary>Une interface sans résolveur ne produit rien : rien à inventorier.</summary>
    [Fact]
    public void An_interface_without_resolvers_yields_nothing()
    {
        Assert.Empty(Collect(new DnsInterface("if0", [], [])));
    }
}

public class HostsFileTests
{
    private static IReadOnlyList<Finding> Collect(params string[] lines) =>
        new HostsFileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            hostsFile: new FakeHostsFileProvider(lines)));

    /// <summary>Le fichier hosts par défaut n'a que des commentaires : rien à relever.</summary>
    [Fact]
    public void A_default_hosts_file_yields_nothing()
    {
        Assert.Empty(Collect("# Copyright", "#", "# 102.54.94.97   rhino.acme.com", "   "));
    }

    /// <summary>
    /// Une redirection vers une adresse routable court-circuite le DNS vers une machine
    /// choisie : elle est relevée, une à une.
    /// </summary>
    [Fact]
    public void A_redirect_to_a_routable_address_is_notable()
    {
        var finding = Assert.Single(Collect("93.184.216.34  example.com"));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("redirection", finding.Details["type"]);
        Assert.Contains("→", finding.Target);
    }

    /// <summary>
    /// Rediriger un domaine sensible — une mise à jour, une authentification — est suspect :
    /// c'est la forme même du détournement.
    /// </summary>
    [Fact]
    public void A_redirect_of_a_sensitive_domain_is_suspicious()
    {
        var finding = Assert.Single(Collect("93.184.216.34  windowsupdate.microsoft.com"));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    /// <summary>
    /// Les blocages se comptent par milliers dans une liste anti-publicité : ils sont
    /// agrégés en un seul constat, avec leur nombre.
    /// </summary>
    [Fact]
    public void Blocking_entries_are_aggregated_into_one_finding()
    {
        var findings = Collect(
            "0.0.0.0  ads.example.com",
            "0.0.0.0  tracker.example.net",
            "127.0.0.1  telemetry.example.org");

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("3", finding.Details["domaines"]);
    }

    /// <summary>
    /// Neutraliser une mise à jour ou une protection n'est pas un réglage anodin : empêcher
    /// un correctif est une manœuvre, et l'agrégat passe alors à suspect.
    /// </summary>
    [Fact]
    public void Blocking_a_critical_domain_escalates_to_suspicious()
    {
        var findings = Collect(
            "0.0.0.0  ads.example.com",
            "0.0.0.0  update.microsoft.com");

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(findings).Severity);
    }

    /// <summary>Une même ligne peut viser plusieurs hôtes vers une adresse : chacun compte.</summary>
    [Fact]
    public void Multiple_hosts_on_one_line_each_count()
    {
        var findings = Collect("0.0.0.0  a.example.com b.example.com c.example.com");

        Assert.Equal("3", Assert.Single(findings).Details["domaines"]);
    }

    /// <summary>Un commentaire en fin de ligne est retiré avant l'analyse.</summary>
    [Fact]
    public void An_inline_comment_is_stripped()
    {
        var finding = Assert.Single(Collect("93.184.216.34  example.com  # test local"));

        Assert.Equal("example.com", finding.Details["domaine"]);
    }
}
