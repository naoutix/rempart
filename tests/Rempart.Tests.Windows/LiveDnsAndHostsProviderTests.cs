using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The DNS read walks the interface keys in the registry and splits the resolver lists.
/// A wrong key path would return an empty list without any signal; this test exercises
/// the real read.
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

            // A wrong split would glue several addresses into one: each resolver must
            // look like a single address, with no leftover separator.
            foreach (var server in iface.StaticServers.Concat(iface.DhcpServers))
            {
                Assert.DoesNotContain(' ', server);
                Assert.DoesNotContain(',', server);
            }
        }
    }
}

/// <summary>
/// The hosts file lives at a fixed location. A wrong path would report "no match" even
/// though the file exists — this test checks that the real file is read; it always
/// carries a comment header.
/// </summary>
public sealed class LiveHostsFileProviderTests
{
    [Fact]
    public void The_real_hosts_file_is_read()
    {
        var lines = new LiveHostsFileProvider().ReadLines();

        // The hosts file shipped with Windows is never empty: it carries a comment
        // header. An empty list would mean a wrong path.
        Assert.NotEmpty(lines);
        Assert.Contains(lines, line => line.TrimStart().StartsWith('#'));
    }
}
