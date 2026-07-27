using System.Net;
using System.Net.Sockets;
using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The dynamic port range read from the real machine.
///
/// <para>
/// The reading exists to replace a constant (DET-PLAGE-DYNAMIQUE), so the interesting
/// question is not whether it parses — that is settled on the Linux job, against output
/// captured from this command — but whether the numbers it comes back with are this
/// machine's. That cannot be checked against <c>netsh</c>, which is where they came from, so
/// it is checked against the operating system's own behaviour: a socket bound to port 0 is
/// handed a number out of exactly this band. Confronting the reading with what the machine
/// <em>does</em> is the only form of this test that is not the provider agreeing with itself.
/// </para>
/// </summary>
public sealed class LiveDynamicPortRangeProviderTests
{
    private readonly DynamicPortRangeRead read = new LiveDynamicPortRangeProvider().Read();

    /// <summary>
    /// This one refuses to go quiet. Every Windows machine hands out ephemeral ports — the
    /// TCP/IP stack cannot work otherwise — and <c>netsh</c> needs no elevation to say which
    /// ones, so an unread range here indicts the provider and not the environment. A test
    /// that skipped on a failed read would leave the whole class green on a machine where
    /// the reading had stopped working, which is the shape this repository has already
    /// shipped once.
    /// </summary>
    [Fact]
    public void The_machine_states_its_dynamic_port_range()
    {
        Assert.True(read.Status == ReadStatus.Found,
            $"Plage de ports dynamique non lue sur cette machine : {read.Diagnostic}. "
            + "Toute machine Windows en attribue, et netsh les déclare sans élévation : "
            + "c'est la lecture qui est en cause, pas l'environnement.");

        Assert.NotNull(read.Range);
        Assert.InRange(read.Range!.FirstPort, 1, 65535);
        Assert.InRange(read.Range.LastPort, read.Range.FirstPort, 65535);
    }

    /// <summary>
    /// The independent half. The band is confronted with the numbers the stack actually
    /// assigns, which nothing in this project produced: a reading that came back plausible
    /// and wrong — the two values swapped, a table misread, the wrong protocol asked — puts
    /// real sockets outside the range it claims.
    ///
    /// <para>
    /// Several sockets rather than one: Windows skips reserved sub-ranges inside the band, so
    /// a single draw landing where expected proves less than a handful of them agreeing.
    /// </para>
    ///
    /// <para>
    /// <b>What it cannot see, measured rather than assumed.</b> It catches a band that is too
    /// narrow or in the wrong place — asking netsh for a protocol family that does not exist
    /// makes it fail — but never one that is merely too <em>wide</em>, since a wider band
    /// still contains every port the system hands out. Swapping the two parsed numbers is
    /// exactly that case: 49152/16384 read backwards yields 16384–65535, a superset, and this
    /// test stays green on it. The one that fails is the parser test on the Linux job, which
    /// holds the two values against the captured output. Neither guard covers the other, and
    /// saying so is cheaper than discovering it later.
    /// </para>
    /// </summary>
    [Fact]
    public void Sockets_the_system_numbers_itself_land_inside_the_range_it_reports()
    {
        Assert.True(read.Range is not null,
            "Aucune plage lue : ce test ne peut rien confronter. Voir le test précédent.");

        var assigned = new List<int>();
        var listeners = new List<TcpListener>();

        try
        {
            for (var i = 0; i < 5; i++)
            {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listeners.Add(listener);
                listener.Start();
                assigned.Add(((IPEndPoint)listener.LocalEndpoint).Port);
            }
        }
        finally
        {
            foreach (var listener in listeners)
            {
                listener.Stop();
            }
        }

        var outside = assigned.Where(port => !read.Range!.Contains(port)).ToList();

        Assert.True(outside.Count == 0,
            $"Le système attribue {string.Join(", ", outside)} hors de la plage annoncée "
            + $"{read.Range!.Describe()} : la lecture rend des nombres qui ne sont pas ceux "
            + "de cette machine, et le rapport marquerait comme « éphémères » des ports qui "
            + "ne le sont pas — en taisant ceux qui le sont.");
    }

    /// <summary>
    /// <c>netsh</c> reconfigures the stack as readily as it describes it: <c>set
    /// dynamicport</c> moves the range, and it is one word away from what is asked here. Same
    /// precaution as the component store, whose tool also deletes one verb away, and pinned
    /// the same way — as data a test can read.
    /// </summary>
    [Fact]
    public void The_queries_only_ever_show()
    {
        Assert.NotEmpty(LiveDynamicPortRangeProvider.Queries);

        foreach (var query in LiveDynamicPortRangeProvider.Queries)
        {
            Assert.Contains("show", query);

            foreach (var mutating in new[] { "set", "add", "delete", "reset", "import" })
            {
                Assert.DoesNotContain(mutating, query, StringComparer.OrdinalIgnoreCase);
            }
        }
    }
}
