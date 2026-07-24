using Rempart.Core.Collectors;
using Rempart.Core.Providers;
using Rempart.Core.Reports;

namespace Rempart.Tests.Unit;

/// <summary>
/// Reading the component store analysis.
///
/// The figures come from another program's text output, which is the one place in this
/// batch where a silent failure is plausible: a Windows update changes a label, the
/// parser matches nothing, and the report announces a machine with nothing to reclaim.
/// So what is pinned here is mostly what happens when the text is <em>not</em> what we
/// expect — refusal, never zeros.
/// </summary>
public sealed class ComponentStoreTests
{
    /// <summary>Shape of an elevated run, as the tool prints it with <c>/English</c>.</summary>
    private const string RealisticOutput = """
        Deployment Image Servicing and Management tool
        Version: 10.0.26100.1

        Image Version: 10.0.26100.1

        [==========================100.0%==========================]

        Component Store (WinSxS) information:

        Windows Explorer Reported Size of Component Store : 7.16 GB

        Actual Size of Component Store : 6.94 GB

            Shared with Windows : 5.85 GB
            Backups and Disabled Features : 900.19 MB
            Cache and Temporary Data : 194.35 MB

        Date of Last Cleanup : 2026-07-01 10:00:00

        Number of Reclaimable Packages : 3
        Component Store Cleanup Recommended : Yes

        The operation completed successfully.
        """;

    [Fact]
    public void The_layers_are_read_from_the_analysis()
    {
        var read = ComponentStoreParser.Parse(RealisticOutput);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal((long)(6.94 * 1024 * 1024 * 1024), read.ActualSizeBytes);
        Assert.Equal((long)(5.85 * 1024 * 1024 * 1024), read.SharedWithWindowsBytes);
        Assert.Equal((long)(900.19 * 1024 * 1024), read.BackupsAndDisabledFeaturesBytes);
        Assert.Equal((long)(194.35 * 1024 * 1024), read.CacheAndTemporaryBytes);
        Assert.Equal(3, read.ReclaimablePackages);
        Assert.True(read.CleanupRecommended);
        Assert.Equal("2026-07-01 10:00:00", read.LastCleanup);
    }

    /// <summary>
    /// Only the two layers a cleanup actually frees. Counting the part shared with
    /// Windows would promise gigabytes that cannot be freed — the exact overstatement
    /// that makes people run cleanup tools on a healthy machine.
    /// </summary>
    [Fact]
    public void Reclaimable_space_excludes_what_windows_is_running_on()
    {
        var read = ComponentStoreParser.Parse(RealisticOutput);

        Assert.Equal(
            (long)(900.19 * 1024 * 1024) + (long)(194.35 * 1024 * 1024),
            read.ReclaimableBytes);
        Assert.True(read.ReclaimableBytes < read.SharedWithWindowsBytes);
    }

    /// <summary>
    /// The whole reason the parser exists as its own testable piece. Unrecognised text
    /// must produce a failure carrying an explanation, never a reading full of zeros
    /// that a report would print as "nothing to reclaim".
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("Erreur : 740\n\nDes autorisations élevées sont requises.")]
    [InlineData("Taille réelle du magasin de composants : 6,94 Go")]
    [InlineData("Actual Size of Component Store : quelque chose")]
    [InlineData("Actual Size of Component Store : 6.94 PB")]
    public void Unrecognised_output_is_refused_rather_than_read_as_zero(string output)
    {
        var read = ComponentStoreParser.Parse(output);

        Assert.NotEqual(ReadStatus.Found, read.Status);
        Assert.Null(read.ActualSizeBytes);
        Assert.Null(read.ReclaimableBytes);
        Assert.NotNull(read.Diagnostic);
    }

    /// <summary>
    /// A size present but a layer missing stays missing. Defaulting it to zero would
    /// shrink the reclaimable total silently.
    /// </summary>
    [Fact]
    public void A_missing_layer_stays_unknown()
    {
        var read = ComponentStoreParser.Parse(
            "Actual Size of Component Store : 6.94 GB\nShared with Windows : 5.85 GB");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.BackupsAndDisabledFeaturesBytes);
        Assert.Null(read.CacheAndTemporaryBytes);
        Assert.Null(read.ReclaimableBytes);
    }

    [Fact]
    public void The_cleanup_date_keeps_the_colons_of_its_time()
    {
        var read = ComponentStoreParser.Parse(
            "Actual Size of Component Store : 1 GB\nDate of Last Cleanup : 2026-07-01 10:23:45");

        Assert.Equal("2026-07-01 10:23:45", read.LastCleanup);
    }

    [Theory]
    [InlineData("1024 bytes", 1024)]
    [InlineData("1 KB", 1024)]
    [InlineData("1 MB", 1024 * 1024)]
    [InlineData("2 GB", 2L * 1024 * 1024 * 1024)]
    public void Sizes_use_binary_multiples_as_windows_does(string text, long expected) =>
        Assert.Equal(expected, ComponentStoreParser.TryBytes(text));

    /// <summary>
    /// Missing privileges are not a failure of the collector: the scan says so and goes
    /// on, and the report shows the gap rather than an absence of data.
    /// </summary>
    [Fact]
    public void Without_elevation_the_collector_reports_the_gap_and_the_scan_continues()
    {
        var result = new ComponentStoreCollector().Collect(
            new ProviderSet(
                new FakeRegistryProvider(), new FakeSystemInfoProvider(),
                componentStore: new RefusingStore(ComponentStoreRead.Denied("élévation requise"))));

        Assert.Equal(CollectorStatus.InsufficientPrivileges, result.Status);
        Assert.Contains("élévation requise", result.Diagnostics.Single(), StringComparison.Ordinal);
        Assert.Empty(result.Fields);
    }

    [Fact]
    public void An_unrequested_analysis_leaves_no_section_in_the_report()
    {
        // No component-store collector ran: the report must not show an empty block.
        var view = ReportView.From(TestScan([]));
        Assert.Null(view.ComponentStore);

        var withStore = ReportView.From(TestScan(
        [
            new CollectorResult("component-store", CollectorStatus.Ok,
                new Dictionary<string, string?> { ["store.reclaimableBytes"] = "1048576" }, []),
        ]));

        Assert.NotNull(withStore.ComponentStore);
    }

    /// <summary>
    /// A degraded analysis is not a source of figures either: a collector in error must
    /// not surface a half-filled section that reads like a measurement.
    /// </summary>
    [Fact]
    public void A_failed_analysis_produces_no_figures()
    {
        var view = ReportView.From(TestScan(
        [
            new CollectorResult("component-store", CollectorStatus.Failed, [], ["format inconnu"]),
        ]));

        Assert.Null(view.ComponentStore);
    }

    private static Rempart.Core.Engine.ScanResult TestScan(List<CollectorResult> collectors) =>
        new("0.6.0", "2026-07-24T09:15:00Z", collectors, [], [], null, "sha256:x",
            new Rempart.Core.Updates.DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));

    private sealed class RefusingStore(ComponentStoreRead read) : IComponentStoreProvider
    {
        public ComponentStoreRead Read() => read;
    }
}
