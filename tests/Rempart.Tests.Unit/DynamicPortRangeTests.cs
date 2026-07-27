using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

internal sealed class FakeDynamicPortRangeProvider(DynamicPortRangeRead read)
    : IDynamicPortRangeProvider
{
    public DynamicPortRangeRead Read() => read;
}

/// <summary>
/// The dynamic port range: what is read from the machine, and what the report is allowed to
/// say when nothing could be read.
///
/// <para>
/// DET-PLAGE-DYNAMIQUE was one constant — 49152 — asserted about every machine that had ever
/// been scanned. The range is configurable, so on a machine that had moved it the tool marked
/// the wrong ports as churn and said nothing about having assumed anything. What closes the
/// debt is not the reading on its own: it is the reading <em>plus</em> a fallback that
/// announces itself, because a tool that silently degrades to a constant has only moved the
/// unbacked claim further from the code that makes it.
/// </para>
/// </summary>
public sealed class DynamicPortRangeTests
{
    /// <summary>
    /// The real output of <c>netsh int ipv4 show dynamicport tcp</c>, captured on the
    /// workstation this batch was written on — a French-language Windows 11, which is exactly
    /// what makes it worth keeping. <c>netsh</c> has no <c>/English</c> switch, so this is
    /// the shape the parser meets on a machine that is not in English, and the shape a parser
    /// written against translated labels would have failed on.
    /// </summary>
    private const string RealFrenchOutput = """

        Plage de ports dynamique du protocole tcp
        -------------------------------------------
        Port de démarrage   : 49152
        Nombre de ports     : 16384


        """;

    [Fact]
    public void The_real_output_of_this_machine_is_read_as_the_range_it_states()
    {
        var range = DynamicPortRange.Parse(RealFrenchOutput);

        Assert.NotNull(range);
        Assert.Equal(49152, range!.FirstPort);
        Assert.Equal(16384, range.PortCount);
        Assert.Equal(65535, range.LastPort);
        Assert.Equal("49152–65535", range.Describe());
    }

    /// <summary>
    /// The claim the parser rests on, stated as a test rather than as a comment: it reads
    /// positions, never words.
    ///
    /// <para>
    /// The labels are replaced with text in no language at all. Had the parser been written
    /// against « Port de démarrage » — or against the English wording, which nobody here has
    /// ever seen this command produce — it would answer correctly on the maintainer's machine
    /// and produce a wrong range, silently, on everyone else's. DISM set the same trap and
    /// there the answer was <c>/English</c>; <c>netsh</c> offers no such switch, so the answer
    /// has to be a parser that does not care.
    /// </para>
    /// </summary>
    [Fact]
    public void The_labels_are_never_matched_only_the_two_values_are()
    {
        var translated = RealFrenchOutput
            .Replace("Port de démarrage", "xxxx yy zzzzzzzzz", StringComparison.Ordinal)
            .Replace("Nombre de ports", "wwwwww vv uuuuu", StringComparison.Ordinal)
            .Replace("Plage de ports dynamique du protocole tcp", "aaaa", StringComparison.Ordinal);

        Assert.Equal(DynamicPortRange.Parse(RealFrenchOutput), DynamicPortRange.Parse(translated));
    }

    /// <summary>
    /// A machine whose range was moved. Nothing in this repository has ever captured one, so
    /// this is the shape of that output rather than a recording of it — and it is the case
    /// the constant got wrong for as long as it existed.
    /// </summary>
    [Fact]
    public void A_reconfigured_range_is_read_as_configured()
    {
        var range = DynamicPortRange.Parse("Début : 10000\nNombre : 5000\n");

        Assert.Equal(10000, range?.FirstPort);
        Assert.Equal(14999, range?.LastPort);
    }

    /// <summary>
    /// Anything that is not exactly two plausible numbers is no reading at all. Guessing here
    /// would invent a machine's configuration out of a parse failure, and the caller would
    /// have no way of telling that apart from a measurement.
    /// </summary>
    [Theory]
    // Nothing at all — the command failed and printed its error somewhere else.
    [InlineData("")]
    // An error message, colon and all: one value, so not the two-row table.
    [InlineData("Erreur : élément introuvable.\n")]
    // Three values: whatever this is, it is not the table we think it is.
    [InlineData("a : 1\nb : 2\nc : 3\n")]
    // A range running past the end of the port space: the two numbers were not the two.
    [InlineData("a : 60000\nb : 10000\n")]
    // Port zero is not handed out.
    [InlineData("a : 0\nb : 1000\n")]
    // A count of zero describes no range.
    [InlineData("a : 49152\nb : 0\n")]
    // Negative values: the minus sign is refused, so this parses as no number at all.
    [InlineData("a : -49152\nb : -16384\n")]
    public void An_output_that_is_not_two_plausible_numbers_yields_no_reading(string output)
    {
        Assert.Null(DynamicPortRange.Parse(output));
    }

    [Fact]
    public void A_range_contains_its_own_bounds_and_nothing_outside_them()
    {
        var range = new DynamicPortRange(49152, 16384);

        Assert.True(range.Contains(49152));
        Assert.True(range.Contains(65535));
        Assert.False(range.Contains(49151));
        Assert.False(range.Contains(65536));
    }

    /// <summary>
    /// Four tables are read and one band is reported, so the span has to cover the lot: a
    /// machine whose UDP range was moved down and whose TCP range was left alone hands out
    /// numbers from both.
    /// </summary>
    [Fact]
    public void Spanning_two_ranges_covers_both()
    {
        var spanned = new DynamicPortRange(49152, 16384)
            .SpannedWith(new DynamicPortRange(10000, 100));

        Assert.Equal(10000, spanned.FirstPort);
        Assert.Equal(65535, spanned.LastPort);
    }

    /// <summary>
    /// Four tables that agree: one band, and nothing to report about them.
    ///
    /// <para>
    /// This is the ordinary machine and it is the case the first version got wrong. It folded
    /// the tables by their <em>labelled</em> descriptions — « ipv4/tcp 49152–65535 » against
    /// « ipv4/udp 49152–65535 » — so four identical ranges counted as four different ones and
    /// every capture carried « Les tables ne déclarent pas la même plage » about a machine
    /// whose tables all said the same thing. Nothing failed: the band was right, only the
    /// sentence beside it was false. It was found by running the published binary and reading
    /// what it wrote, which is the only place it was visible.
    /// </para>
    /// </summary>
    [Fact]
    public void Tables_that_agree_produce_one_band_and_no_diagnostic()
    {
        var read = DynamicPortRangeRead.Combine([
            ("ipv4/tcp", DynamicPortRange.WindowsDefault),
            ("ipv4/udp", DynamicPortRange.WindowsDefault),
            ("ipv6/tcp", DynamicPortRange.WindowsDefault),
            ("ipv6/udp", DynamicPortRange.WindowsDefault),
        ]);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal("49152–65535", read.Range?.Describe());
        Assert.Null(read.Diagnostic);
    }

    /// <summary>
    /// Tables that genuinely disagree — a machine somebody reconfigured for one protocol and
    /// not the other. The band covers both and the diagnostic names them: the span alone
    /// would not say that anything unusual had been configured.
    /// </summary>
    [Fact]
    public void Tables_that_disagree_are_spanned_and_named()
    {
        var read = DynamicPortRangeRead.Combine([
            ("ipv4/tcp", new DynamicPortRange(10000, 5000)),
            ("ipv4/udp", DynamicPortRange.WindowsDefault),
        ]);

        Assert.Equal("10000–65535", read.Range?.Describe());
        Assert.Contains("ipv4/tcp 10000–14999", read.Diagnostic!, StringComparison.Ordinal);
        Assert.Contains("ipv4/udp 49152–65535", read.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// One table refuses and the others answer: what was read is kept and the silent one is
    /// named. The same shape <c>ListeningPortRead.Partial</c> takes, and for the same reason —
    /// dropping three readings because a fourth failed trades one silence for another.
    /// </summary>
    [Fact]
    public void A_table_that_does_not_answer_is_named_beside_what_was_read()
    {
        var read = DynamicPortRangeRead.Combine([
            ("ipv4/tcp", DynamicPortRange.WindowsDefault),
            ("ipv6/udp", null),
        ]);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal("49152–65535", read.Range?.Describe());
        Assert.Contains("ipv6/udp", read.Diagnostic!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nothing answered: a failed read, so the finding falls back to the Windows default and
    /// says it did. Never a range invented from an empty list.
    /// </summary>
    [Fact]
    public void No_table_answering_is_a_failed_read_and_not_a_default()
    {
        var read = DynamicPortRangeRead.Combine([("ipv4/tcp", null), ("ipv4/udp", null)]);

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Range);
        Assert.Contains("ipv4/tcp", read.Diagnostic!, StringComparison.Ordinal);

        // And the judgement still works, on the constant, announced as such.
        Assert.False(read.Effective().Measured);
        Assert.Equal(DynamicPortRange.WindowsDefault, read.Effective().Range);
    }

    /// <summary>
    /// The fallback, and the sentence that keeps it honest. Both halves are asserted in one
    /// test because it is the <em>difference</em> that is the invariant — checking them apart
    /// would let the two notes be made identical again without failing anything, which is the
    /// state this debt was in.
    /// </summary>
    [Fact]
    public void The_finding_says_whether_the_range_was_read_or_assumed()
    {
        var measured = Note(DynamicPortRangeRead.Found(DynamicPortRange.WindowsDefault));
        var assumed = Note(DynamicPortRangeRead.Failed("netsh n'a pas répondu."));

        Assert.NotNull(measured);
        Assert.NotNull(assumed);
        Assert.NotEqual(measured, assumed);

        Assert.Contains("relevée sur la machine", measured!, StringComparison.Ordinal);
        Assert.Contains("49152–65535", measured, StringComparison.Ordinal);

        // The fallback names the band it used and admits it did not read it. « Port de la
        // plage dynamique », full stop, was the old wording: true by luck on a default
        // machine, an unbacked claim on any other.
        Assert.Contains("par défaut de Windows", assumed!, StringComparison.Ordinal);
        Assert.Contains("faute d'avoir pu lire celle de la machine", assumed,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The reading is what decides, not the constant. A machine handing out 10000–14999 must
    /// have 10500 marked as churn and 49700 — a fixed service port, there — left alone. With
    /// the constant in place the tool got both backwards and said nothing about it.
    ///
    /// <para>
    /// Both directions in one test, so it cannot pass by the marker having simply stopped
    /// working: the same two port numbers are asserted the other way round on the default
    /// range.
    /// </para>
    /// </summary>
    [Fact]
    public void A_machine_with_a_moved_range_is_judged_on_its_own_range()
    {
        var moved = DynamicPortRangeRead.Found(new DynamicPortRange(10000, 5000));

        Assert.NotNull(Note(moved, port: 10500));
        Assert.Null(Note(moved, port: 49700));

        var standard = DynamicPortRangeRead.Found(DynamicPortRange.WindowsDefault);

        Assert.Null(Note(standard, port: 10500));
        Assert.NotNull(Note(standard, port: 49700));
    }

    /// <summary>
    /// A severity above benign is never quietened, whatever the port number: an unsigned
    /// binary reachable from a public network is news every time, and this marker exists to
    /// silence churn, never a judgement. The port used is inside the range on purpose.
    /// </summary>
    [Fact]
    public void A_port_that_was_judged_is_never_marked_as_churn()
    {
        var findings = new ListeningPortsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: new FakeSignatureProvider().With(@"C:\tmp\srv.exe", SignatureStatus.Unsigned),
            processes: new FakeProcessProvider([
                new RunningProcess(500, 4, "srv.exe", @"C:\tmp\srv.exe", "")]),
            listeningPorts: new FakeListeningPortProvider(
                new ListeningPort("TCP", "0.0.0.0", 49700, 500)),
            dynamicPortRange: new FakeDynamicPortRangeProvider(
                DynamicPortRangeRead.Found(DynamicPortRange.WindowsDefault))));

        var finding = Assert.Single(findings);

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.False(finding.Details.ContainsKey(FindingDetails.Ephemeral));
    }

    /// <summary>
    /// Runs the collector on one loopback port and returns the churn note it attached, or
    /// null. Going through the collector rather than through a helper is deliberate: what is
    /// pinned is what the report says, and a note produced by a method nobody calls would
    /// prove nothing.
    /// </summary>
    private static string? Note(DynamicPortRangeRead read, int port = 49669)
    {
        var findings = new ListeningPortsCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            listeningPorts: new FakeListeningPortProvider(
                new ListeningPort("TCP", "127.0.0.1", port, 4)),
            dynamicPortRange: new FakeDynamicPortRangeProvider(read)));

        var finding = Assert.Single(findings);

        // Loopback keeps the judgement benign without needing a firewall or a signature. If
        // that ever stopped holding, the notes below would go missing for a reason that has
        // nothing to do with the range, so it is checked here rather than assumed.
        Assert.Equal(FindingSeverity.Benign, finding.Severity);

        return finding.Details.GetValueOrDefault(FindingDetails.Ephemeral);
    }
}
