using System.Text.Json;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

internal sealed class FakeDnsProvider(DnsRead read) : IDnsProvider
{
    public FakeDnsProvider(params DnsInterface[] interfaces)
        : this(DnsRead.Found(interfaces))
    {
    }

    public DnsRead Read() => read;
}

internal sealed class FakeHostsFileProvider(HostsFileRead read) : IHostsFileProvider
{
    public FakeHostsFileProvider(params string[] lines)
        : this(HostsFileRead.Found(lines))
    {
    }

    public HostsFileRead ReadLines() => read;
}

public class DnsResolverTests
{
    private static IReadOnlyList<Finding> Collect(params DnsInterface[] interfaces) =>
        new DnsResolverCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            dns: new FakeDnsProvider(interfaces)));

    /// <summary>
    /// Every stack the provider layer names, so that the judgement below is read once per
    /// stack rather than once — discovered from <see cref="DnsStack"/> and not listed, which
    /// is what makes a stack added tomorrow judged without anyone remembering this file.
    /// </summary>
    public static TheoryData<DnsStack> EveryStack() => [.. Enum.GetValues<DnsStack>()];

    /// <summary>
    /// A resolver received from DHCP is the network's: inventoried, not judged — and the
    /// inventory line says which stack it sits on, since an adapter appears once per stack
    /// under the same identifier.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void A_dhcp_resolver_is_benign_inventory(DnsStack stack)
    {
        var finding = Assert.Single(Collect(
            new DnsInterface("if0", [], ["192.168.0.1"], stack)));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("DHCP", finding.Details["origine"]);
        Assert.Equal(stack.ToString(), finding.Details["pile"]);
    }

    /// <summary>A recognised static resolver — Cloudflare, Google — is a common deliberate choice.</summary>
    [Fact]
    public void A_well_known_static_resolver_is_benign()
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", ["1.1.1.1"], [], DnsStack.IPv4)))
                .Severity);
    }

    /// <summary>
    /// The same, in the vocabulary the IPv6 stack speaks. The well-known list has carried
    /// Cloudflare's and Google's v6 addresses since it was written and the loopback rule has
    /// known <c>::1</c> as long — but nothing ever reached them, the collection stopping at
    /// <c>Tcpip</c> (#191). A machine resolving through Cloudflare over IPv6 must not become a
    /// NOTABLE on the day the second stack starts being read.
    /// </summary>
    [Theory]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::1")]
    public void A_well_known_or_local_IPv6_static_resolver_is_benign(string server)
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", [server], [], DnsStack.IPv6)))
                .Severity);
    }

    /// <summary>A local resolver — loopback, a filter installed on purpose — stays benign.</summary>
    [Fact]
    public void A_loopback_static_resolver_is_benign()
    {
        Assert.Equal(FindingSeverity.Benign,
            Assert.Single(Collect(new DnsInterface("if0", ["127.0.0.1"], [], DnsStack.IPv4)))
                .Severity);
    }

    /// <summary>
    /// An unrecognised static resolver is flagged: a server laid over the network's own
    /// is the very lever of a DNS hijack.
    ///
    /// <para>
    /// Read on every stack, because that is the half of the judgement that transfers: « typed
    /// in by hand » is the same act and the same key name on both, so a v6 resolver nobody
    /// recognises is a hijack lever for the reason a v4 one is. The half that does not transfer
    /// is asserted next door, in <c>RegistryDnsProviderTests</c>, as the silence it is.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryStack))]
    public void An_unrecognised_static_resolver_is_notable(DnsStack stack)
    {
        var finding = Assert.Single(Collect(
            new DnsInterface("if0", ["203.0.113.5"], [], stack)));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("203.0.113.5", string.Join(" ", finding.Reasons));
        Assert.Equal(stack.ToString(), finding.Details["pile"]);
    }

    /// <summary>
    /// A mix of resolvers with one unknown among them is flagged: a single unrecognised
    /// address is enough to warrant a look, and it is the one the reason names.
    /// </summary>
    [Fact]
    public void A_mix_with_one_unrecognised_resolver_is_notable()
    {
        var finding = Assert.Single(Collect(
            new DnsInterface("if0", ["1.1.1.1", "203.0.113.5"], [], DnsStack.IPv4)));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("203.0.113.5", string.Join(" ", finding.Reasons));
        Assert.DoesNotContain("1.1.1.1", finding.Reasons.Single());
    }

    /// <summary>
    /// The same adapter under both stacks, which is how Windows keys the two subtrees: two
    /// resolver lists on one card, and the report has to keep them apart. Folding them on the
    /// identifier would have lost one of the two — and the one lost is whichever stack the
    /// fold happened to visit second.
    /// </summary>
    [Fact]
    public void One_adapter_carrying_a_resolver_on_each_stack_is_judged_twice()
    {
        var findings = Collect(
            new DnsInterface("{carte}", ["1.1.1.1"], [], DnsStack.IPv4),
            new DnsInterface("{carte}", ["2001:db8::53"], [], DnsStack.IPv6));

        Assert.All(findings, finding => Assert.Equal("{carte}", finding.Source));
        Assert.Equal(["IPv4", "IPv6"], findings.Select(finding => finding.Details["pile"]));

        Assert.Equal(
            [FindingSeverity.Benign, FindingSeverity.Notable],
            findings.Select(finding => finding.Severity));
    }

    /// <summary>An interface without resolvers produces nothing: nothing to inventory.</summary>
    [Fact]
    public void An_interface_without_resolvers_yields_nothing()
    {
        Assert.Empty(Collect(new DnsInterface("if0", [], [], DnsStack.IPv4)));
    }

    private static IReadOnlyList<Finding> Collect(DnsRead read) =>
        new DnsResolverCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            dns: new FakeDnsProvider(read)));

    /// <summary>
    /// A refused read, at the collector rather than at the provider: a hole in the audit, and
    /// the one piece of advice that repairs it.
    ///
    /// <para>
    /// <see cref="AuditGap.Refused"/> and not <see cref="AuditGap.Unreadable"/>, argued from
    /// the channel and not from the surface: the only thing under this read is
    /// <c>IRegistryProvider</c>, which catches the two denial exceptions and lets every other
    /// failure through — so <c>AccessDenied</c> here is an ACL and nothing else, and an ACL is
    /// exactly what elevating opens. Exit 3, and the sentence says the same as the number.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_dns_read_is_reported_rather_than_read_as_no_resolver()
    {
        var finding = Assert.Single(Collect(
            DnsRead.Refused([], [RegistryDnsProvider.InterfacesKey])));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal(AuditGap.Refused, finding.Gap);
        Assert.Contains("Interfaces", string.Join(" ", finding.Reasons), StringComparison.Ordinal);

        // And the same read with nothing to say, which is the only way to reach the sentence
        // the collector writes itself: a read carrying a diagnostic has it printed verbatim,
        // so the fallback — the one that names elevation — is unreachable above.
        var mute = Assert.Single(Collect(new DnsRead(ReadStatus.AccessDenied, [], null)));

        Assert.Equal(AuditGap.Refused, mute.Gap);
        Assert.Contains("administrateur", string.Join(" ", mute.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The branch no factory of this read can build, reached the way a capture reaches it —
    /// the hole #177 found on the scheduler and #179 on the firewall, closed here on the day
    /// the channel arrives rather than two issues later.
    ///
    /// <para>
    /// No producer writes <see cref="ReadStatus.Failed"/> on this channel today, the registry
    /// being the only thing under it. A capture is not built, it is deserialised field by
    /// field, and this is a shape it can hold — so the collector reads it as
    /// <see cref="AuditGap.Unreadable"/>: no console however elevated re-reads a snapshot, and
    /// advising elevation over one is the inversion CONTRIBUTING forbids.
    /// </para>
    ///
    /// <para>
    /// The pair is what makes either half a claim: this one alone is satisfied by a collector
    /// answering <c>Unreadable</c> to everything, which is what shipped once and told the
    /// reader nothing could be done about the commonest gap the tool has.
    /// </para>
    /// </summary>
    [Fact]
    public void A_dns_read_that_failed_without_being_denied_is_reported_as_itself()
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            """
            {"dns":[],"dnsStatus":"Failed",
             "dnsDiagnostic":"Interfaces DNS absentes de l'instantané."}
            """);

        var read = new SnapshotDnsProvider(snapshot).Read();

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);

        var finding = Assert.Single(Collect(read));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.DoesNotContain("administrateur", string.Join(" ", finding.Reasons),
            StringComparison.OrdinalIgnoreCase);

        // The mute half, as above: no remedy offered where there is none to offer.
        var mute = Assert.Single(Collect(new DnsRead(ReadStatus.Failed, [], null)));

        Assert.Equal(AuditGap.Unreadable, mute.Gap);
        Assert.NotEmpty(Assert.Single(mute.Reasons));
        Assert.DoesNotContain("administrateur", string.Join(" ", mute.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The four steps a field added to the snapshot has to survive, on the first of the two
    /// reads #184 gave a channel: recorded by the scan, serialised into the capture, replayed
    /// out of it, and — in <c>AnonymiserTests</c> — scrubbed.
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object, for the reason the
    /// firewall and hosts tests give in <c>SnapshotReplayTests</c>: the capture is a
    /// <em>file</em>, and a status the recorder sets but the source-generated serialiser drops
    /// would pass every in-memory assertion and still replay as a machine that resolves through
    /// nothing.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_dns_read_is_recorded_serialised_and_replayed_as_a_refusal()
    {
        // On the IPv6 stack, so the field #191 adds travels the same four steps in the same
        // test rather than in a happier one of its own: a stack recorded and dropped on the way
        // out replays as a v4 resolver, which is an address on a card the reader would go and
        // look for with the wrong command.
        var kept = new DnsInterface("{lu}", ["2001:db8::53"], [], DnsStack.IPv6);

        var snapshot = new MachineSnapshot();
        var source = new CountingDnsProvider(
            DnsRead.Refused([kept], [$@"{RegistryDnsProvider.InterfacesKeyIPv6}\{{muet}}"]));
        var recording = new RecordingDnsProvider(source, snapshot);

        recording.Read();
        recording.Read();

        // A scan walks the collectors twice; asking the registry again on the second pass
        // would make the capture depend on which pass caught the machine in a better mood.
        Assert.Equal(1, source.Calls);

        var replayed = new SnapshotDnsProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).Read();

        Assert.Equal(ReadStatus.AccessDenied, replayed.Status);
        Assert.Contains("{muet}", replayed.Diagnostic!, StringComparison.Ordinal);

        // The list as well as the status beside it. A capture that wrote the status and
        // dropped the interfaces replays as « refusé, et rien vu » — the same silence one step
        // further along, and the mutation that found this on the directory read.
        //
        // Field by field rather than by record equality: the resolver lists are compared by
        // reference there, so two identical interfaces off a round trip are never equal and
        // the assertion would be about the deserialiser rather than about the capture.
        var survivor = Assert.Single(replayed.Interfaces);
        Assert.Equal(kept.Id, survivor.Id);
        Assert.Equal(kept.StaticServers, survivor.StaticServers);
        Assert.Equal(DnsStack.IPv6, survivor.Stack);
    }

    /// <summary>
    /// The compatibility half of the stack field, asserted on the <em>value</em> a capture
    /// written before it replays as — never on the key being missing, which is the premise
    /// #163 caught going green over nothing.
    ///
    /// <para>
    /// A capture predating #191 holds interfaces and no stack, and every one of them was read
    /// from <c>Tcpip</c>: that read walked no other key. So the field has to deserialise to
    /// <see cref="DnsStack.IPv4"/> — not to « unknown », which would put a shrug on every
    /// capture on disk, and not to whichever member happens to be declared first tomorrow.
    /// </para>
    ///
    /// <para>
    /// Against a literal document rather than against the versioned fixture, and beside the
    /// test that uses the fixture: this one keeps saying what it says on the day that capture
    /// is regenerated and starts carrying a stack of its own.
    /// </para>
    /// </summary>
    [Fact]
    public void A_capture_written_before_the_stacks_replays_its_interfaces_as_IPv4()
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            """
            {"dns":[{"id":"{ancienne}","staticServers":["203.0.113.5"],"dhcpServers":[]}]}
            """);

        var iface = Assert.Single(new SnapshotDnsProvider(snapshot).Read().Interfaces);

        Assert.Equal(DnsStack.IPv4, iface.Stack);
        Assert.Equal(["203.0.113.5"], iface.StaticServers);

        // And the report says of it exactly what it said before the field existed.
        Assert.Equal("IPv4", Assert.Single(Collect(iface)).Details["pile"]);
    }

    /// <summary>
    /// The compatibility half, against a capture genuinely written before the field —
    /// <c>compromised-win11</c>, versioned, whose <c>dns</c> block is a bare array.
    ///
    /// <para>
    /// The absence of a status has to keep meaning what it meant: the interfaces were
    /// enumerated. Reading it as a refusal would put a NOTABLE on every capture older than this
    /// batch, the real-machine ones outside the repository included, and send their readers to
    /// elevate against a file already on disk — and the two resolver verdicts this fixture's
    /// golden freezes would travel with a gap they never had.
    /// </para>
    ///
    /// <para>
    /// The premise is asserted on the <em>value</em> and never on the presence of the key: the
    /// serialiser writes every field it has, so the day this capture is regenerated it will
    /// carry <c>"dnsStatus": null</c> and a « key is absent » premise would go green while
    /// proving nothing (#163).
    /// </para>
    /// </summary>
    [Fact]
    public void A_capture_written_before_the_dns_status_replays_as_the_interfaces_it_recorded()
    {
        var json = File.ReadAllText(Path.Combine(
            FixtureReplayTests.FixtureDirectory, "synthetic", "compromised-win11.capture.json"));

        using (var document = JsonDocument.Parse(json))
        {
            Assert.False(
                document.RootElement.TryGetProperty("dnsStatus", out var written)
                && written.ValueKind is not JsonValueKind.Null,
                "La fixture porte désormais un statut de lecture DNS : elle ne prouve plus la "
                + "compatibilité des captures antérieures au champ.");

            Assert.DoesNotContain(
                document.RootElement.GetProperty("dns").EnumerateArray(),
                iface => iface.TryGetProperty("stack", out _));
        }

        var read = new SnapshotDnsProvider(RempartJson.DeserialiseSnapshot(json)).Read();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Equal(2, read.Interfaces.Count);

        // The stack the interfaces of that capture were read on, and the only one the read
        // that wrote it ever walked (#191).
        Assert.All(read.Interfaces, iface => Assert.Equal(DnsStack.IPv4, iface.Stack));

        // And the collector says exactly what it said about that capture yesterday: two
        // resolver findings and no gap.
        Assert.All(Collect(read), finding => Assert.Null(finding.Gap));
    }

    /// <summary>
    /// A capture that never collected the surface. An empty, successful read — the judgement
    /// the partition guard has carried since it was written, « une machine sans interface
    /// réseau configurée existe », and the one #184 deliberately did not reopen: reversing it
    /// would put a gap on three of the four versioned captures and on every real capture
    /// predating the field.
    /// </summary>
    [Fact]
    public void A_capture_that_never_collected_dns_replays_as_the_silence_it_produced()
    {
        var read = new SnapshotDnsProvider(new MachineSnapshot()).Read();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Empty(read.Interfaces);
        Assert.Null(read.Diagnostic);
        Assert.Empty(Collect(read));
    }

    private sealed class CountingDnsProvider(DnsRead answer) : IDnsProvider
    {
        public int Calls { get; private set; }

        public DnsRead Read()
        {
            Calls++;
            return answer;
        }
    }
}

public class HostsFileTests
{
    private static IReadOnlyList<Finding> Collect(params string[] lines) =>
        new HostsFileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            hostsFile: new FakeHostsFileProvider(lines)));

    /// <summary>The default hosts file has nothing but comments: nothing to flag.</summary>
    [Fact]
    public void A_default_hosts_file_yields_nothing()
    {
        Assert.Empty(Collect("# Copyright", "#", "# 102.54.94.97   rhino.acme.com", "   "));
    }

    /// <summary>
    /// A redirect to a routable address short-circuits DNS toward a chosen machine:
    /// each one is flagged individually.
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
    /// Redirecting a sensitive domain — an update, an authentication — is suspicious:
    /// it is the very shape of a hijack.
    /// </summary>
    [Fact]
    public void A_redirect_of_a_sensitive_domain_is_suspicious()
    {
        var finding = Assert.Single(Collect("93.184.216.34  windowsupdate.microsoft.com"));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    /// <summary>
    /// Blocking entries number in the thousands in an ad-blocking list: they are
    /// aggregated into a single finding, with their count.
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
    /// Neutralising an update or a protection is no harmless tweak: preventing a fix is
    /// a manoeuvre, and the aggregate then escalates to suspicious.
    /// </summary>
    [Fact]
    public void Blocking_a_critical_domain_escalates_to_suspicious()
    {
        var findings = Collect(
            "0.0.0.0  ads.example.com",
            "0.0.0.0  update.microsoft.com");

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(findings).Severity);
    }

    /// <summary>One line can point several hosts at one address: each of them counts.</summary>
    [Fact]
    public void Multiple_hosts_on_one_line_each_count()
    {
        var findings = Collect("0.0.0.0  a.example.com b.example.com c.example.com");

        Assert.Equal("3", Assert.Single(findings).Details["domaines"]);
    }

    /// <summary>A trailing comment is stripped before analysis.</summary>
    [Fact]
    public void An_inline_comment_is_stripped()
    {
        var finding = Assert.Single(Collect("93.184.216.34  example.com  # test local"));

        Assert.Equal("example.com", finding.Details["domaine"]);
    }

    private static IReadOnlyList<Finding> Collect(HostsFileRead read) =>
        new HostsFileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            hostsFile: new FakeHostsFileProvider(read)));

    /// <summary>
    /// A <c>hosts</c> file the read was refused. Denying read access to it is the very
    /// technique that protects a redirection already in place, and it produced the same
    /// empty list as the comment-only file Windows ships — so the collector reported
    /// nothing, <c>CriticalFragments</c> included.
    ///
    /// <para>
    /// <c>Refused</c> and not <c>Failed</c> since #173, and the rename is why this guard had
    /// to be reread: the factory it called kept its name and changed its meaning underneath
    /// it, so REV-12's own test walked the failure branch and became a second copy of
    /// <see cref="A_failure_that_is_not_a_denial_is_reported_as_itself"/> with a different
    /// string. Its assertions could not have noticed — a severity both branches share and a
    /// sentence the test itself planted. What separates the two is the value the collector
    /// <em>chose</em>, so that is what each of them now asserts.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_hosts_file_is_reported_rather_than_read_as_no_entry()
    {
        var finding = Assert.Single(Collect(
            HostsFileRead.Refused("Fichier hosts illisible : accès refusé.")));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal(AuditGap.Refused, finding.Gap);
        Assert.Contains("accès refusé", string.Join(" ", finding.Reasons), StringComparison.Ordinal);

        // And the same read with nothing to say, which is the only way to reach the sentence
        // the collector writes itself: a read carrying a diagnostic has it printed verbatim,
        // so the fallback — the one that names elevation — is unreachable above.
        var mute = Assert.Single(Collect(new HostsFileRead(ReadStatus.AccessDenied, [], null)));

        Assert.Equal(AuditGap.Refused, mute.Gap);
        Assert.Contains("administrateur", string.Join(" ", mute.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The other half of the sentence the class summary used to assume. « Pas de fichier
    /// hosts » really is « aucune entrée » — a machine without one resolves through DNS
    /// alone, which is what an empty file means too. Only the <em>refusal</em> was wrongly
    /// folded into it.
    /// </summary>
    [Fact]
    public void An_absent_hosts_file_stays_silent()
    {
        Assert.Empty(Collect(HostsFileRead.Absent));
    }

    /// <summary>
    /// A read that failed without being refused. <c>File.ReadAllLines</c> throws
    /// <c>IOException</c> on a file held open exclusively — which malware does as readily as
    /// it sets an ACL — and calling that « accès refusé » is the invariant CONTRIBUTING
    /// records, paid for once already by two milestones of a mute WMI.
    ///
    /// <para>
    /// The pair of the guard above, and only the pair is a claim: this one alone is satisfied
    /// by a collector that answers <see cref="AuditGap.Unreadable"/> to everything, which is
    /// the shape that shipped once and told the reader nothing could be done about the
    /// commonest gap the tool has.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failure_that_is_not_a_denial_is_reported_as_itself()
    {
        var finding = Assert.Single(Collect(
            HostsFileRead.Failed("Fichier hosts illisible : le fichier est ouvert en exclusif.")));

        var reasons = string.Join(" ", finding.Reasons);
        Assert.Equal(AuditGap.Unreadable, finding.Gap);
        Assert.Contains("exclusif", reasons, StringComparison.Ordinal);
        Assert.DoesNotContain("accès refusé", reasons, StringComparison.Ordinal);

        // The mute half, as above: no remedy offered where there is none to offer, and this is
        // the only read that reaches the collector's own sentence to check it.
        var mute = Assert.Single(Collect(new HostsFileRead(ReadStatus.Failed, [], null)));

        Assert.Equal(AuditGap.Unreadable, mute.Gap);
        Assert.NotEmpty(mute.Reasons);
        Assert.DoesNotContain("administrateur", string.Join(" ", mute.Reasons),
            StringComparison.OrdinalIgnoreCase);
    }
}
