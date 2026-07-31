using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// The capture path of the four status-carrying reads, now written once in
/// <see cref="StatusChannel"/> and therefore worth testing once — properly.
///
/// <para>
/// It was copied four times before, and the fixtures only ever exercised three of its
/// branches: the versioned captures carry a <c>Found</c> status, a list with no status at
/// all, or nothing. <b>None of them carries a recorded failure</b>, which is the branch the
/// whole channel exists for — a capture taken while WMI was mute has to replay as « je n'ai
/// pas pu regarder », never as a machine with no driver loaded. Four copies of an untested
/// branch is what DET-RECPROV costs in practice; one copy with a test is what replaces it.
/// </para>
///
/// <para>
/// The reads are exercised through their real providers rather than through
/// <c>StatusChannel</c> directly. Calling the generic helper with hand-made arguments would
/// prove the helper agrees with itself; going through <c>SnapshotDriverProvider</c> proves
/// the driver surface still answers what phase 2 decided it should.
/// </para>
/// </summary>
public sealed class StatusChannelTests
{
    private static readonly LoadedDriver Driver = new("syndrv64", @"C:\Windows\System32\drivers\x.sys");

    /// <summary>
    /// Whether a versioned capture really carries something under <paramref name="name"/>, as
    /// opposed to merely having the key.
    ///
    /// <para>
    /// Every compatibility test below rests on the same premise — this fixture predates a
    /// field — and the only durable way to state it is on the <em>value</em>.
    /// <see cref="RempartJsonContext"/> is declared
    /// <c>DefaultIgnoreCondition = JsonIgnoreCondition.Never</c>, so the serialiser writes
    /// every field of every object handed to it, and the next run of
    /// <c>scripts/regenerate-fixtures.ps1</c> — prescribed by CONTRIBUTING after any change to
    /// the rule catalogue — rewrites these captures with the key present and empty. Measured
    /// by running <c>rempart synthesise</c> over both fixtures: <c>"diagnostic": null</c>,
    /// <c>"gaps": null</c>, <c>"hostsFileStatus": null</c> and
    /// <c>"registryListsStatus": {}</c>. A premise reading <c>TryGetProperty</c> alone goes
    /// red there on files whose meaning has not changed — measured too: it fails these four
    /// tests and no other, out of 953 — in the middle of an unrelated pull request, and the
    /// only obvious gesture is to delete the assertion, which is the premise that made the
    /// replay test worth running (issue #163).
    /// </para>
    ///
    /// <para>
    /// The rule, and the only one that generalises: a shape carries nothing when it
    /// deserialises to exactly what an <em>absent</em> key deserialises to. Null qualifies,
    /// and so does an empty map, a non-nullable <c>Dictionary</c> property being left on its
    /// <c>[]</c> initialiser either way — which is why the map shape is needed at all, such a
    /// property never being written null. Every other shape counts as something, so the day a
    /// capture does record a status these tests go red and say they have stopped being
    /// evidence about the captures that could not.
    /// </para>
    ///
    /// <para>
    /// An empty <em>array</em> deliberately does not qualify, and the difference is not
    /// cosmetic: every collection these five fields deserialise into is nullable, so <c>[]</c>
    /// arrives as an empty list where an absent key arrives as null. Measured rather than
    /// assumed — planting <c>"gaps": []</c> in a fixture and answering <c>false</c> here lets
    /// the premise stand and moves the red one line down onto
    /// <c>Assert.Null(read.Gaps)</c>, which is the same test failing with nothing to say. The
    /// case is pinned below so that answering <c>false</c> for it is a red with this reason
    /// attached rather than a plausible-looking one-line edit.
    /// </para>
    /// </summary>
    private static bool Carries(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var written) && written.ValueKind switch
        {
            JsonValueKind.Null => false,
            JsonValueKind.Object => written.EnumerateObject().Any(),
            _ => true,
        };

    /// <summary>
    /// The reading the five premises rest on, pinned shape by shape — because a premise that
    /// cannot itself be wrong is a premise nobody checks. Every branch of the switch above is
    /// exercised here, the catch-all included, so neither widening it nor narrowing it is a
    /// silent edit.
    ///
    /// <para>
    /// Narrowed back to the presence of the key, this goes red on <c>nul</c> — the absent key
    /// above it still reads false, <c>TryGetProperty</c> being right about that one and only
    /// that one, which is exactly why the bug of #163 was invisible: the shape a premise was
    /// written against is the one shape the broken reading gets right.
    /// </para>
    /// </summary>
    [Fact]
    public void A_key_written_empty_carries_no_more_than_a_key_that_is_absent()
    {
        using var document = JsonDocument.Parse(
            """
            {"nul":null,"carteVide":{},"statut":"Found","tableauVide":[],
             "carteRemplie":{"HKLM\\Run":"AccessDenied"},"texte":"Pare-feu non lu.",
             "tableauRempli":[{"chemin":"\\Microsoft"}]}
            """);

        var root = document.RootElement;

        // The shapes a regeneration writes for a field no capture recorded. All of them
        // replay as the absent key does, so all of them leave the premise standing.
        Assert.False(Carries(root, "jamaisEcrit"));
        Assert.False(Carries(root, "nul"));
        Assert.False(Carries(root, "carteVide"));

        // And what a capture that really recorded something looks like.
        Assert.True(Carries(root, "statut"));
        Assert.True(Carries(root, "carteRemplie"));
        Assert.True(Carries(root, "texte"));

        // An empty array is on this side of the line, not the one above: the list-typed
        // fields these premises read are nullable, so [] is an empty list and not the null an
        // absent key gives. See the reason on Carries — answering false here hides the change
        // from the premise and lets the same test fail one line later instead.
        Assert.True(Carries(root, "tableauVide"));
        Assert.True(Carries(root, "tableauRempli"));
    }

    /// <summary>
    /// The branch no fixture covers, on the surface it was written for. A capture taken on a
    /// machine whose WMI answered nothing recorded <c>AccessDenied</c> and an empty list;
    /// replaying that as <c>Found</c> would turn a machine nobody could audit into a machine
    /// with a clean kernel — DET-WMI-MUET, in the one direction its own fixtures cannot show.
    /// </summary>
    [Fact]
    public void A_recorded_failure_replays_as_a_failure_and_not_as_an_empty_machine()
    {
        var snapshot = new MachineSnapshot
        {
            Drivers = [],
            DriversStatus = ReadStatus.AccessDenied,
            DriversDiagnostic = "WMI n'a rendu aucune ligne.",
        };

        var read = new SnapshotDriverProvider(snapshot).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Equal("WMI n'a rendu aucune ligne.", read.Diagnostic);
        Assert.Empty(read.Drivers);
    }

    /// <summary>
    /// A partial read keeps what it got. The listening tables are read four times over
    /// (TCP/UDP × IPv4/IPv6) and fail one at a time, so dropping the endpoints that were read
    /// because one table refused would trade one silence for another.
    /// </summary>
    [Fact]
    public void A_recorded_partial_read_keeps_its_endpoints_and_its_diagnostic()
    {
        var snapshot = new MachineSnapshot
        {
            ListeningPorts = [new ListeningPort("TCP", "0.0.0.0", 445, 4)],
            ListeningPortsStatus = ReadStatus.AccessDenied,
            ListeningPortsDiagnostic = "Table TCP6 illisible.",
        };

        var read = new SnapshotListeningPortProvider(snapshot).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Equal("Table TCP6 illisible.", read.Diagnostic);
        Assert.Equal(445, Assert.Single(read.Ports).Port);
    }

    /// <summary>
    /// A capture predating the status field: a list and nothing else. Read as the success it
    /// was taken to be, which is the best available reading of what it recorded — inventing a
    /// failure would make every capture older than DET-WMI-MUET report a broken machine.
    /// </summary>
    [Fact]
    public void A_list_recorded_without_a_status_replays_as_the_success_it_was_taken_to_be()
    {
        var read = new SnapshotDriverProvider(new MachineSnapshot { Drivers = [Driver] })
            .Enumerate();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Equal("syndrv64", Assert.Single(read.Drivers).Name);
    }

    /// <summary>
    /// The asymmetry phase 2 settled, and the one thing a shared shape must not flatten: a
    /// surface never collected answers differently depending on whether zero could be true.
    /// Both halves in one test, because it is the <em>difference</em> that is the invariant —
    /// asserting them apart would let someone align them without failing anything.
    /// </summary>
    [Fact]
    public void An_uncollected_surface_answers_by_whether_zero_could_have_been_true()
    {
        var empty = new MachineSnapshot();

        // No machine that is switched on runs zero drivers or zero processes: silence there
        // can only ever be a failure to look, and it is said out loud.
        Assert.Equal(ReadStatus.AccessDenied, new SnapshotDriverProvider(empty).Enumerate().Status);
        Assert.Equal(ReadStatus.AccessDenied, new SnapshotProcessProvider(empty).Enumerate().Status);
        Assert.Equal(ReadStatus.AccessDenied,
            new SnapshotListeningPortProvider(empty).Enumerate().Status);

        // Zero browser extension is an ordinary state of an ordinary machine, so the same
        // absence is an answer rather than a failure. Flagging it would cry wolf.
        var extensions = new SnapshotBrowserExtensionProvider(empty).Read();
        Assert.Equal(ReadStatus.Found, extensions.Status);
        Assert.Empty(extensions.Extensions);
        Assert.Null(extensions.Diagnostic);
    }

    /// <summary>
    /// The recording half: the three fields are written beside each other, and the surface is
    /// asked exactly once. A capture is produced by a scan that walks the collectors twice
    /// (run, then prefetch); querying again on the second pass would make the snapshot depend
    /// on which pass caught the machine in a better mood, and a fixture that is not the same
    /// twice is not a fixture.
    /// </summary>
    [Fact]
    public void Recording_asks_the_machine_once_and_writes_the_status_beside_the_list()
    {
        var snapshot = new MachineSnapshot();
        var source = new CountingDriverProvider(DriverRead.Failed("WMI muet."));
        var recording = new RecordingDriverProvider(source, snapshot);

        var first = recording.Enumerate();
        var second = recording.Enumerate();

        Assert.Equal(1, source.Calls);

        Assert.Equal(ReadStatus.AccessDenied, snapshot.DriversStatus);
        Assert.Equal("WMI muet.", snapshot.DriversDiagnostic);
        Assert.NotNull(snapshot.Drivers);

        // The second call rebuilds the read from the snapshot: it has to be the same answer,
        // otherwise the capture and the scan that produced it would disagree.
        Assert.Equal(first.Status, second.Status);
        Assert.Equal(first.Diagnostic, second.Diagnostic);
    }

    private const string Startup =
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";

    /// <summary>
    /// The same three-way reading on the fifth read, which is the only one keyed by an
    /// argument (DET-FICHIERS-MUET). Three snapshot maps instead of three properties, so the
    /// branch worth checking is that the status still travels with <em>its own</em> directory
    /// rather than with the snapshot as a whole.
    /// </summary>
    [Fact]
    public void A_refused_directory_replays_as_refused_and_not_as_an_empty_folder()
    {
        var snapshot = new MachineSnapshot
        {
            Directories = { [Startup] = [] },
            DirectoriesStatus = { [Startup] = ReadStatus.AccessDenied },
            DirectoriesDiagnostic = { [Startup] = "Dossier illisible : accès refusé." },
        };

        var read = new SnapshotFileSystemProvider(snapshot).ListFiles(Startup);

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Equal("Dossier illisible : accès refusé.", read.Diagnostic);
        Assert.Empty(read.Files);
    }

    /// <summary>
    /// The branch every capture taken before this batch sits in: a listing and no status.
    /// Read as the success it was taken to be — <c>tests/fixtures/local/</c> holds exactly
    /// this shape, and inventing a refusal for it would make a real capture report two
    /// unreadable startup folders that were read perfectly well.
    /// </summary>
    [Fact]
    public void A_directory_recorded_without_a_status_replays_as_the_success_it_was_taken_to_be()
    {
        var snapshot = new MachineSnapshot
        {
            Directories = { [Startup] = [$@"{Startup}\desktop.ini"] },
        };

        var read = new SnapshotFileSystemProvider(snapshot).ListFiles(Startup);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Equal($@"{Startup}\desktop.ini", Assert.Single(read.Files));
    }

    /// <summary>
    /// A directory the capture holds nothing about. A speaking state and not an empty listing,
    /// for the reason the debt was opened over: the replay would otherwise conclude « aucun
    /// autorun » about a folder this capture never walked. Not <c>NotFound</c> either — that
    /// would claim the folder was missing from the machine, which is a fact the capture never
    /// recorded.
    ///
    /// <para>
    /// <c>Failed</c> since #173, and the change is the assertion catching up with what was
    /// always meant. This read was <c>AccessDenied</c> because that was the only speaking state
    /// the channel had, and the summary here argued only against the other two. Nobody denied
    /// anything: a snapshot with no entry at this path is a capture that never walked it, and
    /// no console however elevated re-walks a file on disk.
    /// </para>
    /// </summary>
    [Fact]
    public void A_directory_absent_from_a_capture_is_not_a_directory_that_was_empty()
    {
        var read = new SnapshotFileSystemProvider(new MachineSnapshot()).ListFiles(Startup);

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Empty(read.Files);
        Assert.Contains(Startup, read.Diagnostic ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// The recording half, per directory. Two things at once, and both matter: the folder is
    /// asked once (a scan walks the collectors twice, and a fixture that is not the same
    /// twice is not a fixture), and the failure of one folder does not follow the other into
    /// the capture — the maps are keyed, so a single status for the whole set would have to
    /// lie about one of them.
    /// </summary>
    [Fact]
    public void Recording_writes_one_status_per_directory_and_asks_each_one_once()
    {
        const string Other = @"C:\Users\anon\Startup";

        var snapshot = new MachineSnapshot();
        var source = new CountingFileSystemProvider(new Dictionary<string, DirectoryRead>
        {
            // Refused, as the sentence beside it has always said. It read Failed until #173,
            // when that factory stopped meaning a denial.
            [Startup] = DirectoryRead.Refused("Accès refusé."),
            [Other] = DirectoryRead.Found([$@"{Other}\app.lnk"]),
        });
        var recording = new RecordingFileSystemProvider(source, snapshot);

        recording.ListFiles(Startup);
        recording.ListFiles(Other);
        var again = recording.ListFiles(Startup);

        Assert.Equal(2, source.Calls);

        Assert.Equal(ReadStatus.AccessDenied, snapshot.DirectoriesStatus[Startup]);
        Assert.Equal("Accès refusé.", snapshot.DirectoriesDiagnostic[Startup]);
        Assert.Empty(snapshot.Directories[Startup]);

        Assert.Equal(ReadStatus.Found, snapshot.DirectoriesStatus[Other]);
        Assert.DoesNotContain(Other, snapshot.DirectoriesDiagnostic.Keys);

        // The listing itself, and not only the status beside it. A capture that wrote the
        // status and dropped the files replays as « lu, et vide » — the very silence this
        // channel was added to remove, one step further along. Found by mutation: removing
        // this write broke nothing, because the recorded status alone was enough to stop the
        // provider re-asking.
        Assert.Equal($@"{Other}\app.lnk", Assert.Single(snapshot.Directories[Other]));

        // The second ask rebuilds from the snapshot: the capture and the scan that produced
        // it have to say the same thing.
        Assert.Equal(ReadStatus.AccessDenied, again.Status);
        Assert.Equal("Accès refusé.", again.Diagnostic);
    }

    private const string Refused = "Pare-feu non lu : règles locales.";

    /// <summary>
    /// The firewall's own version of the branch above, and the four steps a field added to
    /// the snapshot has to survive: recorded by the scan, serialised into the capture,
    /// replayed out of it, and — next door in <c>AnonymiserTests</c> — scrubbed. This
    /// repository has already shipped three of those four.
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object, and that is the
    /// point of the test: the capture is a <em>file</em>. A property the recorder sets and
    /// the source-generated serialiser does not carry would pass every in-memory assertion
    /// and still reach the replay as « lu », which is the exact failure being closed.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_firewall_read_is_recorded_serialised_and_replayed_as_refused()
    {
        var snapshot = new MachineSnapshot();
        var source = new CountingFirewallProvider(FirewallState.Failed(Refused));
        var recording = new RecordingFirewallProvider(source, snapshot);

        var first = recording.Read();
        recording.Read();

        // A scan walks the collectors twice; asking the machine again on the second pass
        // would make the capture depend on which pass caught it in a better mood.
        Assert.Equal(1, source.Calls);
        Assert.False(first.Readable);
        Assert.Equal(Refused, snapshot.Firewall!.Diagnostic);

        var replayed = new SnapshotFirewallProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).Read();

        Assert.False(replayed.Readable);
        Assert.Equal(Refused, replayed.Diagnostic);
        Assert.Equal(FirewallReachability.Unknown,
            replayed.InboundReachability("TCP", 4444, null));
    }

    /// <summary>
    /// The compatibility half, against a capture that really was written before the field
    /// existed — <c>compromised-win11</c>, versioned, whose <c>firewall</c> block carries
    /// rules and <c>readable</c> and nothing else.
    ///
    /// <para>
    /// The absence of the new field has to mean exactly what the old behaviour meant: read,
    /// nothing to report. Inventing a refusal for it would turn every capture older than
    /// this batch into a machine whose firewall nobody could see, and the fixture's own
    /// reachability verdicts — the ones its golden freezes — would go with it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_firewall_captured_before_the_diagnostic_existed_replays_as_read()
    {
        var json = File.ReadAllText(Path.Combine(
            FixtureReplayTests.FixtureDirectory, "synthetic", "compromised-win11.capture.json"));

        using (var document = JsonDocument.Parse(json))
        {
            // The premise of the test, asserted rather than assumed: the day this capture is
            // regenerated with a diagnostic, it stops being evidence about older ones. On the
            // value and never on the key — see Carries.
            Assert.False(
                Carries(document.RootElement.GetProperty("firewall"), "diagnostic"),
                "La fixture porte désormais un diagnostic : elle ne prouve plus la "
                + "compatibilité des captures antérieures au champ.");
        }

        var read = new SnapshotFirewallProvider(RempartJson.DeserialiseSnapshot(json)).Read();

        Assert.True(read.Readable);
        Assert.Null(read.Diagnostic);
        Assert.NotEmpty(read.Rules);
        Assert.Equal(FirewallReachability.Reachable, read.InboundReachability("TCP", 4444, null));
    }

    private static readonly TaskFolderGap Gap =
        TaskFolderGap.Of(@"\Microsoft\Windows\UpdateOrchestrator", "GetTasks",
            unchecked((int)0x80070005));

    /// <summary>
    /// The scheduler's version of the partial branch, and the four steps a field added to
    /// the snapshot has to survive: recorded by the scan, serialised into the capture,
    /// replayed out of it, and — next door in <c>AnonymiserTests</c> — scrubbed.
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object: the capture is a
    /// <em>file</em>, and a field the recorder sets but the source-generated serialiser does
    /// not carry would pass every in-memory assertion and still reach the replay as a walk
    /// that lost nothing. The read is stored whole here, unlike the five loose-field ones
    /// above, so nothing in the recording path had to change for this — which is precisely
    /// what an assertion is for.
    /// </para>
    /// </summary>
    [Fact]
    public void A_partial_task_walk_is_recorded_serialised_and_replayed_with_its_gaps()
    {
        var task = new ScheduledTask(
            @"\Perso", "Perso", Enabled: true, "ready", null, null, null, []);

        var snapshot = new MachineSnapshot();
        var source = new CountingScheduledTaskProvider(ScheduledTaskRead.Partial([task], [Gap]));
        var recording = new RecordingScheduledTaskProvider(source, snapshot);

        var first = recording.Enumerate();
        recording.Enumerate();

        // A scan walks the collectors twice; asking the scheduler again on the second pass
        // would make the capture depend on which pass caught the machine in a better mood.
        Assert.Equal(1, source.Calls);
        Assert.Equal(ReadStatus.AccessDenied, first.Status);

        var replayed = new SnapshotScheduledTaskProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, replayed.Status);
        Assert.Equal(@"\Perso", Assert.Single(replayed.Tasks).Path);
        Assert.Equal(Gap, Assert.Single(replayed.Gaps!));
    }

    /// <summary>
    /// The compatibility half, against a capture genuinely written before the field —
    /// <c>default-win11</c>, versioned, whose <c>scheduledTasks</c> block carries a status,
    /// a list and a diagnostic and nothing else.
    ///
    /// <para>
    /// The absence of the new field has to mean exactly what the old behaviour meant: the
    /// walk lost nothing. Reading it as an unknown gap would turn every capture older than
    /// this batch into a machine whose scheduler was half refused, and put a NOTABLE on the
    /// two hundred tasks its golden freezes.
    /// </para>
    /// </summary>
    [Fact]
    public void A_walk_captured_before_the_gaps_existed_replays_as_one_that_lost_nothing()
    {
        var json = File.ReadAllText(Path.Combine(
            FixtureReplayTests.FixtureDirectory, "synthetic", "default-win11.capture.json"));

        using (var document = JsonDocument.Parse(json))
        {
            // The premise of the test, asserted rather than assumed: the day this capture is
            // regenerated with gaps, it stops being evidence about older ones. On the value
            // and never on the key — see Carries.
            Assert.False(
                Carries(document.RootElement.GetProperty("scheduledTasks"), "gaps"),
                "La fixture porte désormais des lacunes de parcours : elle ne prouve plus la "
                + "compatibilité des captures antérieures au champ.");
        }

        var read = new SnapshotScheduledTaskProvider(
            RempartJson.DeserialiseSnapshot(json)).Enumerate();

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Gaps);
        Assert.NotEmpty(read.Tasks);
    }

    /// <summary>
    /// The <c>hosts</c> file, sixth read to take this channel, through the same four steps:
    /// recorded by the scan, serialised into the capture, replayed out of it, and — in
    /// <c>AnonymiserTests</c> — scrubbed.
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object, for the reason the
    /// scheduler test gives: the capture is a <em>file</em>, and a status the recorder sets
    /// but the source-generated serialiser drops would pass every in-memory assertion and
    /// still replay as a file with no entry in it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_hosts_read_is_recorded_serialised_and_replayed_as_a_refusal()
    {
        var snapshot = new MachineSnapshot();
        var source = new CountingHostsFileProvider(
            HostsFileRead.Refused("Fichier hosts illisible : accès refusé."));
        var recording = new RecordingHostsFileProvider(source, snapshot);

        recording.ReadLines();
        recording.ReadLines();

        // A scan walks the collectors twice; asking the disk again on the second pass would
        // make the capture depend on which pass caught the machine in a better mood.
        Assert.Equal(1, source.Calls);

        var replayed = new SnapshotHostsFileProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).ReadLines();

        Assert.Equal(ReadStatus.AccessDenied, replayed.Status);
        Assert.Equal("Fichier hosts illisible : accès refusé.", replayed.Diagnostic);
        Assert.Empty(replayed.Lines);
    }

    /// <summary>
    /// The other half of the split, through the same file round trip: a read that failed
    /// without being denied has to come back <em>as a failure</em>, not as the denial it was
    /// indistinguishable from until #173.
    ///
    /// <para>
    /// Written because <see cref="ReadStatus.Failed"/> is a new value of a field a capture
    /// already stores, and a value the source-generated serialiser cannot write is a value the
    /// replay silently downgrades. That is the whole class of defect this file exists for —
    /// the status set in memory, dropped on the way to disk, and the machine replaying as one
    /// that answered. The assertion is on the <em>value</em> of the field, never on the key
    /// being present, so the capture stays the contract.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failed_hosts_read_is_recorded_serialised_and_replayed_as_a_failure()
    {
        const string Reason = "Fichier hosts illisible : le fichier est ouvert en exclusif.";

        var snapshot = new MachineSnapshot();
        var recording = new RecordingHostsFileProvider(
            new CountingHostsFileProvider(HostsFileRead.Failed(Reason)), snapshot);

        recording.ReadLines();

        var replayed = new SnapshotHostsFileProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).ReadLines();

        Assert.Equal(ReadStatus.Failed, replayed.Status);
        Assert.Equal(Reason, replayed.Diagnostic);
        Assert.Empty(replayed.Lines);

        // The point of the pair: a capture of a locked file must not replay as one telling its
        // reader to re-run elevated.
        Assert.NotEqual(ReadStatus.AccessDenied, replayed.Status);
    }

    /// <summary>
    /// The compatibility half, against a capture genuinely written before the field.
    /// <c>default-win11</c> carries <c>hostsFile</c> and nothing beside it, and the absence
    /// of a status has to mean exactly what it meant yesterday: a file with no entry in it,
    /// which is the ordinary state of Windows and the reason this read is allowed to be
    /// silent about zero.
    /// </summary>
    [Fact]
    public void A_capture_written_before_the_hosts_status_replays_as_a_file_with_no_entry()
    {
        var json = File.ReadAllText(Path.Combine(
            FixtureReplayTests.FixtureDirectory, "synthetic", "default-win11.capture.json"));

        using (var document = JsonDocument.Parse(json))
        {
            // The premise of the test, asserted rather than assumed: the day this capture is
            // regenerated with a status, it stops being evidence about older ones. On the
            // value and never on the key — see Carries.
            Assert.False(Carries(document.RootElement, "hostsFileStatus"),
                "La fixture porte désormais un statut de lecture du fichier hosts : elle ne "
                + "prouve plus la compatibilité des captures antérieures au champ.");
        }

        var read = new SnapshotHostsFileProvider(
            RempartJson.DeserialiseSnapshot(json)).ReadLines();

        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Empty(read.Lines);
    }

    /// <summary>
    /// The WMI read's version of the partial branch, through the same four steps: recorded by
    /// the scan, serialised into the capture, replayed out of it, and — next door in
    /// <c>AnonymiserTests</c> — scrubbed.
    ///
    /// <para>
    /// No field was added for it, and that is what this checks. <c>WmiRead</c> already
    /// carried a status, a list and a diagnostic; what is new is the <em>combination</em> —
    /// a failed status beside a non-empty list, which no capture written before this could
    /// hold, because a diagnostic implied an empty list by construction. The three keys are
    /// serialised individually today and that says nothing about the trio surviving
    /// together, which is precisely the branch a truncated enumeration lands in.
    /// </para>
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object, for the reason the
    /// scheduler test gives: the capture is a <em>file</em>.
    /// </para>
    /// </summary>
    [Fact]
    public void A_truncated_wmi_walk_is_recorded_serialised_and_replayed_with_its_instances()
    {
        const string Namespace = @"root\CIMV2";
        const string Class = "Win32_SystemDriver";
        string[] properties = ["Name"];

        const string Reason =
            "L'énumération WMI de Win32_SystemDriver s'est interrompue sur 0x80041004 "
            + "après 1 instance(s) : l'inventaire est incomplet.";

        var snapshot = new MachineSnapshot();
        var source = new CountingWmiProvider(WmiRead.Partial(
            [
                new WmiInstance(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Name"] = "pilote",
                }),
            ],
            Reason));

        var first = new RecordingWmiProvider(source, snapshot).Query(Namespace, Class, properties);

        Assert.Equal(1, source.Calls);
        Assert.Equal(ReadStatus.AccessDenied, first.Status);

        var replayed = new SnapshotWmiProvider(
                RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot)))
            .Query(Namespace, Class, properties);

        Assert.Equal(ReadStatus.AccessDenied, replayed.Status);
        Assert.Equal(Reason, replayed.Diagnostic);
        Assert.Equal("pilote", Assert.Single(replayed.Instances).Find("Name"));
    }

    /// <summary>
    /// The compatibility half, on a versioned capture that really predates any of this.
    /// <c>default-win11</c> holds eight <c>wmi</c> entries, and the three that came back with
    /// nothing — one refusal on <c>Win32_EncryptableVolume</c>, two absences under
    /// <c>root\subscription</c> — record their status with an empty list and a null
    /// diagnostic, the only shape this read could take before a walk was allowed to come back
    /// half-done. The premise below is asserted over all eight rather than over the one the
    /// test then reads, so a capture regenerated with a fourth does not slip past it.
    /// </summary>
    [Fact]
    public void A_wmi_read_captured_before_partial_existed_replays_exactly_as_recorded()
    {
        var json = File.ReadAllText(Path.Combine(
            FixtureReplayTests.FixtureDirectory, "synthetic", "default-win11.capture.json"));

        using (var document = JsonDocument.Parse(json))
        {
            // The premise, asserted rather than assumed: the day this capture is regenerated
            // with a truncated walk in it, it stops being evidence about older ones.
            Assert.DoesNotContain(
                document.RootElement.GetProperty("wmi").EnumerateObject(),
                entry => entry.Value.GetProperty("status").GetString() != "Found"
                    && entry.Value.GetProperty("instances").GetArrayLength() > 0);
        }

        var wmi = new SnapshotWmiProvider(RempartJson.DeserialiseSnapshot(json));

        // A recorded failure: still a failure, still empty, still without a diagnostic —
        // inventing one would put a NOTABLE on every capture older than this batch.
        var denied = wmi.Query(
            @"root\CIMV2\Security\MicrosoftVolumeEncryption",
            "Win32_EncryptableVolume",
            ["ProtectionStatus"]);

        Assert.Equal(ReadStatus.AccessDenied, denied.Status);
        Assert.Empty(denied.Instances);
        Assert.Null(denied.Diagnostic);

        // And a recorded success keeps every instance it recorded.
        var services = wmi.Query(@"root\CIMV2", "Win32_Service", ["Name", "PathName"]);

        Assert.Equal(ReadStatus.Found, services.Status);
        Assert.NotEmpty(services.Instances);
    }

    private sealed class CountingWmiProvider(WmiRead answer) : IWmiProvider
    {
        public int Calls { get; private set; }

        public WmiRead Query(
            string namespacePath, string className, IReadOnlyList<string> properties)
        {
            Calls++;
            return answer;
        }
    }

    private const string ServiceFailure =
        "OpenSCManager : erreur Win32 1722 (Le serveur RPC n'est pas disponible.)";

    /// <summary>
    /// The service control manager, seventh read to take this channel, through the four
    /// steps a field added to the snapshot has to survive: recorded by the scan, serialised
    /// into the capture, replayed out of it, and — next door in <c>AnonymiserTests</c> —
    /// scrubbed.
    ///
    /// <para>
    /// Through <see cref="RempartJson"/> rather than against the object, for the reason the
    /// scheduler test gives: the capture is a <em>file</em>, and a field the recorder sets
    /// but the source-generated serialiser drops would pass every in-memory assertion and
    /// still replay as the bare refusal it used to be. Nothing in the recording path had to
    /// change for this — <c>RecordingServiceStateProvider</c> stores the read whole — which
    /// is exactly the claim an assertion is worth making.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failed_service_read_is_recorded_serialised_and_replayed_with_its_reason()
    {
        var snapshot = new MachineSnapshot();
        var recording = new RecordingServiceStateProvider(
            new FixedServiceStateProvider(ServiceRead.Failed(ServiceFailure)), snapshot);

        Assert.Equal(ReadStatus.AccessDenied, recording.Read("mpssvc").Status);

        var replayed = new SnapshotServiceStateProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot))).Read("mpssvc");

        Assert.Equal(ReadStatus.AccessDenied, replayed.Status);
        Assert.Equal(ServiceFailure, replayed.Diagnostic);
        Assert.Null(replayed.Info);

        // And the refusal beside it, which must stay bare: a diagnostic invented for it
        // would say « ce n'est pas un refus » about a read that is one.
        var refused = new MachineSnapshot();
        new RecordingServiceStateProvider(
            new FixedServiceStateProvider(ServiceRead.AccessDenied), refused).Read("mpssvc");

        Assert.Null(new SnapshotServiceStateProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(refused)))
            .Read("mpssvc").Diagnostic);
    }

    /// <summary>
    /// The compatibility half: no versioned capture records a failure under <c>services</c>,
    /// and every entry has to replay as exactly what it recorded. A diagnostic that is not
    /// there means « no failure was noted », which is all any older capture could ever have
    /// meant.
    ///
    /// <para>
    /// The premise is asserted on the <em>value</em> and not on the presence of the key, and
    /// the difference is the whole reliability of this test — see <see cref="Carries"/>, which
    /// is where that reading now lives for all five premises of this file rather than being
    /// spelled out once per test and got right only here.
    /// </para>
    ///
    /// <para>
    /// What it cannot prove is stated rather than implied: no versioned capture holds a
    /// <em>refused</em> service, so the branch where the distinction bites is covered by the
    /// round trip above and not by a file. The fixtures do carry the two shapes that decide
    /// every shipped <c>type: service</c> rule — a service read, and one that is not
    /// installed.
    /// </para>
    /// </summary>
    [Fact]
    public void A_service_captured_before_the_diagnostic_replays_as_the_bare_read_it_recorded()
    {
        foreach (var name in new[]
                 {
                     "default-win11", "hardened-win11", "restricted-access", "compromised-win11",
                 })
        {
            var json = File.ReadAllText(Path.Combine(
                FixtureReplayTests.FixtureDirectory, "synthetic", $"{name}.capture.json"));

            using (var document = JsonDocument.Parse(json))
            {
                // The premise, asserted rather than assumed: the day one of these records a
                // failure, it stops being evidence about captures that could not.
                Assert.DoesNotContain(
                    document.RootElement.GetProperty("services").EnumerateObject(),
                    entry => Carries(entry.Value, "diagnostic"));
            }

            var services = new SnapshotServiceStateProvider(
                RempartJson.DeserialiseSnapshot(json));

            var running = services.Read("mpssvc");
            Assert.Equal(ReadStatus.Found, running.Status);
            Assert.Equal(ServiceState.Running, running.Info!.State);
            Assert.Null(running.Diagnostic);

            var absent = services.Read("TlntSvr");
            Assert.Equal(ReadStatus.NotFound, absent.Status);
            Assert.Null(absent.Info);
            Assert.Null(absent.Diagnostic);
        }
    }

    /// <summary>
    /// The absent key itself, spelled out rather than borrowed from a fixture — because the
    /// four fixtures will stop carrying it. They lack a <c>diagnostic</c> under
    /// <c>services</c> today only because they predate the field; regenerated, they will
    /// write it null, and the shape a capture taken before this batch really has would be
    /// exercised by no file in the repository. Absent has to keep meaning « no failure was
    /// noted », not « unknown » and not a refusal.
    /// </summary>
    [Fact]
    public void A_service_entry_without_the_key_at_all_replays_as_a_read_that_noted_nothing()
    {
        const string beforeTheField = """
            {"services":{"mpssvc":{"status":"Found","info":{
              "name":"mpssvc","state":"Running","startMode":"Automatic"}}}}
            """;

        var read = new SnapshotServiceStateProvider(
            RempartJson.DeserialiseSnapshot(beforeTheField)).Read("mpssvc");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal(ServiceState.Running, read.Info!.State);
        Assert.Null(read.Diagnostic);
    }

    /// <summary>Answers the same read to every service: the machine-side half above.</summary>
    private sealed class FixedServiceStateProvider(ServiceRead answer) : IServiceStateProvider
    {
        public ServiceRead Read(string serviceName) => answer;
    }

    private const string RunKey = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>
    /// The registry enumerations, whose status is stored in a map beside the listing rather
    /// than in the read — the same shape the directory listing takes, and for the same
    /// reason: the key is an argument, so one refused <c>Run</c> key must not describe the
    /// four that answered.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_refused_registry_enumeration_is_recorded_serialised_and_replayed(bool values)
    {
        var snapshot = new MachineSnapshot();
        var recording = new RecordingRegistryProvider(new RefusingRegistryProvider(), snapshot);

        if (values)
        {
            Assert.Equal(ReadStatus.AccessDenied, recording.ListValues(RunKey).Status);
        }
        else
        {
            Assert.Equal(ReadStatus.AccessDenied, recording.ListSubKeys(RunKey).Status);
        }

        var replay = new SnapshotRegistryProvider(
            RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot)));

        var read = values
            ? (replay.ListValues(RunKey).Status, replay.ListValues(RunKey).Values.Count)
            : (replay.ListSubKeys(RunKey).Status, replay.ListSubKeys(RunKey).Names.Count);

        Assert.Equal((ReadStatus.AccessDenied, 0), read);
    }

    /// <summary>
    /// The compatibility half, on a versioned capture that really predates the field.
    /// <c>compromised-win11</c> is the one fixture carrying enumerated <c>Run</c> keys, and
    /// its <c>registryLists</c> block has no status map beside it: read as a refusal, every
    /// capture older than this batch would grow a NOTABLE on the two keys whose entries its
    /// golden freezes.
    /// </summary>
    [Fact]
    public void A_capture_written_before_the_list_status_replays_as_the_listing_it_recorded()
    {
        var json = File.ReadAllText(Path.Combine(
            FixtureReplayTests.FixtureDirectory, "synthetic", "compromised-win11.capture.json"));

        using (var document = JsonDocument.Parse(json))
        {
            // On the value and never on the key — see Carries. This one is the reason the
            // reading has to know about maps at all: RegistryListsStatus is a non-nullable
            // Dictionary initialised to [], so a regeneration writes it {} rather than null.
            Assert.False(Carries(document.RootElement, "registryListsStatus"),
                "La fixture porte désormais un statut d'énumération : elle ne prouve plus la "
                + "compatibilité des captures antérieures au champ.");
        }

        var read = new SnapshotRegistryProvider(RempartJson.DeserialiseSnapshot(json))
            .ListValues(RunKey);

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.NotEmpty(read.Values);
    }

    /// <summary>
    /// The other half of the same promise, and the one that decides whether an old fixture
    /// stays replayable at all: a key this capture never enumerated. It answered an empty
    /// listing before the status existed and must stay just as silent — <c>NotFound</c>, not
    /// a refusal nobody was given. That deliberate degradation is what
    /// <c>AutorunsCollector.StartupFolders</c> reads <c>ListValues</c> for instead of
    /// <c>ReadValue</c>, which throws on the same capture.
    /// </summary>
    [Fact]
    public void A_key_this_capture_never_enumerated_stays_silent_rather_than_refused()
    {
        var read = new SnapshotRegistryProvider(new MachineSnapshot());

        Assert.Equal(ReadStatus.NotFound, read.ListValues(RunKey).Status);
        Assert.Equal(ReadStatus.NotFound, read.ListSubKeys(RunKey).Status);
    }

    /// <summary>Refuses every enumeration, answers nothing else: the machine-side half of
    /// the recording test above.</summary>
    private sealed class RefusingRegistryProvider : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) =>
            RegistryRead.AccessDenied;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.AccessDenied;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.AccessDenied;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.AccessDenied;
    }

    private sealed class CountingHostsFileProvider(HostsFileRead answer) : IHostsFileProvider
    {
        public int Calls { get; private set; }

        public HostsFileRead ReadLines()
        {
            Calls++;
            return answer;
        }
    }

    private sealed class CountingScheduledTaskProvider(ScheduledTaskRead answer)
        : IScheduledTaskProvider
    {
        public int Calls { get; private set; }

        public ScheduledTaskRead Enumerate()
        {
            Calls++;
            return answer;
        }
    }

    private sealed class CountingFirewallProvider(FirewallState answer) : IFirewallProvider
    {
        public int Calls { get; private set; }

        public FirewallState Read()
        {
            Calls++;
            return answer;
        }
    }

    private sealed class CountingDriverProvider(DriverRead answer) : IDriverProvider
    {
        public int Calls { get; private set; }

        public DriverRead Enumerate()
        {
            Calls++;
            return answer;
        }
    }

    private sealed class CountingFileSystemProvider(
        Dictionary<string, DirectoryRead> answers) : IFileSystemProvider
    {
        public int Calls { get; private set; }

        public DirectoryRead ListFiles(string directory)
        {
            Calls++;
            return answers[directory];
        }
    }
}
