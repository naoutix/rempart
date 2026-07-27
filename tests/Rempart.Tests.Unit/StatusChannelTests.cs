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
    /// A directory the capture holds nothing about. <c>AccessDenied</c> and not an empty
    /// listing, for the reason the debt was opened over: the replay would otherwise conclude
    /// « aucun autorun » about a folder this capture never walked. Not <c>NotFound</c>
    /// either — that would claim the folder was missing from the machine, which is a fact the
    /// capture never recorded.
    /// </summary>
    [Fact]
    public void A_directory_absent_from_a_capture_is_not_a_directory_that_was_empty()
    {
        var read = new SnapshotFileSystemProvider(new MachineSnapshot()).ListFiles(Startup);

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
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
            [Startup] = DirectoryRead.Failed("Accès refusé."),
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
