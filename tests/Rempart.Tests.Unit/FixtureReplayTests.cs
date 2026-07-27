using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Reports;
using Rempart.Core.Snapshots;
using Xunit.Abstractions;

namespace Rempart.Tests.Unit;

/// <summary>
/// Level-2 tests: the collectors replay snapshots, compared against a versioned
/// reference output. A regression becomes visible without starting a VM.
///
/// Two directories, two regimes:
/// <list type="bullet">
///   <item><c>synthetic/</c> — versioned, fabricated values. The repository being
///   public, no real machine appears there.</item>
///   <item><c>local/</c> — outside version control. Captures of real machines stay
///   there, and are replayed when present: that is where the cases live that
///   nobody would have thought to fabricate.</item>
/// </list>
/// </summary>
public sealed class FixtureReplayTests(ITestOutputHelper output)
{
    /// <summary>
    /// States what was actually replayed.
    ///
    /// <para>
    /// The fixture list is discovered on disk and <c>local/</c> is gitignored, so this
    /// workstation replays more cases than CI does — 513 unit tests against 511, a
    /// difference nothing announced. A suite that quietly does less work still reports
    /// green, and that green reads like the fuller one. The same rule already applies to
    /// the WMI tests: a check that did not run has to say so.
    /// </para>
    /// </summary>
    [Fact]
    public void The_replay_states_how_many_fixtures_it_found()
    {
        var synthetic = Fixtures().Cast<object[]>()
            .Select(row => (string)row[0])
            .ToList();

        var local = synthetic.Where(name => name.StartsWith("local/", StringComparison.Ordinal)).ToList();
        var versioned = synthetic.Except(local).ToList();

        output.WriteLine(
            $"Fixtures rejouées : {versioned.Count} versionnée(s), {local.Count} locale(s) — "
            + $"{synthetic.Count} au total.");

        foreach (var name in synthetic)
        {
            output.WriteLine($"  · {name}");
        }

        if (local.Count == 0)
        {
            output.WriteLine(
                "Aucune capture réelle dans tests/fixtures/local : les chemins que seule une "
                + "vraie machine exerce ne sont pas couverts par cette exécution. C'est le cas "
                + "en CI, par conception — le dépôt est public (voir DET-DIRTY).");
        }

        // The versioned fixtures are the contract: their absence means a broken checkout,
        // not a machine without local captures.
        Assert.NotEmpty(versioned);
    }

    public static TheoryData<string> Fixtures()
    {
        var data = new TheoryData<string>();
        foreach (var path in Directory.EnumerateFiles(FixtureDirectory, "*.capture.json",
                     SearchOption.AllDirectories))
        {
            data.Add(Path.GetRelativePath(FixtureDirectory, path)
                .Replace(".capture.json", string.Empty)
                .Replace(Path.DirectorySeparatorChar, '/'));
        }

        // Synthetic fixtures are versioned: their absence signals an incomplete
        // repository, not a machine without local captures.
        Assert.Contains(data.Cast<object[]>().Select(d => (string)d[0]),
            name => name.StartsWith("synthetic/", StringComparison.Ordinal));
        return data;
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Replay_matches_the_recorded_reference(string fixture)
    {
        var actual = Replay(fixture);
        var expectedPath = Path.Combine(FixtureDirectory, $"{fixture}.expected.json");

        if (!File.Exists(expectedPath))
        {
            // Normalised on the way out, like the console and diff references beside it:
            // the serialiser indents with the platform's newline, so a reference first
            // written on this Windows workstation landed in CRLF while every existing one
            // is LF. Git hides that — .gitattributes normalises on commit — so the whole
            // file would have been rewritten with nothing to show for it in the diff.
            File.WriteAllText(expectedPath, Normalise(actual));
            Assert.Fail(
                $"Référence absente pour « {fixture} » : elle vient d'être écrite dans " +
                $"{expectedPath}. Relire le contenu, puis le versionner.");
        }

        Assert.Equal(Normalise(File.ReadAllText(expectedPath)), Normalise(actual));
    }

    /// <summary>
    /// Freezes the console output, which until now nothing observed.
    ///
    /// <para>
    /// The CLI wrote straight to <see cref="Console"/>, so a change in what the tool says
    /// was invisible: CI checks an exit code, not a text. The reports got this treatment
    /// in M6 and it is what caught the capped score gauges; the console never did. Now
    /// that the renderer is pure, the same golden-file discipline applies to it.
    /// </para>
    ///
    /// <para>
    /// The tool version is <c>test</c> here, as everywhere in the replay, so the reference
    /// does not churn on every release. That the extraction itself changed nothing was
    /// proved separately, by diffing the real CLI output on these three fixtures before
    /// and after the move.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void The_console_rendering_matches_its_reference(string fixture)
    {
        var actual = Normalise(ConsoleReport.HumanReadable(Scan(fixture)));
        var referencePath = Path.Combine(FixtureDirectory, $"{fixture}.console.txt");

        if (!File.Exists(referencePath))
        {
            File.WriteAllText(referencePath, actual);
            Assert.Fail(
                $"Référence console absente pour « {fixture} » : elle vient d'être écrite "
                + $"dans {referencePath}. Relire le contenu, puis le versionner.");
        }

        Assert.Equal(Normalise(File.ReadAllText(referencePath)), actual);
    }

    /// <summary>
    /// The pairs worth freezing, named rather than discovered. Four fixtures would give
    /// sixteen combinations and most of them prove the same thing twice; and a discovered
    /// list would eventually pair a <c>local/</c> capture of a real machine, whose
    /// rendering would land in a public repository.
    ///
    /// <para>
    /// The first two are the same pair read in both directions, which is what it takes to
    /// cover both signs of the delta: no two fixtures here regress and improve at once.
    /// The third compares a capture with itself — the only way to freeze what the tool
    /// says when nothing moved.
    /// </para>
    ///
    /// <para>
    /// The fourth is the comparison the tool exists for: a machine re-scanned after an
    /// intrusion. Until the compromised fixture existed, no reference had ever carried a
    /// <c>Suspicious</c> finding — the highest severity the diff rendering had ever been
    /// asked to print was <c>Notable</c>, so the one output a scheduled re-scan is read
    /// for was frozen by nothing.
    /// </para>
    /// </summary>
    public static TheoryData<string, string> DiffPairs() => new()
    {
        { "synthetic/restricted-access", "synthetic/default-win11" },
        { "synthetic/default-win11", "synthetic/restricted-access" },
        { "synthetic/default-win11", "synthetic/default-win11" },
        { "synthetic/default-win11", "synthetic/compromised-win11" },
    };

    /// <summary>
    /// Freezes the comparison rendering, on the discipline
    /// <see cref="The_console_rendering_matches_its_reference"/> applies to the scan.
    ///
    /// <para>
    /// <c>ConsoleReport.Diff</c> shipped with no test at all: <c>ScanDiffTests</c> pins how
    /// a move is classified and <c>DiffReportTests</c> pins the HTML and the Markdown, but
    /// the lines that decide what the terminal prints were observed by nobody. The pairs
    /// are chosen so that between them the reference carries a regression, a correction, a
    /// control that went blind, one that came back, a scope change, and findings that
    /// disappeared and were retargeted.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(DiffPairs))]
    public void The_diff_rendering_matches_its_reference(string before, string after)
    {
        var actual = Normalise(ConsoleReport.Diff(ScanDiff.Compare(Scan(before), Scan(after))));
        var referencePath = Path.Combine(FixtureDirectory, DiffReferenceName(before, after));

        if (!File.Exists(referencePath))
        {
            File.WriteAllText(referencePath, actual);
            Assert.Fail(
                $"Référence de comparaison absente pour « {before} → {after} » : elle vient "
                + $"d'être écrite dans {referencePath}. Relire le contenu, puis le versionner.");
        }

        Assert.Equal(Normalise(File.ReadAllText(referencePath)), actual);
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Replay_is_deterministic(string fixture)
    {
        // A replay that varied from one run to the next would make any reference
        // unusable — including for rempart diff (M7).
        Assert.Equal(Replay(fixture), Replay(fixture));
    }

    [Fact]
    public void No_shipped_rule_fails_on_a_hardened_machine()
    {
        // A rule that can never pass is a bug: contradictory expectation, wrong
        // path, badly chosen operator. It would produce a permanent failure on
        // every machine, one that nobody could fix.
        //
        // The "hardened" fixture sets on each key the value its rule expects.
        //
        // NotApplicable remains an acceptable answer, and requiring its absence
        // would be a mistake: some rules exclude each other by construction. RDP
        // disabled satisfies WIN-RDP-001 and makes WIN-RDP-002 (NLA) moot — no
        // machine can satisfy both at once.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "hardened-win11.capture.json")));

        var result = ScanEngine.Default().Run(
            new ProviderSet(new SnapshotRegistryProvider(snapshot),
                new SnapshotSystemInfoProvider(snapshot),
                new SnapshotServiceStateProvider(snapshot),
                new SnapshotSecurityPolicyProvider(snapshot),
                new SnapshotWmiProvider(snapshot)),
            "test", snapshot.CapturedAtUtc);

        var failing = result.Verdicts
            .Where(v => v.Status is VerdictStatus.Fail or VerdictStatus.Unknown)
            .Select(v => $"{v.RuleId} (observé {v.Observed ?? "—"}, attendu {v.Expected ?? "—"})");

        Assert.Empty(failing);
        Assert.Equal(100, result.Score?.Overall);
    }

    [Fact]
    public void The_hardened_fixture_leaves_almost_no_rule_unevaluated()
    {
        // Guardrail against the opposite drift: a fixture that pushed most rules
        // out of scope would reach 100 % without proving anything. Exclusions
        // must stay rare and intentional.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "hardened-win11.capture.json")));

        var result = ScanEngine.Default().Run(
            new ProviderSet(new SnapshotRegistryProvider(snapshot),
                new SnapshotSystemInfoProvider(snapshot),
                new SnapshotServiceStateProvider(snapshot),
                new SnapshotSecurityPolicyProvider(snapshot),
                new SnapshotWmiProvider(snapshot)),
            "test", snapshot.CapturedAtUtc);

        var notApplicable = result.Verdicts.Count(v => v.Status == VerdictStatus.NotApplicable);

        Assert.True(notApplicable <= 2,
            $"{notApplicable} règles hors périmètre sur la fixture durcie : le 100 % " +
            "ne prouverait plus grand-chose.");
    }

    [Fact]
    public void Versioned_fixtures_are_anonymised()
    {
        var synthetic = Path.Combine(FixtureDirectory, "synthetic");

        foreach (var path in Directory.EnumerateFiles(synthetic, "*.capture.json"))
        {
            var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(path));

            // Guardrail: the repository is public. A raw capture dropped here by
            // mistake fails the test now, not six months later while rereading the repo.
            Assert.True(snapshot.Anonymised, $"Fixture non anonymisée : {path}");
            Assert.StartsWith("anon:", snapshot.SystemInfo?.MachineName, StringComparison.Ordinal);

            AssertNoHardwareIdentity(snapshot, path);
            AssertNoThirdPartyTaskLabel(snapshot, path);
        }
    }

    /// <summary>
    /// The mainboard and the firmware, which the flag above says nothing about.
    ///
    /// <para>
    /// Everything recorded under the BIOS key is hardware identity — model, board, BIOS
    /// version and release date — so the check is the key rather than a list of value
    /// names. A list would have to be kept in step with the anonymiser's own, and a value
    /// dropped from one would silently stop being checked by the other; here a new read
    /// under that key fails until somebody decides what it is.
    /// </para>
    /// </summary>
    private static void AssertNoHardwareIdentity(MachineSnapshot snapshot, string path)
    {
        const string BiosKey = @"HKLM\HARDWARE\DESCRIPTION\System\BIOS||";

        var readable = snapshot.Registry
            .Where(entry => entry.Key.StartsWith(BiosKey, StringComparison.OrdinalIgnoreCase))
            .Where(entry => entry.Value.Value?.Text is { Length: > 0 } text
                && !text.StartsWith("anon:", StringComparison.Ordinal))
            .Select(entry => $"{entry.Key[BiosKey.Length..]} = {entry.Value.Value!.Text}")
            .ToList();

        Assert.True(readable.Count == 0,
            $"Identité matérielle en clair dans {Path.GetFileName(path)} — modèle de carte "
            + "mère, version ou date de BIOS désignent la machine d'origine et le dépôt est "
            + $"public : {string.Join(", ", readable)}");
    }

    /// <summary>
    /// The task labels, which name the installed software.
    ///
    /// <para>
    /// Everything outside <c>\Microsoft\</c> was put there by an installer, so its path
    /// and its name are an inventory line. The exclusion is the point of the criterion and
    /// not an oversight: the compromised fixture plants a task inside that folder on
    /// purpose, and a check that demanded a digest everywhere would force it out of the one
    /// place where it means something.
    /// </para>
    /// </summary>
    private static void AssertNoThirdPartyTaskLabel(MachineSnapshot snapshot, string path)
    {
        var readable = (snapshot.ScheduledTasks?.Tasks ?? [])
            .Where(task => !task.Path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
            .Where(task => !task.Path.StartsWith("anon:", StringComparison.Ordinal)
                || !task.Name.StartsWith("anon:", StringComparison.Ordinal))
            .Select(task => $"{task.Path} ({task.Name})")
            .ToList();

        Assert.True(readable.Count == 0,
            $"Tâche(s) planifiée(s) tierce(s) en clair dans {Path.GetFileName(path)} — le "
            + "chemin nomme le logiciel installé, et parfois un GUID d'installation ou un "
            + $"SID : {string.Join(", ", readable)}");
    }

    [Fact]
    public void Local_fixtures_stay_out_of_version_control()
    {
        // The policy lives in .gitignore; this test makes it visible from the code,
        // right where someone might drop a real capture out of convenience.
        var local = Path.Combine(FixtureDirectory, "local");
        var readme = Path.Combine(local, "README.md");

        Assert.True(File.Exists(readme),
            $"Le répertoire {local} doit porter un README rappelant qu'il n'est pas versionné.");
    }

    /// <summary>
    /// The replay wiring — now <see cref="SnapshotProviders.Replaying"/>, the same call
    /// <c>rempart scan --from</c> makes, rather than a second list written here.
    ///
    /// <para>
    /// That copy was the loophole in the guard below. It checked that every provider was
    /// wired into <em>this file</em>, so the shipped command could drop one and stay green:
    /// the property it was watching belonged to the test. What it verified was that the test
    /// agreed with itself — the circular shape this repository has caught itself writing
    /// before. Pointing both at Core is what makes the guard bite on the product.
    /// </para>
    /// </summary>
    private static ProviderSet ReplayProviders(MachineSnapshot snapshot) =>
        SnapshotProviders.Replaying(snapshot);

    /// <summary>
    /// Closes D2 and D2b, which are the same mistake made twice: a provider added to
    /// <see cref="ProviderSet"/> without being wired into the replay. Both times the
    /// collector ran on nothing and the reference froze "nothing found", which reads
    /// exactly like a clean machine.
    ///
    /// <para>
    /// Reflection rather than a hand-kept list, because a hand-kept list is the thing
    /// that was already forgotten twice. Every provider property must hold a
    /// <c>Snapshot*</c> implementation: the no-op fallbacks are what a missing argument
    /// silently leaves behind.
    /// </para>
    ///
    /// <para>
    /// The count is asserted as well, and it is not decoration: the whole check is a filter,
    /// and a filter that matches nothing reports success. Were <c>ProviderSet</c> to stop
    /// exposing its providers as interface-typed properties — or were this test to be
    /// pointed at something that has none — the list of failures would be empty for the one
    /// reason that must never pass for a pass.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_provider_is_wired_into_the_replay()
    {
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "default-win11.capture.json")));

        AssertEveryProviderIsWired(SnapshotProviders.Replaying(snapshot), "Snapshot",
            "au rejeu de fixtures, donc collecteur tournant à vide derrière une référence "
            + "qui fige « rien trouvé »");
    }

    /// <summary>
    /// The other direction, which nothing watched: a provider missing from the recording
    /// wiring never writes anything into the capture.
    ///
    /// <para>
    /// It is the worse half of the same accident. A replay that forgets a provider still has
    /// the data — the capture holds it, and re-running the replay after the fix recovers the
    /// findings. A capture that forgets one has written nothing down, and the machine it was
    /// taken on is not there any more. That is the shape the versioned fixtures are supposed
    /// to protect against, and it is exactly the shape they cannot detect: a fixture recorded
    /// without a provider replays perfectly and reports « rien trouvé » forever.
    /// </para>
    ///
    /// <para>
    /// Runs on the Linux job because <see cref="SnapshotProviders.Recording"/> wraps a
    /// <see cref="ProviderSet"/> it is handed rather than building Windows providers itself.
    /// The set handed in here is the replay one, which is convenient rather than meaningful:
    /// what is under test is the wrapping, and any set with twenty providers exercises it.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_provider_is_wrapped_by_the_capture()
    {
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "default-win11.capture.json")));

        AssertEveryProviderIsWired(
            SnapshotProviders.Recording(SnapshotProviders.Replaying(snapshot), new MachineSnapshot()),
            "Recording",
            "à l'enregistrement, donc une capture qui ne contient rien pour lui — et aucun "
            + "rejeu ultérieur ne peut retrouver ce qui n'a jamais été écrit");
    }

    private static void AssertEveryProviderIsWired(ProviderSet wiring, string prefix, string harm)
    {
        var wired = typeof(ProviderSet).GetProperties()
            .Where(property => property.PropertyType.IsInterface)
            .Select(property => (property.Name, Implementation: property.GetValue(wiring)))
            .ToList();

        // An exact count, not a floor. A floor of nineteen had tolerated one provider slipping
        // out of the filter — exposing one as a concrete decorator rather than as its
        // interface is an ordinary refactoring, and it would have taken the provider out of
        // this guard's sight while the assertion still passed. A filter that quietly stops
        // looking at something is the failure this whole test exists to prevent.
        Assert.True(wired.Count == 20,
            $"{wired.Count} fournisseur(s) inspecté(s) sur ProviderSet au lieu de 20 : ce "
            + "garde filtre sur les propriétés de type interface, et un fournisseur qui "
            + "cesse d'en être une sort de sa vue sans que rien ne le dise.");

        var missing = wired
            .Where(entry => entry.Implementation?.GetType().Name
                .StartsWith(prefix, StringComparison.Ordinal) != true)
            .Select(entry => $"{entry.Name} → {entry.Implementation?.GetType().Name ?? "null"}")
            .ToList();

        Assert.True(missing.Count == 0,
            $"Fournisseur(s) non câblé(s) {harm} : {string.Join(", ", missing)}.");
    }

    /// <summary>
    /// The scan a fixture replays to, result and all. Shared by the console goldens, which
    /// need the object rather than the JSON <see cref="Replay"/> returns, and by
    /// <c>ExitCodeTests</c>, which needs the scan the exit code answers for. Internal
    /// rather than copied there: a second twenty-provider wiring would drift from this
    /// one, and the claim being made — that the fixture scoring 100 % exits 5 — is only
    /// worth anything about the scan these references freeze.
    ///
    /// <para>
    /// The inventory fields are left intact here, unlike in <see cref="Replay"/>. The
    /// comparison reads <c>machine.name</c> to decide whether it spans one machine or two;
    /// stripping it first would turn every pair into "machine inconnue" against itself,
    /// flip <c>SameMachine</c> to true and silently rewrite the header of every reference.
    /// </para>
    /// </summary>
    internal static ScanResult Scan(string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            File.ReadAllText(Path.Combine(FixtureDirectory, $"{fixture}.capture.json")));

        return ScanEngine.Default().Run(ReplayProviders(snapshot), "test", snapshot.CapturedAtUtc);
    }

    /// <summary>
    /// <c>{before}__{after}.diff.txt</c>, beside the captures it compares. The separator is
    /// split by hand: these identifiers always use '/', and going through
    /// <see cref="Path"/> would have the reference change name between the Windows
    /// workstation and the Linux job.
    /// </summary>
    private static string DiffReferenceName(string before, string after)
    {
        var leaf = after[(after.LastIndexOf('/') + 1)..];
        return $"{before}__{leaf}.diff.txt";
    }

    private static string Replay(string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            File.ReadAllText(Path.Combine(FixtureDirectory, $"{fixture}.capture.json")));

        var providers = ReplayProviders(snapshot);

        // Full engine, rules included: what we want frozen is the verdict rendered
        // on a given machine, not just the collected fields.
        var result = ScanEngine.Default().Run(providers, "test", snapshot.CapturedAtUtc);

        // Volatile fields are removed: a reference cannot freeze an uptime.
        var comparable = result with
        {
            Collectors = [.. result.Collectors.Select(c => c with
            {
                Fields = c.Fields
                    .Where(f => FieldSemantics.IsComparable(f.Key))
                    .ToDictionary(f => f.Key, f => f.Value),
            })],
        };

        return RempartJson.Serialise(comparable);
    }

    private static string Normalise(string json) => json.ReplaceLineEndings("\n").Trim();

    private static string FixtureDirectory { get; } = Locate();

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "tests", "fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Répertoire tests/fixtures introuvable.");
    }
}
