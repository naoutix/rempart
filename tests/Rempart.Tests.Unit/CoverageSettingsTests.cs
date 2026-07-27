using System.Text.RegularExpressions;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds the coverage configurations together with the workflow that asks for them.
///
/// <para>
/// VSTest pairs a run-settings block to a collector by <c>friendlyName</c>, and a mismatch
/// is not an error: the collector falls back to its defaults, the <c>Include</c> filter
/// disappears, every referenced assembly joins the measurement, and the percentage moves
/// for a reason nobody can name. Silent degradation behind a green build is the failure
/// mode this repository has already paid for three times — D2, D2b and the component store.
/// </para>
///
/// <para>
/// There are two configurations since DET-COUVERTURE was narrowed to its real subject: the
/// Linux job measures <c>Rempart.Core</c>, the Windows job measures <c>Rempart.Windows</c>,
/// which the Linux job cannot even compile. Two files, so two chances to drift, so the
/// guards below read both rather than the first one.
/// </para>
///
/// <para>
/// Reading repository files from a test is the same technique as the replay wiring guard:
/// the invariant spans files that no compiler checks against each other.
/// </para>
/// </summary>
public sealed class CoverageSettingsTests
{
    private const string Ci = ".github/workflows/ci.yml";
    private const string CoreSettings = "tests/coverage.runsettings";
    private const string WindowsSettings = "tests/coverage.windows.runsettings";

    [Fact]
    public void Coverage_settings_name_the_collector_the_workflow_asks_for()
    {
        Assert.Contains("--collect:\"XPlat Code Coverage\"", RepositoryFiles.Read(Ci),
            StringComparison.Ordinal);

        foreach (var settings in Settings)
        {
            var declared = Regex.Match(RepositoryFiles.Read(settings), "friendlyName=\"([^\"]+)\"");

            Assert.True(declared.Success,
                $"{settings} ne déclare plus de friendlyName : la configuration de couverture "
                + "n'est appariée à aucun collecteur.");

            Assert.True(
                string.Equals(declared.Groups[1].Value, "XPlat Code Coverage",
                    StringComparison.OrdinalIgnoreCase),
                $"Le collecteur déclaré dans {settings} (« {declared.Groups[1].Value} ») ne "
                + "correspond plus à celui que ci.yml collecte : la configuration est ignorée "
                + "en silence et la couverture est mesurée avec les valeurs par défaut.");
        }
    }

    /// <summary>
    /// The denominator is a decision, not a default. Anything joining it — a new project
    /// reference, a dependency — changes what the percentage means.
    /// </summary>
    [Fact]
    public void Coverage_settings_measure_Rempart_Core_only()
    {
        var includes = Regex.Matches(RepositoryFiles.Read(CoreSettings), "<Include>([^<]+)</Include>");

        Assert.Single(includes);
        Assert.Equal("[Rempart.Core]*", includes[0].Groups[1].Value);
    }

    /// <summary>
    /// An <c>Include</c> naming an assembly that does not exist matches nothing, and coverlet
    /// says nothing about it: the report comes back with zero packages and a percentage of
    /// "n/a" that reads like a tooling hiccup. Confronted here with the projects that exist
    /// rather than with a second list of names.
    /// </summary>
    [Fact]
    public void Every_measured_assembly_is_a_project_of_this_repository()
    {
        var measured = MeasuredAssemblies().ToList();

        Assert.NotEmpty(measured);

        foreach (var (settings, assembly) in measured)
        {
            var project = RepositoryFiles.Resolve($"src/{assembly}/{assembly}.csproj");

            Assert.True(File.Exists(project),
                $"{settings} mesure « {assembly} », qui n'est pas un projet de ce dépôt. Un "
                + "filtre qui ne correspond à rien ne fait pas échouer la collecte : il rend "
                + "un rapport vide, indiscernable d'un rapport où rien n'est couvert.");
        }
    }

    /// <summary>
    /// The two jobs must measure disjoint assemblies. Let them overlap and the repository
    /// publishes two percentages for the same code, measured by two suites on two operating
    /// systems, that a reader will inevitably compare — the Windows suite exercises
    /// <c>Rempart.Core</c> too, and counting it here would print a much lower Core figure
    /// beside the real one.
    /// </summary>
    [Fact]
    public void The_two_jobs_do_not_measure_the_same_assembly_twice()
    {
        var byAssembly = MeasuredAssemblies()
            .GroupBy(measured => measured.Assembly, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .ToList();

        Assert.True(byAssembly.Count == 0,
            "Deux configurations de couverture mesurent la même assembly : "
            + string.Join(" ; ", byAssembly.Select(group =>
                $"{group.Key} dans {string.Join(" et ", group.Select(measured => measured.Settings))}"))
            + ". Les deux chiffres publiés répondraient alors à la même question avec deux "
            + "réponses différentes.");
    }

    /// <summary>
    /// Both directions of the same wiring. A configuration file nobody reads is a file that
    /// documents a measurement which is not taken; a job pointing at a file that is not there
    /// silently loses its filter, since VSTest treats a missing settings path as no settings
    /// at all.
    /// </summary>
    [Fact]
    public void Every_coverage_configuration_is_read_by_a_job_and_every_job_reads_one_that_exists()
    {
        var workflow = RepositoryFiles.Read(Ci);

        var onDisk = Directory
            .EnumerateFiles(RepositoryFiles.Resolve("tests"), "*.runsettings",
                SearchOption.TopDirectoryOnly)
            .Select(path => "tests/" + Path.GetFileName(path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(onDisk);

        foreach (var settings in onDisk)
        {
            Assert.True(workflow.Contains($"--settings {settings}", StringComparison.Ordinal),
                $"{settings} existe mais aucun job de la CI ne le passe à dotnet test : il "
                + "décrit une mesure que personne ne prend.");
        }

        foreach (var referenced in Regex
            .Matches(workflow, @"--settings\s+(\S+)")
            .Select(match => match.Groups[1].Value))
        {
            Assert.True(onDisk.Contains(referenced, StringComparer.Ordinal),
                $"Un job de la CI passe --settings {referenced}, qui n'existe pas. VSTest ne "
                + "s'en plaint pas : il collecte avec les valeurs par défaut, sans filtre, et "
                + "le pourcentage publié n'est plus celui qu'on croit lire.");
        }
    }

    /// <summary>
    /// The measurement is worth nothing if it is not published. Each job that collects must
    /// also hand its results to the summary script — the same script, with the assembly it
    /// measured, because a second summariser is the divergence DET-SCRIPTS describes.
    /// </summary>
    [Fact]
    public void Each_job_publishes_the_coverage_it_collects()
    {
        var workflow = RepositoryFiles.Read(Ci);

        Assert.Contains("--settings tests/coverage.runsettings", workflow, StringComparison.Ordinal);
        Assert.Contains("--settings tests/coverage.windows.runsettings", workflow, StringComparison.Ordinal);

        var summaries = Regex.Matches(workflow, @"coverage-summary\.ps1").Count;

        Assert.True(summaries == 2,
            $"{summaries} appel(s) à coverage-summary.ps1 dans ci.yml, deux attendus : la "
            + "couverture Linux et la couverture Windows. Une collecte sans résumé produit un "
            + "artefact que personne n'ouvre.");

        Assert.Contains("-Package Rempart.Windows", workflow, StringComparison.Ordinal);

        // Reading the script's own parameter list rather than trusting the call site: the
        // day -Package is renamed, the workflow keeps passing a switch nothing reads and
        // publishes the Windows report under the Core heading.
        Assert.Contains("$Package", RepositoryFiles.Read("scripts/coverage-summary.ps1"),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Coverage is an indicator, not a gate — stated in docs/DEBT.md under DET-COUVERTURE
    /// and enforced here, so that a threshold cannot be added without also removing the
    /// paragraph that argues against one. Widening the perimeter to the Windows layer does
    /// not soften that: what changed is what is seen, not what is enforced.
    /// </summary>
    [Fact]
    public void The_coverage_step_carries_no_threshold()
    {
        foreach (var settings in Settings)
        {
            // The element, not the word: the files' own comments argue against a threshold,
            // and matching prose would make this test fail on the sentence that explains it.
            Assert.DoesNotContain("<Threshold", RepositoryFiles.Read(settings),
                StringComparison.OrdinalIgnoreCase);
        }

        Assert.Contains("DET-COUVERTURE", RepositoryFiles.Read("docs/DEBT.md"), StringComparison.Ordinal);
    }

    /// <summary>
    /// A CI job that filters on a test name and matches nothing exits 0. It is green
    /// forever, and it is green precisely because it checks nothing.
    ///
    /// <para>
    /// Not hypothetical: <c>fixtures-anonymised</c> — the job whose whole purpose is to
    /// keep a raw capture of a real machine out of a public repository, and whose comment
    /// promises to "make the failure readable without opening the logs" — filtered on
    /// <c>Anonymised_fixtures_carry_no_machine_name</c> for months after that test was
    /// renamed. Measured: "No test matches the given testcase filter", exit code 0. The
    /// suite still ran the real assertion inside the <c>test</c> job, so nothing was ever
    /// exposed; what was lost is the dedicated guard, silently.
    /// </para>
    ///
    /// <para>
    /// Same shape as the drift this repository keeps paying for: two hand-written names,
    /// in two files, that no compiler relates to one another.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_test_name_a_CI_job_filters_on_exists()
    {
        var filtered = Regex.Matches(RepositoryFiles.Read(Ci),
                """FullyQualifiedName~([A-Za-z_][A-Za-z0-9_]*)""")
            .Select(m => m.Groups[1].Value)
            .ToList();

        Assert.NotEmpty(filtered);

        var declared = Directory
            .EnumerateFiles(RepositoryFiles.Resolve("tests"), "*.cs",
                SearchOption.AllDirectories)
            .Where(path => !path.Split(Path.DirectorySeparatorChar)
                .Any(segment => segment is "bin" or "obj"))
            .SelectMany(path => Regex.Matches(File.ReadAllText(path),
                    """public\s+void\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(""")
                .Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.Ordinal);

        var missing = filtered.Where(name => !declared.Contains(name)).ToList();

        Assert.True(missing.Count == 0,
            "Un job de la CI filtre sur un test qui n'existe pas : "
            + $"{string.Join(", ", missing)}. Le job n'exécute alors aucun test et sort 0, "
            + "donc il est vert en permanence sans rien vérifier.");
    }

    private static string[] Settings { get; } = [CoreSettings, WindowsSettings];

    /// <summary>
    /// Every assembly an <c>Include</c> filter names, with the file that named it. The
    /// bracket form is coverlet's: <c>[Assembly]TypeGlob</c>.
    /// </summary>
    private static IEnumerable<(string Settings, string Assembly)> MeasuredAssemblies() =>
        Settings.SelectMany(settings => Regex
            .Matches(RepositoryFiles.Read(settings), @"<Include>\[([^\]]+)\]")
            .Select(match => (Settings: settings, Assembly: match.Groups[1].Value)));
}
