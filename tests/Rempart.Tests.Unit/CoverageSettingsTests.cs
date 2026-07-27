using System.Text.RegularExpressions;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds the coverage configuration together with the workflow that asks for it.
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
/// Reading repository files from a test is the same technique as the replay wiring guard:
/// the invariant spans two files that no compiler checks against each other.
/// <see cref="Path"/> is legitimate here — these are real paths on the host running the
/// test, not Windows paths captured on one machine and replayed on another.
/// </para>
/// </summary>
public sealed class CoverageSettingsTests
{
    [Fact]
    public void Coverage_settings_name_the_collector_the_workflow_asks_for()
    {
        var declared = Regex.Match(Read("tests/coverage.runsettings"), "friendlyName=\"([^\"]+)\"");

        Assert.True(declared.Success,
            "tests/coverage.runsettings ne déclare plus de friendlyName : la configuration "
            + "de couverture n'est appariée à aucun collecteur.");

        Assert.Contains("--collect:\"XPlat Code Coverage\"", Read(".github/workflows/ci.yml"),
            StringComparison.Ordinal);

        Assert.True(
            string.Equals(declared.Groups[1].Value, "XPlat Code Coverage",
                StringComparison.OrdinalIgnoreCase),
            $"Le collecteur déclaré dans tests/coverage.runsettings (« {declared.Groups[1].Value} ») "
            + "ne correspond plus à celui que ci.yml collecte : la configuration est ignorée "
            + "en silence et la couverture est mesurée avec les valeurs par défaut.");
    }

    /// <summary>
    /// The denominator is a decision, not a default. Anything joining it — a new project
    /// reference, a dependency — changes what the percentage means.
    /// </summary>
    [Fact]
    public void Coverage_settings_measure_Rempart_Core_only()
    {
        var includes = Regex.Matches(Read("tests/coverage.runsettings"), "<Include>([^<]+)</Include>");

        Assert.Single(includes);
        Assert.Equal("[Rempart.Core]*", includes[0].Groups[1].Value);
    }

    [Fact]
    public void The_test_job_passes_the_coverage_settings()
    {
        Assert.Contains("--settings tests/coverage.runsettings", Read(".github/workflows/ci.yml"),
            StringComparison.Ordinal);

        Assert.Contains("coverage-summary.ps1", Read(".github/workflows/ci.yml"),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Coverage is an indicator, not a gate — stated in docs/DEBT.md under DET-COUVERTURE
    /// and enforced here, so that a threshold cannot be added without also removing the
    /// paragraph that argues against one.
    /// </summary>
    [Fact]
    public void The_coverage_step_carries_no_threshold()
    {
        // The element, not the word: the file's own comment argues against a threshold,
        // and matching prose would make this test fail on the sentence that explains it.
        Assert.DoesNotContain("<Threshold", Read("tests/coverage.runsettings"),
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains("DET-COUVERTURE", Read("docs/DEBT.md"), StringComparison.Ordinal);
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
        var filtered = Regex.Matches(Read(".github/workflows/ci.yml"),
                """FullyQualifiedName~([A-Za-z_][A-Za-z0-9_]*)""")
            .Select(m => m.Groups[1].Value)
            .ToList();

        Assert.NotEmpty(filtered);

        var declared = Directory
            .EnumerateFiles(Path.Combine(RepositoryRoot, "tests"), "*.cs",
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

    private static string Read(string relativePath) =>
        File.ReadAllText(Path.Combine(RepositoryRoot, relativePath.Replace('/', Path.DirectorySeparatorChar)));

    private static string RepositoryRoot { get; } = Locate();

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".github")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Racine du dépôt introuvable.");
    }
}
