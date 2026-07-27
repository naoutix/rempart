using System.Globalization;
using System.Text.RegularExpressions;
using Rempart.Core.Cli;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds <c>scripts/verify.ps1</c> against the workflows it claims to replay, and both
/// against the code they run.
///
/// <para>
/// DET-SCRIPTS is not a theory. The batch that introduced exit code 5 widened both workflows
/// from <c>{0, 3}</c> to <c>{0, 3, 5}</c> and left <c>verify.ps1</c> at <c>{0, 3}</c>: from
/// then on the script would have rejected every correct build on the maintainer's own
/// machine. The only thing that caught it was a reviewer reading three files side by side.
/// Nothing failed. Nothing could have.
/// </para>
///
/// <para>
/// Three ways of closing it were open. Calling <c>verify.ps1</c> from CI would leave a
/// single source of truth, but CI is four jobs running in parallel and the script is
/// sequential: the fast feedback the split buys would be spent to remove a duplication that
/// costs nothing as long as it is watched. Extracting the constants into a shared file means
/// inventing a fourth format and writing a parser for it in PowerShell, in YAML and in C#,
/// to hold two short lists. So: a guard — the technique <c>CoverageSettingsTests</c> already
/// uses for the coverage filter, and the one this repository reaches for whenever an
/// invariant spans files no compiler reads together.
/// </para>
///
/// <para>
/// The lists are extracted from both sides and compared to <em>each other</em>, never to a
/// third list written here: that would only move the drift into this file and leave the
/// guard agreeing with itself. Where a third opinion already exists in compiled code
/// (<see cref="ExitCodes"/>, <see cref="CommandSurface"/>) the scripts are confronted with
/// that instead of with one another.
/// </para>
/// </summary>
public sealed class BuildChainParityTests
{
    private const string Ci = ".github/workflows/ci.yml";
    private const string Release = ".github/workflows/release.yml";
    private const string Verify = "scripts/verify.ps1";
    private const string GlobalJson = "global.json";

    /// <summary>
    /// The exact drift the repository already produced once, in the direction that hurts: a
    /// workflow accepting a code the local script refuses means every correct build is
    /// rejected on the workstation, and the developer is told their code is broken.
    ///
    /// <para>
    /// Equality rather than inclusion, because the other direction is a failure too, just a
    /// quieter one: a script accepting more than CI does turns a red build into a surprise
    /// discovered after the push.
    /// </para>
    /// </summary>
    [Fact]
    public void The_workflows_and_the_local_script_accept_the_same_scan_exit_codes()
    {
        var gates = Files
            .SelectMany(file => AcceptedCodes(file).Select(codes => (File: file, Codes: codes)))
            .ToList();

        // Without this, deleting every gate would leave nothing to disagree with, and the
        // test would pass by having found nothing to check.
        foreach (var file in Files)
        {
            Assert.True(gates.Any(gate => gate.File == file),
                $"Aucune garde de code de sortie trouvée dans {file} : soit le contrôle a "
                + "disparu, soit sa forme a changé et ce test ne lit plus rien.");
        }

        var distinct = gates
            .Select(gate => Describe(gate.Codes))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(distinct.Count == 1,
            "Les codes de sortie acceptés après un scan ne sont pas les mêmes partout : "
            + string.Join(" ; ", gates.Select(gate => $"{gate.File} accepte {Describe(gate.Codes)}"))
            + ". Un workflow qui accepte un code que scripts/verify.ps1 refuse fait rejeter en "
            + "local des builds que la CI valide — c'est exactement ce qui est arrivé quand le "
            + "code 5 est apparu.");
    }

    /// <summary>
    /// The scripts confronted with the contract rather than with each other: three files can
    /// agree perfectly on a number the tool never returns. A gate listing a code no
    /// <see cref="ExitCode"/> carries accepts an outcome that cannot happen, which is a way
    /// of writing a contract nobody has read against the enum that defines it.
    /// </summary>
    [Fact]
    public void Every_exit_code_the_build_chain_accepts_is_one_the_tool_can_return()
    {
        var declared = ExitCodes.All.Select(code => (int)code).ToHashSet();
        var examined = 0;

        foreach (var file in Files)
        {
            foreach (var code in AcceptedCodes(file).SelectMany(gate => gate))
            {
                examined++;
                Assert.True(declared.Contains(code),
                    $"{file} accepte le code de sortie {code}, qui n'est déclaré nulle part "
                    + "dans ExitCode. Une garde qui autorise un code que l'outil ne rend "
                    + "jamais n'autorise rien : elle décrit une autre version du contrat.");
            }
        }

        Assert.True(examined > 0, "Aucun code de sortie n'a été extrait : ce test ne vérifie rien.");
    }

    /// <summary>
    /// <c>verify.ps1</c> advertises itself as "replays locally what CI does" and ran not one
    /// of the four diagnostics the publish job runs against the published binary. Those are
    /// the checks that exist precisely because the Windows suite runs under JIT and the
    /// shipped artifact does not: an interop defect once left WMI dead in the AOT binary
    /// while every test stayed green.
    ///
    /// <para>
    /// Inclusion, not equality: the script may legitimately do more than CI — it already
    /// checks the capture/replay round trip no job runs. What it may not do is less.
    /// </para>
    /// </summary>
    [Fact]
    public void The_local_script_replays_every_diagnostic_the_publish_job_runs()
    {
        var inCi = Regex.Matches(RepositoryFiles.Read(Ci), @"\$exe\s+(diagnose-[a-z0-9-]+)")
            .Select(match => match.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(inCi.Count > 0,
            $"Aucune commande diagnose-* trouvée dans {Ci} : soit le job publish-aot ne les "
            + "exécute plus, soit ce test ne sait plus les lire.");

        var inVerify = LocalDiagnostics();

        Assert.True(inVerify.Count > 0,
            $"$aotDiagnostics est introuvable ou vide dans {Verify} : ce test ne compare "
            + "plus rien.");

        var missing = inCi
            .Except(inVerify, StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0,
            $"{Verify} prétend rejouer la CI mais ne passe pas au binaire publié : "
            + $"{string.Join(", ", missing)}. Ces commandes existent parce qu'un défaut "
            + "d'interop ne se voit ni à la compilation ni sous JIT : les sauter en local, "
            + "c'est ne les découvrir qu'après le push.");
    }

    /// <summary>
    /// The last hand-written link: a command word typed into a workflow or a script is a
    /// string nothing checks. Confronted here with <see cref="CommandSurface"/>, which is
    /// what the dispatch table actually knows.
    /// </summary>
    [Fact]
    public void Every_command_the_build_chain_invokes_exists_in_the_command_surface()
    {
        var invoked = Regex
            .Matches(RepositoryFiles.Read(Ci) + RepositoryFiles.Read(Release),
                @"\$exe\s+([a-z][a-z0-9-]*)")
            .Select(match => match.Groups[1].Value)
            .Concat(Regex
                .Matches(RepositoryFiles.Read(Verify), @"rempart\.exe\s+([a-z][a-z0-9-]*)")
                .Select(match => match.Groups[1].Value))
            .Concat(LocalDiagnostics())
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(invoked.Count > 0, "Aucune commande extraite : ce test ne vérifie rien.");

        var unknown = invoked
            .Where(name => CommandSurface.Find(name) is null)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(unknown.Count == 0,
            "La chaîne de build appelle des commandes que CommandSurface ne déclare pas : "
            + $"{string.Join(", ", unknown)}. Une faute de frappe dans un workflow ne se voit "
            + "qu'au moment où le job rougit, avec un message qui parle d'un code de sortie "
            + "et non d'un nom.");
    }

    /// <summary>
    /// <c>global.json</c> and the <c>dotnet-version</c> band are one decision written twice.
    /// The band is a request made to one installer on one runner; <c>global.json</c> is
    /// checked by MSBuild everywhere, workstation included. Let them name different
    /// major.minor versions and setup-dotnet installs an SDK the build then refuses: the job
    /// stops before compiling a line, on "compatible SDK not found".
    /// </summary>
    [Fact]
    public void The_SDK_lock_and_the_band_the_workflows_ask_for_name_the_same_version()
    {
        var locked = Regex.Match(RepositoryFiles.Read(GlobalJson),
            @"""version""\s*:\s*""(\d+\.\d+)\.\d+");

        Assert.True(locked.Success,
            "global.json ne déclare plus de version de SDK : le verrou a disparu, et la "
            + "machine qui compile redevient celle qui décide avec quoi.");

        var bands = new[] { Ci, Release }
            .SelectMany(file => Regex
                .Matches(RepositoryFiles.Read(file), @"dotnet-version:\s*'([^']+)'")
                .Select(match => (File: file, Band: match.Groups[1].Value)))
            .ToList();

        Assert.True(bands.Count > 0,
            "Aucune bande dotnet-version trouvée dans les workflows : ce test ne compare rien.");

        var expected = locked.Groups[1].Value + ".";

        foreach (var (file, band) in bands)
        {
            Assert.True(band.StartsWith(expected, StringComparison.Ordinal),
                $"{file} demande le SDK « {band} » alors que global.json verrouille "
                + $"{locked.Groups[1].Value}.x : setup-dotnet installerait une version que la "
                + "compilation refuserait ensuite.");
        }
    }

    /// <summary>
    /// An SDK version with no <c>rollForward</c> defaults to <c>latestPatch</c>, which pins
    /// the feature band. The runner images refresh their preinstalled SDK every few weeks,
    /// so the day the '10.0.x' band resolves to a higher feature band every job would stop
    /// on a commit that changed nothing. Deleting the line is a silent way of choosing the
    /// strictest policy there is.
    /// </summary>
    [Fact]
    public void The_SDK_lock_states_its_roll_forward_policy()
    {
        // Assert.Matches on its own fails with "Pattern not found in value", which tells a
        // maintainer nothing about what breaks. Every other guard in this file names the
        // consequence; this one used to be the exception.
        Assert.True(
            Regex.IsMatch(RepositoryFiles.Read(GlobalJson), @"""rollForward""\s*:\s*""[a-zA-Z]+"""),
            "global.json ne déclare plus de politique rollForward. Sans elle, le défaut est "
            + "« latestPatch » : la bande de fonctionnalités est figée, et le premier jour "
            + "où l'image du runner passe à la suivante, tous les jobs s'arrêtent sur "
            + "« compatible SDK not found » — pour un commit qui n'a rien changé.");
    }

    /// <summary>
    /// Windows PowerShell 5.1 reads a script with no byte-order mark as ANSI, not as UTF-8.
    /// Every accented character and every em dash in these files then decodes to something
    /// else, and one of those something-elses is fatal: the em dash <c>U+2014</c> becomes
    /// three characters ending in <c>U+201D</c>, a closing double quote, which PowerShell
    /// honours as a string delimiter.
    ///
    /// <para>
    /// Measured on this machine, not reasoned about: the same line printed mojibake inside
    /// single quotes and made the whole file fail to parse inside double quotes — which is
    /// how it was found, by moving one existing sentence from one kind of quote to the
    /// other. <c>verify.ps1</c> already carried the mark; the two scripts it calls did not,
    /// and were surviving only because every non-ASCII character in them happened to sit in
    /// a single-quoted string. That is an invariant nobody could have known they were
    /// maintaining.
    /// </para>
    ///
    /// <para>
    /// CI never sees it — the workflows run <c>pwsh</c> 7, which assumes UTF-8 either way.
    /// It is the maintainer's own shell that breaks, which is exactly the class of defect
    /// DET-SCRIPTS is about: the local path and the CI path quietly stop being the same one.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_script_carrying_non_ASCII_text_is_saved_with_a_byte_order_mark()
    {
        var scripts = Directory
            .EnumerateFiles(RepositoryFiles.Resolve("scripts"), "*.ps1", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(scripts);

        var examined = 0;

        foreach (var script in scripts)
        {
            var bytes = File.ReadAllBytes(script);
            if (!bytes.Any(b => b > 0x7F))
            {
                continue;
            }

            examined++;

            Assert.True(
                bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
                $"{Path.GetFileName(script)} contient du texte non-ASCII sans marque d'ordre "
                + "des octets. Windows PowerShell 5.1 le lira en ANSI : au mieux la sortie est "
                + "illisible, au pire un tiret cadratin dans une chaîne à guillemets doubles "
                + "se termine par U+201D et le script entier cesse de s'analyser.");
        }

        Assert.True(examined > 0,
            "Aucun script non-ASCII trouvé : ce test ne vérifie rien. Il a été écrit contre "
            + "des fichiers qui en contiennent tous.");
    }

    /// <summary>
    /// Every file that decides whether a scan counts as having succeeded — the workflows
    /// <em>enumerated from disk</em>, plus the local script.
    ///
    /// <para>
    /// Listing the workflows by name was this guard's own version of the defect it exists
    /// to catch. A fourth workflow carrying the historical <c>{0, 3}</c> passed green:
    /// proven by dropping a <c>nightly.yml</c> in, whole suite still passing. The debt
    /// being closed here is "the same fact written by hand in several files that nothing
    /// relates" — writing the file list by hand reproduced it one level up.
    /// </para>
    /// </summary>
    private static string[] Files { get; } =
    [
        .. Directory
            .EnumerateFiles(Path.Combine(RepositoryFiles.Root, ".github", "workflows"), "*.yml")
            .Select(path => Path.GetRelativePath(RepositoryFiles.Root, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.Ordinal),
        Verify,
    ];

    /// <summary>
    /// The accepted-code sets of a file, one entry per gate found. The shape is identical in
    /// the script and in the two workflows, which write their gates in <c>pwsh</c> too:
    /// <c>-notin @(0, 3, 5)</c>.
    /// </summary>
    private static List<int[]> AcceptedCodes(string relativePath) =>
        Regex.Matches(RepositoryFiles.Read(relativePath), @"-notin\s*@\(([^)]*)\)")
            .Select(match => match.Groups[1].Value
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(value => int.Parse(value, CultureInfo.InvariantCulture))
                .ToArray())
            .ToList();

    /// <summary>
    /// The <c>$aotDiagnostics</c> array of verify.ps1. Read by name rather than by scanning
    /// the whole file for <c>diagnose-*</c>: a mention in a comment would then satisfy the
    /// guard without the script running anything.
    /// </summary>
    private static HashSet<string> LocalDiagnostics()
    {
        var declaration = Regex.Match(RepositoryFiles.Read(Verify),
            @"\$aotDiagnostics\s*=\s*@\(([^)]*)\)");

        return declaration.Success
            ? Regex.Matches(declaration.Groups[1].Value, "'([^']+)'")
                .Select(match => match.Groups[1].Value)
                .ToHashSet(StringComparer.Ordinal)
            : [];
    }

    private static string Describe(IEnumerable<int> codes) =>
        "{" + string.Join(", ", codes.OrderBy(code => code)) + "}";
}
