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
    /// A <c>${{ }}</c> expression inside a <c>run:</c> body is not a value the shell receives:
    /// the runner substitutes its text into the script before any interpreter parses it, so
    /// whatever the expression holds becomes source code. <c>release.yml</c> read the tag that
    /// way three times, from an input <c>workflow_dispatch</c> accepts as free text, on the one
    /// job in this repository that carries <c>contents: write</c> and a <c>GH_TOKEN</c>: a tag
    /// of the form <c>v1.0.0";&lt;command&gt;;"</c> closed the literal and ran the rest.
    ///
    /// <para>
    /// The rule GitHub documents is to bind the expression to the step's <c>env:</c> and read
    /// it back with <c>$env:NAME</c>, where it is data the whole way. That is a rule about a
    /// shape, not about a list of known-bad lines — which is why it is checked here over every
    /// workflow found on disk rather than over the two that exist today. <c>with:</c> blocks
    /// are deliberately out of scope: a value passed as an action input is never handed to a
    /// shell.
    /// </para>
    /// </summary>
    [Fact]
    public void No_workflow_expands_an_expression_inside_a_script_body()
    {
        var examined = 0;
        var offences = new List<string>();

        foreach (var file in Workflows)
        {
            foreach (var (line, body) in ScriptBodies(RepositoryFiles.Read(file)))
            {
                examined++;
                // Singleline: the runner expands an expression whose braces sit on two lines
                // exactly as it expands one on a single line, and without this the guard read
                // the dangerous form as absent.
                offences.AddRange(Regex.Matches(body, @"\$\{\{.*?\}\}", RegexOptions.Singleline)
                    .Select(match => $"{file}:{line + body.Take(match.Index).Count(c => c == '\n')}"
                        + $" → {Regex.Replace(match.Value, @"\s+", " ").Trim()}"));
            }
        }

        Assert.True(examined > 0,
            "Aucun bloc run: n'a été extrait des workflows : soit ils n'exécutent plus rien, "
            + "soit ce test ne sait plus les lire, et il passerait au vert quoi qu'il arrive.");

        Assert.True(offences.Count == 0,
            "Une expression ${{ }} est développée à l'intérieur d'un corps de script — "
            + string.Join(" ; ", offences)
            + ". Le runner y colle le texte brut avant que l'interpréteur ne l'analyse : une "
            + "valeur portant un guillemet referme le littéral, et ce qui suit s'exécute avec "
            + "les droits du job — c'est ainsi que l'étiquette de release, texte libre venu "
            + "de workflow_dispatch, atteignait un runner portant contents: write et un "
            + "GH_TOKEN. Lier la valeur au bloc env: du step, puis la lire par $env:NOM.");
    }

    /// <summary>
    /// The stick <c>release.yml</c> assembles and the folder <c>verify.ps1</c> runs the binary
    /// from must hold the same things.
    ///
    /// <para>
    /// This is the guard that was missing, and its absence shipped a release that could not
    /// run a single scan. <c>release.yml</c> copied the repository's <c>rules/</c> beside the
    /// executable, where the binary picks it up as an <em>external</em> catalogue — and the
    /// 82 shipped rules are compiled into the binary, so all 82 identifiers collided and
    /// <see cref="Rempart.Core.Rules.RuleCatalog"/> refused to load, exactly as it was written
    /// to. Nothing caught it because nothing ever ran the artifact in the shape it ships: the
    /// workflow scanned from the publish folder, before assembly, and this script copied the
    /// executable alone into a sandbox.
    /// </para>
    ///
    /// <para>
    /// Equality, not inclusion, and in both directions. A file the release adds and the script
    /// does not is a shape nobody runs before a tag — the defect above. A file the script adds
    /// and the release does not is the quieter mirror: the local run then proves a layout no
    /// user receives, which is how a check stops meaning what its name says.
    /// </para>
    /// </summary>
    [Fact]
    public void The_release_stick_and_the_folder_the_local_script_runs_hold_the_same_files()
    {
        var shipped = StagedItems(RepositoryFiles.Read(Release), @"\$stage");
        var local = LocalStickContents();

        Assert.True(shipped.Count > 0,
            $"Aucune copie vers le dossier de la clé trouvée dans {Release} : soit l'assemblage "
            + "a changé de forme, soit ce test ne le lit plus.");

        Assert.True(local.Count > 0,
            $"$stickContents est introuvable ou vide dans {Verify} : le script ne construit "
            + "plus la disposition qu'il prétend éprouver.");

        var onlyShipped = shipped.Except(local, StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.Ordinal).ToList();
        var onlyLocal = local.Except(shipped, StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.Ordinal).ToList();

        Assert.True(onlyShipped.Count == 0 && onlyLocal.Count == 0,
            "La clé livrée et le dossier éprouvé en local ne portent pas les mêmes fichiers — "
            + $"{Release} seul : [{string.Join(", ", onlyShipped)}] ; {Verify} seul : "
            + $"[{string.Join(", ", onlyLocal)}]. Ce qui n'est posé que dans la clé n'est "
            + "exécuté nulle part avant un tag : c'est ainsi qu'un dossier rules/ livré à côté "
            + "d'un binaire qui embarque déjà ces règles a produit une release dont chaque scan "
            + "s'arrêtait sur 82 identifiants en double.");
    }

    /// <summary>
    /// The items every <c>Copy-Item</c> places in the given destination variable, reduced to
    /// bare names — <c>src/…/rempart.exe</c> and <c>rempart.exe</c> are the same item of the
    /// stick, and the workflow names it by the path it is built at.
    /// </summary>
    private static HashSet<string> StagedItems(string script, string destination) =>
        Regex.Matches(script, @"Copy-Item\s+(?<sources>.+?)\s+" + destination + @"\b")
            .SelectMany(match => Regex.Matches(match.Groups["sources"].Value, @"""([^""]+)""")
                .Select(quoted => quoted.Groups[1].Value))
            .Select(path => path.Trim('/').Split('/').Last())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The <c>$stickContents</c> array of verify.ps1, read by name for the same reason
    /// <see cref="LocalDiagnostics"/> reads <c>$aotDiagnostics</c> that way: scanning the file
    /// for names would let a mention in a comment satisfy the guard while the script copies
    /// nothing.
    ///
    /// <para>
    /// The script declares the list instead of having it inferred from its <c>Copy-Item</c>
    /// calls, because one of those copies its source from a variable holding a build path —
    /// unreadable from here without reimplementing PowerShell variable resolution, which is
    /// the kind of parser this file already refused to write once.
    /// </para>
    /// </summary>
    private static HashSet<string> LocalStickContents()
    {
        var declaration = Regex.Match(RepositoryFiles.Read(Verify),
            @"\$stickContents\s*=\s*@\(([^)]*)\)");

        return declaration.Success
            ? Regex.Matches(declaration.Groups[1].Value, "'([^']+)'")
                .Select(match => match.Groups[1].Value)
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
            : [];
    }

    /// <summary>
    /// Every workflow, <em>enumerated from disk</em> rather than named.
    ///
    /// <para>
    /// Listing them by name was this guard's own version of the defect it exists to catch. A
    /// fourth workflow carrying the historical <c>{0, 3}</c> passed green: proven by dropping
    /// a <c>nightly.yml</c> in, whole suite still passing. The debt being closed here is "the
    /// same fact written by hand in several files that nothing relates" — writing the file
    /// list by hand reproduced it one level up.
    /// </para>
    /// </summary>
    private static string[] Workflows { get; } =
    [
        .. Directory
            .EnumerateFiles(Path.Combine(RepositoryFiles.Root, ".github", "workflows"))
            // Both spellings. Actions runs a .yaml exactly as it runs a .yml, so a guard
            // that reads one of them is the hand-written list one directory up: today the
            // folder happens to hold only .yml files, and "happens to" is the whole defect.
            .Where(path => path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            .Select(path => Path.GetRelativePath(RepositoryFiles.Root, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.Ordinal),
    ];

    /// <summary>
    /// Every file that decides whether a scan counts as having succeeded — the workflows,
    /// plus the local script.
    /// </summary>
    private static string[] Files { get; } = [.. Workflows, Verify];

    /// <summary>
    /// The body of every <c>run:</c> of a workflow, paired with the line its key sits on.
    ///
    /// <para>
    /// Read by indentation rather than by a YAML parser, and the shape is what makes that
    /// enough: whichever scalar style the key uses — <c>|</c>, <c>&gt;</c> or a plain value
    /// spilling onto the next lines — the body is exactly the run of lines indented past the
    /// <c>run:</c> key. Stopping at the first line that is not tells the guard where the
    /// sibling keys resume, which is what keeps an <c>env:</c> block out of the text it
    /// examines: binding an expression there is the fix, not the defect.
    /// </para>
    /// </summary>
    private static List<(int Line, string Body)> ScriptBodies(string workflow)
    {
        var lines = workflow.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var bodies = new List<(int, string)>();

        for (var index = 0; index < lines.Length; index++)
        {
            var opening = Regex.Match(lines[index], @"^(?<lead>[ ]*(?:-[ ]+)?)run:(?<rest>.*)$");
            if (!opening.Success)
            {
                continue;
            }

            var column = opening.Groups["lead"].Length;

            // `defaults: run:` spells the same key and is a mapping, not a script:
            // `working-directory: ${{ github.workspace }}` under it is legitimate and reaches
            // no shell. Told apart by the key it hangs from rather than by its own shape,
            // because a step may legally write `run:` with the script on the lines below.
            if (EnclosingKey(lines, index, column) == "defaults")
            {
                continue;
            }

            var body = new List<string> { opening.Groups["rest"].Value };

            var next = index + 1;
            for (; next < lines.Length; next++)
            {
                var line = lines[next];
                if (line.Trim().Length > 0 && line.Length - line.TrimStart().Length <= column)
                {
                    break;
                }

                body.Add(line);
            }

            bodies.Add((index + 1, string.Join('\n', body)));
            index = next - 1;
        }

        return bodies;
    }

    /// <summary>
    /// The mapping key a line hangs from: the nearest line above it that is less indented and
    /// ends on a key. Enough to tell <c>defaults: run:</c> from a step's, which is the only
    /// question asked of it, and it stops at the first candidate rather than modelling the
    /// document — a YAML parser is what this file has already refused to write once.
    /// </summary>
    private static string? EnclosingKey(string[] lines, int index, int column)
    {
        for (var above = index - 1; above >= 0; above--)
        {
            var line = lines[above];
            if (line.Trim().Length == 0)
            {
                continue;
            }

            if (line.Length - line.TrimStart().Length >= column)
            {
                continue;
            }

            var key = Regex.Match(line, @"^[ ]*(?:-[ ]+)?(?<key>[A-Za-z0-9_-]+):\s*$");
            return key.Success ? key.Groups["key"].Value : null;
        }

        return null;
    }

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
