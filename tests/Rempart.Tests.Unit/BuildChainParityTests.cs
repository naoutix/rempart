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
    private const string NuGetConfig = "nuget.config";

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
    /// A command line the tool refused to honour never passes for a build that ran.
    ///
    /// <para>
    /// <see cref="ExitCode.Usage"/> exists so that a caller can tell « je n'ai pas compris la
    /// ligne » from « la machine a cassé », and the build chain is the first such caller. A
    /// gate that let <c>6</c> through would turn the smoke tests green on a binary that
    /// scanned nothing at all — the shape of DET-OPTION-INCONNUE moved one level up, where a
    /// job passes while having audited nothing.
    /// </para>
    ///
    /// <para>
    /// Read off the gates rather than compared to a <c>0, 3, 5</c> retyped here. That triple
    /// is what the workflows accept <em>today</em>; the invariant is about <c>6</c>, and it
    /// has to survive the day a gate legitimately widens — which the class summary above says
    /// is the only way a guard like this stays worth running.
    /// </para>
    /// </summary>
    [Fact]
    public void A_usage_error_is_never_a_code_the_build_chain_accepts()
    {
        var examined = 0;

        foreach (var file in Files)
        {
            foreach (var gate in AcceptedCodes(file))
            {
                examined++;
                Assert.True(!gate.Contains((int)ExitCode.Usage),
                    $"{file} accepte le code {(int)ExitCode.Usage} "
                    + $"({ExitCodes.Describe(ExitCode.Usage)}) parmi "
                    + $"{Describe(gate)}. Une ligne de commande que l'outil a refusé "
                    + "d'exécuter passerait alors pour un scan réussi : le job resterait vert "
                    + "sans avoir audité quoi que ce soit.");
            }
        }

        Assert.True(examined > 0, "Aucune garde de code de sortie n'a été lue : ce test ne vérifie rien.");
    }

    /// <summary>
    /// The build chain runs the binary on a command line the tool must refuse, and requires
    /// <see cref="ExitCode.Usage"/> back.
    ///
    /// <para>
    /// This is the only place the refusal is actually walked through. <c>Usage.Check</c> is a
    /// pure function of Core and is tested to death there; what connects it to a command line
    /// is four tokens in <c>Program.cs</c>, which the Linux job does not compile and no test
    /// can therefore call. Both halves of that wiring were mutated by a single token and left
    /// the whole suite green: dropping the <c>return</c> from the refusal branch printed
    /// « Rien n'a été exécuté » and then scanned the machine anyway, and handing the check the
    /// exempted command word rescanned it without a word. <c>CommandSurfaceTests</c> now reads
    /// the shape of that branch, which is what a textual guard can do; running the binary is
    /// what proves it, and it costs one line in a step that already exists.
    /// </para>
    ///
    /// <para>
    /// Which invocations count as probes is <see cref="Usage.Check"/>'s own answer, not a
    /// spelling written here: every binary call found in the chain is parsed back into tokens
    /// and submitted to it, so the guard keeps working the day the probe is rewritten with a
    /// different undeclared word — or with a surplus bare argument, the other half of the same
    /// defect.
    /// </para>
    ///
    /// <para>
    /// Both directions, and the second is what the whole chain gets for free: a line the tool
    /// refuses and nobody expected it to is now a red test rather than a job that stops on
    /// « rempart scan failed (6) » the day a tag is cut. So every workflow is walked, and only
    /// the two files that must carry a probe are required to have one.
    /// </para>
    ///
    /// <para>
    /// Since a word naming no command is refused too, the probes now include one — the command
    /// typo that used to be answered by the help with a code of success. That one is worth more
    /// than the other two put together: what changed for it is which of two doors the word
    /// walks into, and no reading of Core can see a door in <c>Rempart.Cli</c>.
    /// </para>
    ///
    /// <para>
    /// One probe per <see cref="RefusalKind"/> rather than one probe, because « at least one
    /// line the tool refuses » stopped distinguishing them the day the command word became
    /// refusable. Misspell the two probes DET-OPTION-INCONNUE exists for — <c>sacn --replay
    /// nowhere.json</c>, <c>scna nowhere.json</c> — and the binary answers 6 to both, so the
    /// workflow's own gates pass, this guard passed, and nothing reached the option branches
    /// any more. Measured, whole suite green.
    /// </para>
    /// </summary>
    [Fact]
    public void The_build_chain_runs_the_binary_on_a_line_the_tool_must_refuse()
    {
        var expected = (int)ExitCode.Usage;
        var ungated = new List<string>();
        var probing = new Dictionary<string, HashSet<RefusalKind>>(StringComparer.Ordinal);

        foreach (var call in Invocations())
        {
            if (Usage.Check(call.Command, call.Typed) is not { } refusal)
            {
                continue;
            }

            if (!call.GatedOnRefusal)
            {
                ungated.Add($"{call.File}:{call.Line} → {call.Text}");
                continue;
            }

            if (!probing.TryGetValue(call.File, out var kinds))
            {
                probing[call.File] = kinds = [];
            }

            kinds.Add(KindOf(call, refusal));
        }

        Assert.True(ungated.Count == 0,
            "La chaîne de build passe au binaire une ligne que l'outil refuse, sans attendre "
            + $"le code {expected} : {string.Join(" ; ", ungated)}. Ou c'est une sonde dont la "
            + "vérification a disparu, ou c'est une commande réelle devenue irrecevable — et "
            + "dans ce second cas le job s'arrêtera sur « rempart scan failed (6) », le jour "
            + "d'une étiquette.");

        foreach (var file in new[] { Ci, Verify })
        {
            var kinds = probing.TryGetValue(file, out var found) ? found : [];

            Assert.True(kinds.Count > 0,
                $"{file} ne passe au binaire aucune ligne que l'outil doit refuser. Le refus "
                + "est écrit dans Core, où tout l'éprouve, et relié à une ligne de commande par "
                + "quelques jetons de Program.cs que le job Linux ne compile pas. Deux "
                + "mutations d'un seul jeton y rouvrent le défaut de bout en bout avec la suite "
                + "entièrement verte : c'est ici, en exécutant le binaire, que cela se voit.");

            var missing = Enum.GetValues<RefusalKind>()
                .Where(kind => !kinds.Contains(kind))
                .ToList();

            Assert.True(missing.Count == 0,
                $"{file} ne sonde pas chaque refus : {string.Join(", ", missing)} n'y est "
                + "éprouvé sur aucune ligne gardée. Les trois branches partent du même "
                + "Usage.Check et arrivent au même code 6, ce qui les rend interchangeables "
                + "pour la garde du workflow : une faute de frappe dans le mot d'une sonde "
                + "d'option — « sacn --replay » pour « scan --replay » — la transforme en "
                + "troisième sonde de mot inconnu, le binaire rend toujours 6, et plus rien "
                + "n'éprouve l'option ni l'argument nu de bout en bout. Le mot est décidé par "
                + "CommandSurface, l'option et l'argument par la phrase que l'outil imprime : "
                + "aucune orthographe n'est écrite ici.");
        }
    }

    /// <summary>
    /// The build chain runs the binary on the lines this refusal promised not to touch, and
    /// requires <see cref="ExitCode.Success"/> back.
    ///
    /// <para>
    /// Refusing the command word made <c>Program.cs</c>'s first token load-bearing, and nothing
    /// was watching it. <c>WordAt(args, 0) ?? Usage.Fallback</c> is the whole of what keeps
    /// <c>rempart --help</c> and bare <c>rempart</c> out of the check; write
    /// <c>?? args[0]</c> instead and <c>rempart --help</c> answers 6, having printed a refusal
    /// naming <c>--help</c> as a command nobody declares. Measured: whole suite green, because
    /// the check is a pure function of Core and every unit test of the exemption hands it
    /// <see cref="Usage.Fallback"/> itself. That same mutation over the previous behaviour was
    /// inert — the word went to the dispatch table's fallback arm and the help was printed
    /// anyway — so this exposure is the correction's own, and the natural shape of the next
    /// question in this series (<c>rempart --json</c> still exits 0) is exactly that mutation.
    /// </para>
    ///
    /// <para>
    /// Both shapes are required, and the second is the one that bites: a line carrying no
    /// command word but carrying tokens is where the boundary sits, and bare <c>rempart</c>
    /// alone would survive the mutation above. The exempted word typed out is the third, for
    /// the same reason the refusal has a probe per branch rather than one — it is the only one
    /// of the three that reaches the dispatch table.
    /// </para>
    ///
    /// <para>
    /// Of the shape that carries tokens, <em>every</em> declared spelling is required rather
    /// than one of them, and that list is <see cref="CommandSurface.HelpFlags"/> rather than a
    /// list written here. Those spellings are what now tells <c>rempart --help</c> from
    /// <c>rempart -scan</c>, which used to be the same line to this tool; each one is a
    /// promise that a person's line goes on working, and a promise held by nothing but its
    /// sibling's probe is one that the day it breaks nobody measures. <c>-h</c> in particular
    /// answered <c>0</c> by accident before it was declared, and the accident is exactly what
    /// this change removed.
    /// </para>
    /// </summary>
    [Fact]
    public void The_build_chain_runs_the_binary_on_the_lines_the_refusal_must_not_touch()
    {
        var bare = new List<string>();
        var exemptedWord = new List<string>();
        var spelled = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);

        foreach (var call in Invocations().Where(call => call.GatedOnSuccess))
        {
            if (call.Word is null)
            {
                if (call.Typed.Length == 0)
                {
                    bare.Add(call.File);
                    continue;
                }

                if (!spelled.TryGetValue(call.File, out var found))
                {
                    spelled[call.File] = found = [];
                }

                found.Add(call.Typed[0]);
            }
            else if (string.Equals(call.Word, Usage.Fallback, StringComparison.Ordinal))
            {
                exemptedWord.Add(call.File);
            }
        }

        // The premise: the day nothing is declared, every requirement below about a line
        // carrying tokens would be satisfied by an empty demand, and the boundary this guard
        // exists for would stop being run at all.
        Assert.NotEmpty(CommandSurface.HelpFlags);

        foreach (var file in new[] { Ci, Verify })
        {
            var typed = spelled.TryGetValue(file, out var found) ? found : [];

            var missing = CommandSurface.HelpFlags
                .Where(flag => !typed.Contains(flag))
                .ToList();

            Assert.True(missing.Count == 0,
                $"{file} ne lance pas le binaire sur ces lignes en exigeant 0 : "
                + $"{string.Join(", ", missing.Select(flag => $"« rempart {flag} »"))}. Ce sont "
                + "des lignes qui portent des jetons sans mot de commande, c'est-à-dire la "
                + "frontière même du refus : elle tient à « WordAt(args, 0) ?? Usage.Fallback » "
                + "dans Program.cs, et « ?? args[0] » à la place fait rendre 6 à "
                + "« rempart --help » avec toute la suite verte, parce que rien ici ne compile "
                + "Rempart.Cli et que les tests de l'exemption passent Usage.Fallback "
                + "eux-mêmes. Seul le binaire franchit cette porte.");

            Assert.True(bare.Contains(file),
                $"{file} ne lance jamais le binaire sans aucun argument en exigeant 0. "
                + "« rempart » seul est la première ligne que tape qui découvre l'outil, et "
                + "c'est la moitié du contrat que le refus du mot de commande promet de ne pas "
                + "toucher.");

            Assert.True(exemptedWord.Contains(file),
                $"{file} ne lance jamais le binaire sur « rempart {Usage.Fallback} » en "
                + "exigeant 0. C'est la seule des trois lignes d'aide qui traverse le contrôle "
                + "puis la table de dispatch : les deux autres s'arrêtent à l'exemption.");
        }
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
    ///
    /// <para>
    /// The calls the chain gates on <see cref="ExitCode.Usage"/> are left out, and that is the
    /// one exemption: a line written to be refused names a word on purpose, and the probe for
    /// the command typo names one that must never exist. Excluding on « the word is unknown »
    /// instead would have made this test vacuous the day it was written: every typo would
    /// exempt itself.
    /// </para>
    ///
    /// <para>
    /// What the exemption does let through is a typo written <em>inside</em> a gated probe, and
    /// that is watched next door rather than here:
    /// <see cref="The_build_chain_runs_the_binary_on_a_line_the_tool_must_refuse"/> requires one
    /// gated probe per branch of the refusal, so a misspelt <c>sacn --replay nowhere.json</c>
    /// takes the option branch's only end-to-end probe away and is red there. Measured before
    /// that requirement existed: both DET-OPTION-INCONNUE probes misspelt, the binary answering
    /// 6 to each, CI green and the whole suite green.
    /// </para>
    ///
    /// <para>
    /// The premise is on the calls and not on the total: <c>LocalDiagnostics</c> alone
    /// satisfies « something was extracted », so were the exemption to swallow every call this
    /// test would go on checking four names and pass its own emptiness check.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_command_the_build_chain_invokes_exists_in_the_command_surface()
    {
        var typed = Invocations()
            .Where(call => !call.GatedOnRefusal)
            .Select(call => call.Word)
            .OfType<string>()
            .ToList();

        Assert.True(typed.Count > 0,
            "Aucun appel du binaire portant un mot de commande n'a survécu à l'exemption : ce "
            + "test ne lit plus que $aotDiagnostics, et passerait quelle que soit la ligne "
            + "écrite dans un workflow.");

        var invoked = typed
            .Concat(LocalDiagnostics())
            .ToHashSet(StringComparer.Ordinal);

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
    /// A workflow with no <c>permissions:</c> block runs with whatever the repository default
    /// grants — a decision taken in a settings page, invisible from the file, and applied to
    /// every job at once. <c>ci.yml</c> had none: five jobs that do nothing but read the code
    /// and upload artifacts, which travel on the Actions runtime token and not on this one.
    ///
    /// <para>
    /// Checked over every workflow found on disk, and in both halves. That the block exists,
    /// because its absence is not a value anyone chose. And that the file-wide grant stays
    /// read-only: a job that genuinely writes — drafting a release is the only one here — asks
    /// for it on itself, which is also what keeps a workflow called from that file from
    /// inheriting more than reading.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_workflow_names_what_the_token_it_runs_with_may_do()
    {
        foreach (var file in Workflows)
        {
            var block = Regex.Match(RepositoryFiles.Read(file),
                @"(?m)^permissions:(?<inline>[^\n]*)\n(?<body>(?:[ ]+[^\n]*\n|\n)*)");

            Assert.True(block.Success,
                $"{file} ne déclare aucun bloc permissions: au niveau du fichier. Ses jobs "
                + "tournent alors avec le jeton par défaut du dépôt, dont l'étendue se décide "
                + "dans une page de réglages et ne se lit nulle part ici — y compris depuis un "
                + "fork, où ce n'est pas le même réglage. Lire le dépôt suffit à tout ce que "
                + "font ces jobs.");

            var granted = block.Groups["inline"].Value + block.Groups["body"].Value;

            Assert.False(granted.Contains("write", StringComparison.Ordinal),
                $"{file} accorde une écriture à tous ses jobs : « {granted.Trim()} ». Le "
                + "fichier entier n'en a pas besoin : le job qui publie la demande sur "
                + "lui-même, et un workflow appelé depuis celui-là n'hérite alors que de la "
                + "lecture.");
        }
    }

    /// <summary>
    /// Nothing required a tag to name a commit the checks had run on. <c>ci.yml</c> triggers on
    /// a push to main, on <c>pull_request</c> and on <c>workflow_dispatch</c> — not on tags —
    /// and the release job carried neither a <c>needs:</c> nor a test of its own. <c>git push
    /// origin v1.0.1</c> on any commit therefore assembled and drafted a release having run zero
    /// unit tests, zero Windows tests and not the fixture-anonymisation guard. In practice a tag
    /// is cut on main, which passed CI when it was pushed; in practice is not a gate.
    ///
    /// <para>
    /// Two halves, because either alone leaves the hole open. The publishing job must depend on
    /// a job that <em>calls</em> a workflow of this repository — calling rather than restating
    /// the checks keeps one definition of what CI is, where a second copy would be the drift
    /// DET-SCRIPTS describes. And no job may select the ref it builds: with no <c>ref:</c>
    /// anywhere, what is checked out is the commit that triggered the run, which is exactly the
    /// commit the called workflow ran on. Otherwise a <c>workflow_dispatch</c> naming one tag
    /// while started from another ref would ship a commit that was never tested.
    /// </para>
    /// </summary>
    [Fact]
    public void The_workflow_that_publishes_builds_the_commit_the_checks_ran_on()
    {
        var release = RepositoryFiles.Read(Release);
        var jobs = Jobs(release);

        Assert.True(jobs.Count > 1,
            $"Moins de deux jobs lus dans {Release} : soit le fichier a changé de forme, soit "
            + "ce test ne sait plus le découper, et il passerait au vert quoi qu'il contienne.");

        var gates = jobs
            .Select(job => (job.Id, Called: Regex.Match(job.Body, @"(?m)^    uses:\s*(\S+)")))
            .Where(job => job.Called.Success)
            .Select(job => (job.Id, Path: job.Called.Groups[1].Value))
            .ToList();

        Assert.True(gates.Count > 0,
            $"{Release} n'appelle aucun workflow de ce dépôt : rien n'exige donc qu'une "
            + "étiquette pointe un commit ayant passé les contrôles. ci.yml ne se déclenche pas "
            + "sur les tags, et une étiquette posée sur n'importe quel commit assemble une "
            + "release ayant exécuté zéro test.");

        foreach (var (id, path) in gates)
        {
            var called = path.StartsWith("./", StringComparison.Ordinal) ? path[2..] : path;

            Assert.True(Workflows.Contains(called, StringComparer.Ordinal),
                $"Le job « {id} » de {Release} appelle « {path} », qui n'est pas un workflow de "
                + $"ce dépôt — trouvés sur disque : [{string.Join(", ", Workflows)}]. Les "
                + "contrôles qui gardent une étiquette seraient alors définis ailleurs que "
                + "sous .github/workflows, hors de ce que la revue et Dependabot regardent.");

            Assert.True(Regex.IsMatch(RepositoryFiles.Read(called), @"(?m)^\s{2}workflow_call:"),
                $"{Release} appelle {called}, qui ne se déclare pas appelable "
                + "(« workflow_call »). L'exécution s'arrêterait au démarrage, sans job et sans "
                + "journal à consulter — la panne exactement que le job lint-workflows existe "
                + "pour éviter.");
        }

        var gateIds = gates.Select(gate => gate.Id).ToHashSet(StringComparer.Ordinal);

        foreach (var job in jobs.Where(job => !gateIds.Contains(job.Id)))
        {
            var needs = Regex.Match(job.Body, @"(?m)^    needs:\s*(.+)$");

            Assert.True(
                needs.Success && gateIds.Any(gate =>
                    Regex.IsMatch(needs.Groups[1].Value, $@"\b{Regex.Escape(gate)}\b")),
                $"Le job « {job.Id} » de {Release} ne dépend pas des contrôles : il tourne en "
                + $"parallèle de [{string.Join(", ", gateIds)}] et publie quel que soit leur "
                + "résultat. C'est le défaut entier — une étiquette suffit, les tests sont une "
                + "coïncidence.");
        }

        Assert.False(Regex.IsMatch(release, @"(?m)^\s+ref:\s"),
            $"{Release} choisit la référence qu'il extrait. Les contrôles appelés plus haut "
            + "tournent sur le commit qui a déclenché l'exécution : en extraire un autre, ce "
            + "serait livrer un commit et en avoir testé un second. Ne rien passer à checkout "
            + "est ce qui lie les deux.");
    }

    /// <summary>
    /// <c>Copy-Item "README.md", "LICENSE" $stage -ErrorAction SilentlyContinue</c>: the
    /// per-cmdlet <c>-ErrorAction</c> outranks the <c>$ErrorActionPreference = 'Stop'</c> GitHub
    /// sets for <c>shell: pwsh</c>, so a file renamed or missing left the archive without it and
    /// the job green. The stick could be published without its licence.
    ///
    /// <para>
    /// The list guard below compares what the two sides copy, not whether a copy is allowed to
    /// fail: <see cref="StagedItems"/> reads the quoted names and never looks at the switches
    /// after them, which is how both files agreed on a list while one of them treated it as a
    /// wish. Suppressing the error on a copy that assembles a deliverable is the defect whatever
    /// is being copied, so it is checked as a shape over the whole chain rather than on the one
    /// line that carried it.
    /// </para>
    /// </summary>
    [Fact]
    public void No_copy_that_assembles_the_stick_may_fail_without_saying_so()
    {
        var examined = 0;
        var offences = new List<string>();

        foreach (var file in Files)
        {
            var lines = RepositoryFiles.Read(file)
                .Replace("\r\n", "\n", StringComparison.Ordinal)
                .Split('\n');

            for (var index = 0; index < lines.Length; index++)
            {
                if (lines[index].TrimStart().StartsWith('#')
                    || !Regex.IsMatch(lines[index], @"(?<![-\w])Copy-Item\b"))
                {
                    continue;
                }

                examined++;

                var suppressed = Regex.Match(lines[index],
                    @"-ErrorAction\s+(SilentlyContinue|Continue|Ignore)");

                if (suppressed.Success)
                {
                    offences.Add($"{file}:{index + 1} → {suppressed.Value}");
                }
            }
        }

        Assert.True(examined > 0,
            "Aucun Copy-Item trouvé dans la chaîne de build : soit la clé s'assemble "
            + "autrement, soit ce test ne le lit plus et il passerait au vert quoi qu'il "
            + "arrive.");

        Assert.True(offences.Count == 0,
            "Une copie qui assemble le livrable a le droit d'échouer en silence — "
            + string.Join(" ; ", offences)
            + ". Le -ErrorAction du cmdlet l'emporte sur le $ErrorActionPreference = 'Stop' "
            + "que GitHub pose pour shell: pwsh : un fichier renommé ou absent laisse "
            + "l'archive sans lui, et le job reste vert. La clé peut ainsi partir sans sa "
            + "licence.");
    }

    /// <summary>
    /// The two strongest claims of <c>SECURITY.md</c>: CI stops at a <em>draft</em>, and the
    /// archive it attaches is named <c>-unsealed</c> because the publisher key is deliberately
    /// not available to the build. Both were true, and both were held by nothing — dropping
    /// <c>--draft</c> or renaming the archive would publish a release the security policy calls
    /// impossible, with the whole suite green.
    ///
    /// <para>
    /// The arguments are read from the array they are splatted from rather than from the
    /// command line, for the reason <see cref="LocalStickContents"/> gives: resolving PowerShell
    /// variables from here is the parser this file already refused to write once. Renaming that
    /// array makes the guard find nothing, which is what the count assertion is for.
    /// </para>
    /// </summary>
    [Fact]
    public void The_release_the_chain_creates_is_a_draft_carrying_an_unsealed_archive()
    {
        var examined = 0;

        foreach (var file in Workflows)
        {
            var workflow = RepositoryFiles.Read(file);

            foreach (var creation in Regex.Matches(workflow, @"gh release create\s+@(\w+)")
                         .Select(match => match.Groups[1].Value))
            {
                examined++;

                var declaration = Regex.Match(workflow, $@"\${creation}\s*=\s*@\(([^)]*)\)");

                Assert.True(declaration.Success,
                    $"{file} passe @{creation} à « gh release create » sans que ce tableau soit "
                    + "déclaré d'un bloc : ce test ne lit plus les arguments de la publication.");

                var literals = Regex.Matches(declaration.Groups[1].Value, "'([^']+)'")
                    .Select(match => match.Groups[1].Value)
                    .ToList();

                Assert.True(literals.Contains("--draft"),
                    $"{file} crée une release qui n'est pas un brouillon : "
                    + $"[{string.Join(", ", literals)}]. SECURITY.md annonce l'inverse, et c'est "
                    + "la moitié du contrat : la clé d'éditeur n'est pas donnée au build, donc "
                    + "le sceau est posé à la main entre ce job et la publication. Publier ici, "
                    + "c'est livrer une archive que « rempart seal --check » refuse.");

                var archive = Regex.Match(workflow, @"\$zip\s*=\s*""([^""]+)""");

                Assert.True(archive.Success,
                    $"{file} publie une release sans que le nom de l'archive soit lisible ici : "
                    + "la garde ne tient plus rien.");

                Assert.True(archive.Groups[1].Value.EndsWith("-unsealed.zip", StringComparison.Ordinal),
                    $"{file} attache une archive nommée « {archive.Groups[1].Value} ». "
                    + "SECURITY.md dit d'une archive encore nommée « -unsealed » qu'elle n'est "
                    + "pas une release : c'est ce mot qui distingue ce que la CI sait produire "
                    + "de ce que l'éditeur scelle ensuite, et le retirer ici ferait passer le "
                    + "brouillon pour le livrable auprès de quiconque le télécharge.");
            }
        }

        Assert.True(examined > 0,
            "Aucune création de release trouvée dans les workflows : soit rien ne publie plus, "
            + "soit ce test ne le voit plus et les deux affirmations de SECURITY.md "
            + "redeviennent des vœux.");
    }

    /// <summary>
    /// The other half of the same claim, and the one that held only by absence: the publisher
    /// key is not available to CI. No workflow read a secret, and nothing said one may not — a
    /// single <c>secrets.PUBLISHER_KEY</c> added to the release job would falsify SECURITY.md
    /// without a test flinching, on the file whose whole argument is that a signing key held by
    /// the build system signs whatever the build system is told to.
    ///
    /// <para>
    /// Over everything under <c>.github/</c> rather than over the two workflows: a composite
    /// action or a second workflow reads secrets the same way. No legitimate use is being
    /// denied — the ambient token is reached through <c>github.token</c> here — and the day one
    /// is needed it should be a decision, not a diff nobody read.
    /// </para>
    /// </summary>
    [Fact]
    public void Nothing_under_the_github_folder_reads_a_repository_secret()
    {
        var examined = 0;
        var offences = new List<string>();

        foreach (var path in Directory
                     .EnumerateFiles(RepositoryFiles.Resolve(".github"), "*", SearchOption.AllDirectories)
                     .OrderBy(path => path, StringComparer.Ordinal))
        {
            examined++;

            offences.AddRange(Regex.Matches(File.ReadAllText(path), @"secrets\.\w+")
                .Select(match => $"{Path.GetFileName(path)} → {match.Value}"));
        }

        Assert.True(examined > 0, "Aucun fichier lu sous .github/ : ce test ne vérifie rien.");

        Assert.True(offences.Count == 0,
            "Un secret du dépôt est lu depuis .github/ — " + string.Join(" ; ", offences)
            + ". SECURITY.md tient sur le contraire : la clé d'éditeur n'est pas donnée au "
            + "build, et c'est pour cela que l'archive sort « -unsealed » et que le sceau est "
            + "posé à la main. Une clé de signature détenue par le système de construction "
            + "signe ce qu'on lui dit de signer.");
    }

    /// <summary>
    /// <c>verify.ps1</c> wrote <c>ok</c> for a step that had not run. The workflow-lint step
    /// returns early whenever <c>actionlint</c> is absent — deliberately, it is optional and
    /// documented as such in BUILD.md — and the final table then showed a green line
    /// indistinguishable from a real success. "Could not verify" rendered as "verified" is the
    /// one thing this tool refuses to do about a machine; the script that verifies the tool was
    /// doing it.
    ///
    /// <para>
    /// The outcomes are declared as a named map the script uses at every site, and read here by
    /// name for the reason <see cref="LocalDiagnostics"/> gives. What the guard holds is that
    /// there are more than two of them, that each is one the summary knows how to print, and
    /// that the one meaning "did not run" does not fail the run: an unverified check is not a
    /// failure either, and turning a workstation red for a missing optional tool is how a
    /// script gets run with a flag that silences it.
    /// </para>
    /// </summary>
    [Fact]
    public void The_local_script_tells_a_check_it_could_not_run_from_one_that_passed()
    {
        var script = RepositoryFiles.Read(Verify);

        var declaration = Regex.Match(script, @"\$stepStates\s*=\s*\[ordered\]@\{([^}]*)\}");

        Assert.True(declaration.Success,
            $"$stepStates est introuvable dans {Verify} : le script ne déclare plus les issues "
            + "qu'un contrôle peut avoir, et ce test ne lit plus rien.");

        var declared = Regex.Matches(declaration.Groups[1].Value, @"(\w+)\s*=\s*'([^']+)'")
            .ToDictionary(match => match.Groups[1].Value, match => match.Groups[2].Value,
                StringComparer.Ordinal);

        Assert.True(declared.Values.Distinct(StringComparer.Ordinal).Count() == declared.Count,
            "Deux issues de contrôle portent le même mot dans le tableau final : "
            + $"[{string.Join(", ", declared.Select(state => $"{state.Key} = {state.Value}"))}]. "
            + "Elles y sont alors indiscernables, ce que ce test existe précisément pour "
            + "refuser.");

        Assert.True(declared.ContainsKey("skipped"),
            $"{Verify} ne sait dire d'un contrôle que « réussi » ou « échoué ». Celui qui n'a "
            + "pas pu tourner — actionlint absent, par exemple — repart donc avec l'issue du "
            + "succès, et la dernière ligne du tableau est indiscernable d'une vraie "
            + "réussite. « Pas pu vérifier » rendu comme « vérifié » est le défaut que cet "
            + "outil refuse sur une machine.");

        var recorded = Regex.Matches(script, @"State\s*=\s*\$stepStates\.(\w+)")
            .Select(match => match.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(recorded.SetEquals(declared.Keys),
            "Les issues que Step sait inscrire et celles que le script déclare ne sont pas les "
            + $"mêmes — déclarées : [{string.Join(", ", declared.Keys)}] ; inscrites : "
            + $"[{string.Join(", ", recorded)}]. Une issue déclarée que rien n'inscrit ne "
            + "décrit rien, et une inscrite sans être déclarée ne sera pas rendue.");

        var branch = Regex.Match(script,
            @"elseif\s*\(\s*\$step\.State\s*-eq\s*\$stepStates\.skipped\s*\)\s*\{([^}]*)\}");

        Assert.True(branch.Success,
            $"Le tableau final de {Verify} ne distingue plus le contrôle qui n'a pas tourné : "
            + "il le rend comme un succès ou comme un échec, et les deux sont faux.");

        Assert.False(branch.Groups[1].Value.Contains("$failed", StringComparison.Ordinal),
            $"{Verify} fait échouer la vérification sur un contrôle qui n'a pas tourné. Ce "
            + "n'est pas un échec — actionlint est optionnel et documenté comme tel — et un "
            + "script qui rougit sur une machine correcte finit lancé avec le drapeau qui le "
            + "fait taire. Le dire, sans le compter.");
    }

    /// <summary>
    /// The repository pins its actions by commit hash and writes each package version down
    /// exactly once, and then left it to the machine to decide which feeds those packages come
    /// from. Without a <c>nuget.config</c> the source list is assembled from whatever
    /// configuration that machine carries: <c>%AppData%\NuGet</c>, a file dropped higher in the
    /// tree, a feed a build agent was set up with years ago.
    ///
    /// <para>
    /// The two <c>&lt;clear /&gt;</c> are the whole point, and neither is decoration. Without
    /// the first, this file <em>adds</em> to the inherited feeds rather than replacing them.
    /// Without the second, an inherited <c>disabledPackageSources</c> can switch nuget.org off
    /// here, and restore then either fails or resolves elsewhere.
    /// </para>
    ///
    /// <para>
    /// What this does <em>not</em> hold is the resolved graph itself: there is no lock file,
    /// and the file says at length why it was measured and left out.
    /// </para>
    /// </summary>
    [Fact]
    public void The_sources_the_restore_reads_are_named_by_this_repository()
    {
        Assert.True(File.Exists(RepositoryFiles.Resolve(NuGetConfig)),
            $"{NuGetConfig} est absent : la liste des flux dont la restauration tire les "
            + "paquets vient alors de la machine qui compile. Le dépôt épingle ses actions par "
            + "SHA et écrit chaque version de paquet une fois, puis laisse un réglage hors du "
            + "dépôt décider d'où ces paquets arrivent.");

        var config = RepositoryFiles.Read(NuGetConfig);

        Assert.True(Regex.IsMatch(config, @"<packageSources>\s*<clear\s*/>"),
            $"{NuGetConfig} ne vide pas <packageSources> avant de déclarer les siens : il "
            + "ajoute aux flux hérités au lieu de les remplacer, et le dépôt ne décide plus "
            + "d'où viennent ses paquets — il décide seulement d'un flux de plus.");

        Assert.True(Regex.IsMatch(config, @"<disabledPackageSources>\s*<clear\s*/>"),
            $"{NuGetConfig} ne vide pas <disabledPackageSources> : un réglage de la machine "
            + "peut éteindre le seul flux déclaré ici, et la restauration échoue — ou pire, "
            + "résout ailleurs.");
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
    /// Which of <see cref="Usage.Check"/>'s refusals a probe of the build chain walks into.
    ///
    /// <para>
    /// Named here because « at least one refused line » stopped telling them apart the day the
    /// command word became refusable: the two probes DET-OPTION-INCONNUE exists for can be
    /// misspelt into two more command-word probes — <c>sacn --replay nowhere.json</c>,
    /// <c>scna nowhere.json</c> — and the binary still answers 6 to both, so the workflow's own
    /// gates pass and the chain goes on looking exercised while nothing reaches the option
    /// branches any more. Measured: with that pair written into <c>ci.yml</c>, the whole suite
    /// stayed green.
    /// </para>
    /// </summary>
    private enum RefusalKind
    {
        /// <summary>A word <see cref="CommandSurface"/> does not declare.</summary>
        CommandWord,

        /// <summary>
        /// A first token wearing a dash that asks for nothing declared — <c>-scan</c>,
        /// <c>--json</c>.
        ///
        /// <para>
        /// Its own kind rather than a variety of <see cref="CommandWord"/>, because it walks
        /// into the refusal by a different door and that door is the one this repository keeps
        /// finding unguarded: <see cref="CommandLine.WordAt"/> answers <c>null</c>, the line
        /// resolves to <see cref="Usage.Fallback"/>, and it was the exempted command that
        /// decided its fate. Sharing the kind would leave the probe deletable — the
        /// command-word probe alone would satisfy the requirement — which is exactly how a
        /// guard stops holding what its name says.
        /// </para>
        /// </summary>
        DashedWord,

        /// <summary>An option the command does not declare, or one left without its value.</summary>
        Option,

        /// <summary>One bare argument more than the command has a reader for.</summary>
        BareArgument,
    }

    /// <summary>
    /// One call of the binary found in the build chain: where it sits, the tokens the tool
    /// would receive, the command word typed if any, and the exit code the chain demands of it.
    /// </summary>
    private sealed record Invocation(
        string File, int Line, string Text, string? Word, string[] Typed, int? Gate)
    {
        /// <summary>
        /// The word the entry point would resolve this line to, which is
        /// <see cref="Usage.Fallback"/> when the line carries none.
        ///
        /// <para>
        /// A reproduction of <c>Program.cs</c> rather than a reading of it, and it is stated
        /// as such because the repository forbids the second list everywhere else: nothing
        /// here compiles <c>Rempart.Cli</c>. What holds the entry point to it is not this
        /// property but the probes
        /// <see cref="The_build_chain_runs_the_binary_on_the_lines_the_refusal_must_not_touch"/>
        /// requires — <c>rempart --help</c> run by the binary, which answers 0 only if the
        /// resolution really is this one.
        /// </para>
        /// </summary>
        public string Command => Word ?? Usage.Fallback;

        /// <summary>The chain requires this call to be refused.</summary>
        public bool GatedOnRefusal => Gate == (int)ExitCode.Usage;

        /// <summary>The chain requires this call to succeed.</summary>
        public bool GatedOnSuccess => Gate == (int)ExitCode.Success;
    }

    /// <summary>
    /// Every call of the binary the build chain makes, parsed back into the tokens the tool
    /// would receive.
    ///
    /// <para>
    /// One walk read by three guards, for the reason <see cref="CommandLine.Split"/> is one
    /// walk read by two refusals: they judge the same lines from different sides — is a line
    /// the tool refuses gated on that refusal, is a line nobody gated naming a command at all,
    /// and are the lines that must keep working actually run — and one call belongs to several
    /// of those questions at once. Two walks could disagree about where a call stops, and then
    /// a probe would look like a typo to one guard while a typo looked like a probe to another.
    /// </para>
    ///
    /// <para>
    /// Keyed on the call operator rather than on the binary's name, so that a line carrying no
    /// command word at all — <c>&amp; $exe</c>, <c>&amp; $exe --help</c> — is a call like the
    /// rest instead of being invisible; those two are exactly the half of the contract the
    /// command-word refusal promised not to touch. The argument list stops at whatever ends it
    /// in these scripts — a pipe, a closing parenthesis, a separator, a comment — so that
    /// « (&amp; $exe version).Trim() » is not read as a command carrying an argument named
    /// « ).Trim() ».
    /// </para>
    ///
    /// <para>
    /// A call whose arguments come from a variable is left out, because its tokens are not in
    /// the file: <c>&amp; .\rempart.exe $command</c> is the <c>$aotDiagnostics</c> loop, and
    /// <see cref="The_local_script_replays_every_diagnostic_the_publish_job_runs"/> is what
    /// reads it, by name, against the workflow.
    /// </para>
    /// </summary>
    private static List<Invocation> Invocations()
    {
        var found = new List<Invocation>();

        foreach (var file in Files)
        {
            var lines = RepositoryFiles.Read(file)
                .Replace("\r\n", "\n", StringComparison.Ordinal)
                .Split('\n');

            for (var index = 0; index < lines.Length; index++)
            {
                var call = Regex.Match(lines[index],
                    @"&\s*(?:\$exe|(?:\.\\)?rempart\.exe)(?<rest>[^|)\n;#>]*)");

                if (!call.Success || call.Groups["rest"].Value.Contains('$', StringComparison.Ordinal))
                {
                    continue;
                }

                string[] typed = [.. call.Groups["rest"].Value
                    .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)];

                // The gate sits on the line below, or just under the comment explaining it.
                var gate = Regex.Match(string.Join('\n', lines.Skip(index).Take(4)),
                    @"-ne\s+(?<code>\d+)");

                found.Add(new Invocation(
                    file,
                    index + 1,
                    lines[index].Trim(),
                    CommandLine.WordAt(typed, 0),
                    typed,
                    gate.Success
                        ? int.Parse(gate.Groups["code"].Value, CultureInfo.InvariantCulture)
                        : null));
            }
        }

        return found;
    }

    /// <summary>
    /// Which refusal a probe walks into, decided by <see cref="CommandSurface"/> and by the
    /// sentence the tool itself prints — never by a second copy of <see cref="Usage.Check"/>'s
    /// branches written here, which would agree with itself the day one of them stopped firing.
    ///
    /// <para>
    /// The absence of a word first, then the word, because those are the two branches whose
    /// condition is a declaration lookup and nothing else. Past them, the refusal names the
    /// token it is about: an option token it names is an option refused — unknown, or left
    /// without its value — and anything else is the surplus bare argument.
    /// </para>
    /// </summary>
    private static RefusalKind KindOf(Invocation call, FailureExit refusal) =>
        call.Word is null
            ? RefusalKind.DashedWord
            : CommandSurface.Find(call.Word) is null
                ? RefusalKind.CommandWord
                : call.Typed.Skip(1).Any(token => token.StartsWith('-')
                    && refusal.Message.Contains(token, StringComparison.Ordinal))
                    ? RefusalKind.Option
                    : RefusalKind.BareArgument;

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
    /// The jobs of a workflow, each paired with the lines under its key.
    ///
    /// <para>
    /// By indentation again, and for the same reason <see cref="ScriptBodies"/> gives: what is
    /// being read here is a shape these files hold everywhere. A job identifier is a key at two
    /// spaces under <c>jobs:</c>, and its body is everything indented past it — which is what
    /// lets a caller tell a job-level <c>uses:</c> (four spaces) from a step's (deeper, behind
    /// a dash), a distinction the whole gate guard rests on.
    /// </para>
    /// </summary>
    private static List<(string Id, string Body)> Jobs(string workflow)
    {
        var lines = workflow.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var jobs = new List<(string, string)>();
        var body = new List<string>();
        string? current = null;
        var inJobs = false;

        foreach (var line in lines)
        {
            if (Regex.IsMatch(line, @"^jobs:\s*$"))
            {
                inJobs = true;
                continue;
            }

            if (!inJobs)
            {
                continue;
            }

            // A key back at column zero ends the jobs mapping, whatever follows it.
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                break;
            }

            var header = Regex.Match(line, @"^  (?<id>[A-Za-z0-9_.-]+):\s*$");
            if (!header.Success)
            {
                body.Add(line);
                continue;
            }

            if (current is not null)
            {
                jobs.Add((current, string.Join('\n', body)));
            }

            current = header.Groups["id"].Value;
            body = [];
        }

        if (current is not null)
        {
            jobs.Add((current, string.Join('\n', body)));
        }

        return jobs;
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
