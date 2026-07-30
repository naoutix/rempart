using System.Text.RegularExpressions;
using Rempart.Core.Cli;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Reports;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The door every step that runs beside a finished scan goes through, and what it answers
/// for: building the source, using it, disposing of it.
///
/// <para>
/// Each enrichment already guards its own call — <c>FindingEnrichment</c> answers for
/// <c>IReputationSource.Lookup</c>, <c>PacEnrichment</c> for <c>IPacFetcher.Fetch</c> — and
/// every one of those guarantees stops at the same place. The source is built one line
/// above them, in <c>ScanCommand</c>, where nothing stands between an exception and the
/// catch-all of <c>Program</c>: a complete scan, one statement from being written out,
/// thrown away for an enrichment the run could do without.
/// </para>
/// </summary>
public sealed class OptionalStepTests
{
    /// <summary>A source whose constructor fails, the case no enrichment can guard.</summary>
    private sealed class UnbuildableSource : IDisposable
    {
        public UnbuildableSource() =>
            throw new FormatException("la clé ne peut pas voyager dans un en-tête");

        public void Dispose()
        {
        }
    }

    /// <summary>A source that closes badly — the third of the three moments.</summary>
    private sealed class UndisposableSource : IDisposable
    {
        public void Dispose() => throw new IOException("socket déjà fermé");
    }

    private static ScanResult Finished(params Finding[] findings) =>
        new("1.0.0", "2026-07-30T00:00:00Z", [], [], [.. findings], null, "abc",
            DataFreshness.At("2026-07-01T00:00:00Z", "2026-07-30T00:00:00Z"));

    private static Finding Autorun() =>
        new("autorun", "Run", "x.exe", FindingSeverity.Suspicious, ["Persistance."],
            new Dictionary<string, string>(StringComparer.Ordinal));

    /// <summary>
    /// The source cannot be built — the moment no enrichment can answer for, because the
    /// object it would be handed does not exist yet. This is #162's <c>ScanCommand:93</c>.
    /// </summary>
    [Fact]
    public void A_source_that_cannot_be_built_costs_a_line_and_not_the_scan()
    {
        AssertRecorded("la source ne se construit pas",
            scan =>
            {
                using var source = new UnbuildableSource();
                return scan with { Findings = [] };
            },
            "la clé ne peut pas voyager dans un en-tête");
    }

    /// <summary>
    /// The source throws in use, with a type no hand-kept list would have foreseen. The
    /// door names none: a list of exception types is a list to keep up to date, and three
    /// of this repository's have been caught short.
    /// </summary>
    [Fact]
    public void A_source_that_throws_in_use_costs_a_line_and_not_the_scan()
    {
        AssertRecorded("la source lève à l'usage",
            _ => throw new InvalidTimeZoneException("panne qu'aucune liste n'aurait prévue"),
            "panne qu'aucune liste n'aurait prévue");
    }

    /// <summary>
    /// The source throws on the way out — the third moment, and the one a guard placed
    /// around the call alone still misses.
    /// </summary>
    [Fact]
    public void A_source_that_throws_while_closing_costs_a_line_and_not_the_scan()
    {
        AssertRecorded("la source lève en se fermant",
            scan =>
            {
                using var source = new UndisposableSource();
                return scan with { Findings = [] };
            },
            "socket déjà fermé");
    }

    private static void AssertRecorded(
        string moment, Func<ScanResult, ScanResult> step, string message)
    {
        var kept = Autorun();

        var after = OptionalStep.Ran(Finished(kept), "--virustotal-key", step);

        Assert.True(after.Findings.Count == 2,
            $"{moment} : le scan terminé compte {after.Findings.Count} constat(s) au lieu de 2. "
            + "Une étape facultative qui échoue ne retire rien de ce qui était déjà trouvé.");

        Assert.Same(kept, after.Findings[0]);

        var line = after.Findings[1];

        Assert.True(line.Gap == AuditGap.Broken,
            $"{moment} : l'étape manquée porte {line.Gap?.ToString() ?? "aucune lacune"}. "
            + "Broken est ce que lit ExitCodes, et relancer en élévation ne la répare pas.");

        Assert.True(line.Severity == FindingSeverity.Notable,
            $"{moment} : sévérité {line.Severity}. Rien n'a été observé, donc rien n'est "
            + "reproché à la machine.");

        Assert.Equal("--virustotal-key", line.Source);

        Assert.True(line.Reasons.Single().Contains(message, StringComparison.Ordinal),
            $"{moment} : la ligne ne porte pas le message de l'échec — « {line.Reasons.Single()} »");

        // The family reaches the reader, which is a second file's business: HTML and
        // Markdown group findings by ReportLabels.Family, and an unlabelled kind falls back
        // to its own identifier — a heading written for the code rather than for whoever
        // has to work out what the report is missing.
        Assert.True(ReportLabels.Family(line.Kind) != line.Kind,
            $"{moment} : la famille « {line.Kind} » n'a pas de libellé dans "
            + "ReportLabels.Family, donc le rapport titre la section avec l'identifiant.");
    }

    /// <summary>
    /// The exit code, because that is the half silence used to cost: a scheduler reads the
    /// number and nothing else, and an enrichment that was asked for and did not happen has
    /// to reach it.
    /// </summary>
    [Fact]
    public void A_step_that_fails_reaches_the_exit_code()
    {
        var after = OptionalStep.Ran(Finished(Autorun()), "--fetch-pac",
            _ => throw new NotSupportedException("schéma file non pris en charge"));

        Assert.Equal(ExitCode.Failure, ExitCodes.ForScan(after));
    }

    /// <summary>
    /// The door is not a filter on the way in: a step that works hands back its own result,
    /// untouched, and adds nothing.
    /// </summary>
    [Fact]
    public void A_step_that_works_is_left_alone()
    {
        var enriched = Finished(Autorun(), Autorun());

        var after = OptionalStep.Ran(Finished(Autorun()), "--probe-dns", _ => enriched);

        Assert.Same(enriched, after);
    }
}

/// <summary>
/// <c>ScanCommand</c> against the door, read as source.
///
/// <para>
/// This is the layer nothing held. Before this file, every mention of <c>ScanCommand</c>
/// anywhere under <c>tests/</c> was prose: two doc comments in <c>VirusTotalTests</c>
/// describing where an exception would end up. No test read the command and none exercised
/// it. Two of #162's five lines are in it, and a third — the seal note — is called from it
/// and nowhere else. <c>Rempart.Cli</c> targets <c>net10.0-windows</c> and neither test
/// project references it, so a test naming <c>ScanCommand</c> would not even compile — the
/// source is read instead, the technique <c>CommandSurfaceTests</c> and
/// <c>FieldCollectorRegistrationTests</c> already use, for that same reason.
/// <see cref="Path"/> is legitimate here: these are paths on the machine running the test.
/// </para>
///
/// <para>
/// Two claims, because one of them alone is answered by a one-token move. That every
/// assignment to the finished scan goes through the door says nothing about where the
/// source was built: <c>using var s = new Source(); result = OptionalStep.Ran(…, scan =&gt;
/// … s …);</c> satisfies it and is exactly the shape #162 reports. That everything the
/// command opens is opened inside the door says nothing about what is done with the scan
/// afterwards. Both, or neither is worth much.
/// </para>
///
/// <para>
/// <b>The second claim is read as a refusal, not as a recognition</b>, and that is the
/// correction this file needed. It first looked for one spelling — <c>using var x = new
/// T(</c> — and reported the matches that fell outside the door. Measured on the delivered
/// tree: dropping the single word <c>using</c> in front of the PAC fetcher left all seven
/// tests green, and so did writing the same construction as a <c>using</c> statement, which
/// leaks nothing, warns nothing under <c>-warnaserror</c>, and takes <c>Dispose</c> out of
/// the door as well. A guard can be green because it matched the right thing or green
/// because it stopped looking, and those two were indistinguishable from the pass. So
/// nothing is recognised any more: <em>no</em> <c>new</c> at all once the scan is finished,
/// and <em>no</em> <c>using</c> anywhere in the method, outside the door. Four further
/// spellings the old grammar walked past — a factory call, a qualified type, a generic
/// type, no <c>using</c> at all — are pinned below beside the two measured ones.
/// </para>
///
/// <para>
/// What the readings <em>refuse</em> is pinned against bodies written in this file: the real
/// body is well-formed, so no assertion on it can exercise a refusal.
/// </para>
/// </summary>
public sealed class ScanCommandStepTests
{
    private const string Command = "src/Rempart.Cli/Commands/ScanCommand.cs";
    private const string Door = "OptionalStep.Ran(";
    private const string Run = "public static int Run(string[] args)";

    private const string Writer =
        "private static bool WriteReportBundle(string[] args, ScanResult result)";

    /// <summary>
    /// An assignment to the scan being built, and what it is assigned. The declaration is
    /// told apart by its <c>var</c>: it is the one assignment that cannot go through the
    /// door, since there is nothing to hand it yet.
    /// </summary>
    private static readonly Regex AssignsTheScan = new(
        @"(?<declaration>\bvar\s+)?\bresult\s*=(?!=)\s*(?<value>[^;\r\n]*)",
        RegexOptions.Compiled);

    /// <summary>
    /// Anything the command opens and has to close again — the <c>using</c> keyword itself,
    /// declaration or statement, whatever produced the value. A factory call is as capable
    /// of throwing as a constructor, and <c>Dispose</c> runs wherever the scope ends.
    /// </summary>
    private static readonly Regex Opens = new(@"\busing\b", RegexOptions.Compiled);

    /// <summary>
    /// Anything the command constructs. Deliberately blind to the type: qualified, generic
    /// or target-typed, a constructor that throws beside a finished scan costs the same
    /// report, and every list of spellings this file tried to keep was one token short.
    /// </summary>
    private static readonly Regex Builds = new(@"\bnew\b", RegexOptions.Compiled);

    /// <summary>
    /// The finished scan is only ever changed behind the door.
    ///
    /// <para>
    /// Every optional step of a scan reaches the report by assigning <c>result</c>, so this
    /// is where a step written outside the door becomes visible. The three that exist —
    /// reputation, PAC, DNS — plus the stick seal all had to be moved for it to hold.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_change_to_the_finished_scan_goes_through_the_door()
    {
        var (declarations, assignments) = ScanAssignments(MethodBody(Run));

        Assert.True(declarations == 1,
            $"{declarations} déclarations de « result » dans ScanCommand.Run, attendu une "
            + "seule. Cette garde suit une variable : deux la rendraient muette sur l'une "
            + "des deux.");

        Assert.True(assignments.Count > 0,
            "Aucune affectation de « result » après sa déclaration : la garde ne lit plus "
            + "rien, et une garde qui n'inspecte rien passe.");

        var outside = assignments
            .Where(value => !value.StartsWith(Door, StringComparison.Ordinal))
            .ToList();

        Assert.True(outside.Count == 0,
            $"Le scan terminé est modifié hors de la porte : {Join(outside)}. Ce qu'une "
            + "étape facultative lève à cet endroit n'a plus rien devant lui que le catch "
            + "de Program : l'audit complet est perdu une instruction avant d'être écrit, "
            + "pour un enrichissement dont le rapport pouvait se passer.");
    }

    /// <summary>
    /// Everything the command opens is opened inside the door — the half #157 left open and
    /// #162 reports, where the guarantee of the enrichment stops at its own call and the
    /// source is built one line above it.
    ///
    /// <para>
    /// The whole method and not only the part after the scan, because a <c>using</c>
    /// declared before it closes after it: the source would be built harmlessly, and its
    /// <c>Dispose</c> would still run with a complete audit standing behind it.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_source_the_command_opens_is_opened_inside_the_door()
    {
        var body = MethodBody(Run);
        var opened = Opens.Matches(body);

        Assert.True(opened.Count > 0,
            "Aucun « using » dans ScanCommand.Run : la garde ne lit plus rien, et une garde "
            + "qui n'inspecte rien passe.");

        var outside = opened
            .Where(match => !Inside(body, match.Index))
            .Select(match => LineAt(body, match.Index))
            .ToList();

        Assert.True(outside.Count == 0,
            $"Ouvertes hors de la porte : {Join(outside)}. Ce qui s'ouvre là lève au "
            + "constructeur ou en se refermant sans que rien ne l'attrape, et "
            + "l'enrichissement en dessous n'y peut rien — sa garantie commence à son "
            + "propre appel.");
    }

    /// <summary>
    /// Once the scan is finished, nothing at all is constructed outside the door.
    ///
    /// <para>
    /// Read as a refusal because every recognition tried here was answered by one token.
    /// Before the finished scan exists the command is still building it, and a constructor
    /// that throws there costs nothing that exists yet; after it, everything that throws
    /// costs a complete audit one statement from being written out, which is the whole of
    /// #162. So the rule is stated on the position rather than on the shape: past that
    /// point, whatever is built is built behind the door.
    /// </para>
    ///
    /// <para>
    /// The price is that a harmless value built there — a list for the console, a
    /// formatter — is refused too, and has to move above the scan or inside the door. Paid
    /// deliberately: a rule with an exemption is a rule with a way through, and this file
    /// has already been answered twice by one token.
    /// </para>
    /// </summary>
    [Fact]
    public void Nothing_is_built_beside_the_finished_scan_outside_the_door()
    {
        var body = MethodBody(Run);
        var finished = FinishedAt(body);

        var built = Builds.Matches(body)
            .Where(match => match.Index > finished)
            .ToList();

        Assert.True(built.Count > 0,
            "Plus rien n'est construit après le scan terminé dans ScanCommand.Run : la "
            + "garde ne lit plus rien. Les trois sources sont-elles parties ailleurs ?");

        var outside = built
            .Where(match => !Inside(body, match.Index))
            .Select(match => LineAt(body, match.Index))
            .ToList();

        Assert.True(outside.Count == 0,
            $"Construites hors de la porte : {Join(outside)}. Un constructeur qui lève coûte "
            + "le rapport entier, et l'enrichissement en dessous n'y peut rien — sa garantie "
            + "commence à son propre appel.");
    }

    /// <summary>
    /// The report bundle is written under a guard as wide as what the guard covers.
    ///
    /// <para>
    /// This is the same reproach the seal note was just fixed on, twenty lines below the
    /// door and left standing: <c>ReportBundle.Build</c> renders the HTML, renders the
    /// Markdown and serialises the JSON, none of which is a write, under a <c>catch</c>
    /// filtered on <c>IOException or UnauthorizedAccessException</c> — and the folder was
    /// named outside the <c>try</c> altogether. What those three throw crossed the filter,
    /// reached the catch-all of <c>Program</c>, and the stick's deliverable was lost with
    /// an English sentence instead of the French one naming the folder.
    /// </para>
    ///
    /// <para>
    /// Read as source, and the reading is worth exactly what it says: that the guard is
    /// placed and shaped as claimed. That the sentence it prints is the right one is not
    /// something any run of this suite can see, because no test project compiles
    /// <c>Rempart.Cli</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void The_report_bundle_is_written_under_a_guard_as_wide_as_its_body()
    {
        var body = MethodBody(Writer);
        var guard = body.IndexOf("try", StringComparison.Ordinal);
        var caught = body.IndexOf("catch", StringComparison.Ordinal);

        Assert.True(guard >= 0 && caught > guard,
            "WriteReportBundle n'a plus la forme « try … catch » que cette garde sait "
            + "lire : elle ne lit plus rien.");

        string[] steps =
        [
            "ReportBundle.FolderName(", "FreeFolder(", "Directory.CreateDirectory(",
            "ReportBundle.Build(", "File.WriteAllText(",
        ];

        foreach (var step in steps)
        {
            var at = body.IndexOf(step, StringComparison.Ordinal);

            Assert.True(at > guard && at < caught,
                $"« {step} » est hors du try de WriteReportBundle. Ce qu'il lève traverse "
                + "jusqu'au catch de Program, et le livrable du bâton est perdu avec une "
                + "phrase anglaise à la place de celle qui nomme le dossier.");
        }

        var opens = body.IndexOf('{', caught);

        Assert.True(opens > caught, "Le catch de WriteReportBundle n'ouvre aucun bloc.");

        Assert.True(!Regex.IsMatch(body[caught..opens], @"\bwhen\b"),
            $"Le catch de WriteReportBundle filtre : « {body[caught..opens].Trim()} ». Son "
            + "corps rend deux rapports et sérialise le troisième ; un filtre est plus "
            + "étroit que ce qu'il couvre dès qu'on nomme la paire évidente.");
    }

    /// <summary>
    /// The grammar of the assignment guard, pinned against bodies written here. Each case is
    /// a mutation that leaves the real file's shape almost intact.
    /// </summary>
    [Theory]
    [InlineData("le scan est modifié sans passer par la porte",
        "var result = Engine.Run(); result = result with { Findings = [] };")]
    [InlineData("la porte est appelée mais son résultat est jeté",
        "var result = Engine.Run(); OptionalStep.Ran(result, \"x\", s => s); result = Other(result);")]
    public void An_assignment_outside_the_door_is_refused(string mutation, string body)
    {
        var (declarations, assignments) = ScanAssignments(body);

        Assert.True(declarations == 1, $"{mutation} : {declarations} déclarations lues.");

        Assert.True(
            assignments.Any(value => !value.StartsWith(Door, StringComparison.Ordinal)),
            $"La forme « {mutation} » a été lue comme conforme : {Join(assignments)}. Une "
            + "garde qui accepte la mutation qu'elle prétend refuser est pire que pas de "
            + "garde.");
    }

    /// <summary>
    /// A second declaration is refused rather than counted as an assignment: the guard
    /// follows one variable, and two of them would let the second escape it entirely.
    /// </summary>
    [Fact]
    public void A_second_declaration_of_the_scan_is_refused()
    {
        var (declarations, _) = ScanAssignments(
            "var result = Engine.Run(); var result = Other();");

        Assert.Equal(2, declarations);
    }

    /// <summary>
    /// The shape #162 reports — the source outside, used inside — in every spelling that
    /// walked past the recognising version of this guard, plus the one it did catch.
    ///
    /// <para>
    /// The first two are the measured ones: dropping <c>using</c>, and the <c>using</c>
    /// statement. Both left the whole class green on the delivered tree, and the second
    /// compiles without a warning under <c>-warnaserror</c>, which makes it the shape
    /// anyone adding a fifth step or sharing one source between two of them would write.
    /// The rest are read straight off the old pattern: it required the keyword, then
    /// <c>new</c>, then an unqualified non-generic type name.
    /// </para>
    ///
    /// <para>
    /// Every case satisfies the assignment guard — the scan really is changed through the
    /// door — which is the point of having two.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("sans le mot using", "var fetcher = new LivePacFetcher();")]
    [InlineData("using instruction", "using (var fetcher = new LivePacFetcher())\n{\n}")]
    [InlineData("using var et new, la seule forme attrapée avant",
        "using var fetcher = new LivePacFetcher();")]
    [InlineData("fabrique au lieu du constructeur", "using var fetcher = Factory.Create();")]
    [InlineData("type qualifié", "using var fetcher = new Pac.LivePacFetcher();")]
    [InlineData("type générique", "using var fetcher = new Fetcher<Pac>();")]
    public void A_source_opened_outside_the_door_is_refused(string spelling, string outside)
    {
        var body = Code($$"""
            var result = Engine.Run();
            {{outside}}
            result = OptionalStep.Ran(result, "--fetch-pac", scan => scan with
            {
                Findings = [.. PacEnrichment.WithRouting(scan.Findings, fetcher)],
            });
            """);

        var (_, assignments) = ScanAssignments(body);

        Assert.True(
            assignments.All(value => value.StartsWith(Door, StringComparison.Ordinal)),
            $"« {spelling} » : la garde d'affectation doit accepter cette forme, c'est bien "
            + "par la porte que le scan est modifié. Sinon la seconde ne prouve rien de plus.");

        var finished = FinishedAt(body);

        var refused =
            Opens.Matches(body).Any(match => !Inside(body, match.Index))
            || Builds.Matches(body)
                .Any(match => match.Index > finished && !Inside(body, match.Index));

        Assert.True(refused,
            $"La forme « {spelling} » a été lue comme conforme. C'est exactement le défaut "
            + "que #162 rapporte, vert : une garde qui accepte la mutation qu'elle prétend "
            + "refuser est pire que pas de garde.");
    }

    /// <summary>
    /// The reading half of the same grammar: a source opened inside the door is not
    /// reported. Without this, a guard that answered "outside" to everything would look
    /// just as green on the real file the day the real file stopped conforming.
    /// </summary>
    [Fact]
    public void A_source_opened_inside_the_door_is_read_as_inside()
    {
        var body = Code("""
            var result = Engine.Run();
            result = OptionalStep.Ran(result, "--fetch-pac", scan =>
            {
                using var fetcher = new LivePacFetcher();
                return scan with { Findings = [.. PacEnrichment.WithRouting(scan.Findings, fetcher)] };
            });
            """);

        var finished = FinishedAt(body);

        Assert.True(Opens.Matches(body).All(match => Inside(body, match.Index)),
            "Une source ouverte dans la porte doit être lue comme telle, sinon la garde "
            + "refuse la forme même qu'elle exige.");

        Assert.True(
            Builds.Matches(body)
                .Where(match => match.Index > finished)
                .All(match => Inside(body, match.Index)),
            "Une construction faite dans la porte doit être lue comme telle, sinon le vert "
            + "du fichier réel ne prouve rien.");
    }

    /// <summary>
    /// Whether an offset falls inside one of the door's argument lists, by counting
    /// parentheses from each call. Brace and bracket depth are irrelevant — only the call's
    /// own parentheses close it — and the string bodies are blanked before this runs, so an
    /// unbalanced one written in a message cannot be miscounted.
    /// </summary>
    private static bool Inside(string body, int offset)
    {
        for (var start = body.IndexOf(Door, StringComparison.Ordinal); start >= 0;
             start = body.IndexOf(Door, start + 1, StringComparison.Ordinal))
        {
            var depth = 0;

            for (var i = start + Door.Length - 1; i < body.Length; i++)
            {
                depth += body[i] switch { '(' => 1, ')' => -1, _ => 0 };

                if (depth == 0)
                {
                    if (offset > start && offset < i)
                    {
                        return true;
                    }

                    break;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Where the finished scan starts existing: the end of the statement that declares it.
    /// </summary>
    private static int FinishedAt(string body)
    {
        var declared = Regex.Match(body, @"\bvar\s+result\b");

        Assert.True(declared.Success,
            "« var result » est introuvable : le scan n'est plus déclaré sous ce nom, et "
            + "cette garde ne sait plus dire où il commence à exister.");

        var depth = 0;

        for (var i = declared.Index; i < body.Length; i++)
        {
            depth += body[i] switch
            {
                '(' or '{' or '[' => 1,
                ')' or '}' or ']' => -1,
                _ => 0,
            };

            if (depth == 0 && body[i] == ';')
            {
                return i;
            }
        }

        Assert.Fail("La déclaration du scan ne se referme pas : délimiteurs déséquilibrés.");
        return 0;
    }

    /// <summary>
    /// How many times the scan is declared, and what every later assignment hands it.
    /// </summary>
    private static (int Declarations, List<string> Assignments) ScanAssignments(string body)
    {
        var declarations = 0;
        var assignments = new List<string>();

        foreach (Match match in AssignsTheScan.Matches(body))
        {
            if (match.Groups["declaration"].Success)
            {
                declarations++;
            }
            else
            {
                assignments.Add(match.Groups["value"].Value.Trim());
            }
        }

        return (declarations, assignments);
    }

    /// <summary>
    /// The body of one method of <c>ScanCommand</c>, braces matched from its signature, with
    /// comments and string bodies already blanked.
    ///
    /// <para>
    /// Sliced rather than read whole, so that a <c>using</c> legitimately opened by another
    /// method of the file is not held to a rule about the scan. Both ends are checked: a
    /// method renamed or reshaped fails here, loudly, rather than yielding a slice that
    /// matches nothing and a green test.
    /// </para>
    /// </summary>
    private static string MethodBody(string signature)
    {
        var source = Code(RepositoryFiles.Read(Command));
        var start = source.IndexOf(signature, StringComparison.Ordinal);

        Assert.True(start >= 0,
            $"« {signature} » est introuvable dans {Command} : la méthode a été renommée ou "
            + "déplacée, et cette garde ne lit plus rien.");

        var open = source.IndexOf('{', start);

        Assert.True(open > start,
            $"« {signature} » n'ouvre aucun bloc : la méthode n'a plus la forme que cette "
            + "garde sait découper.");

        var depth = 0;

        for (var i = open; i < source.Length; i++)
        {
            depth += source[i] switch { '{' => 1, '}' => -1, _ => 0 };

            if (depth == 0)
            {
                return source[open..i];
            }
        }

        Assert.Fail($"« {signature} » ne se referme pas : accolades déséquilibrées.");
        return string.Empty;
    }

    /// <summary>
    /// The same text with its comments and string bodies replaced by spaces, every offset
    /// left where it was.
    ///
    /// <para>
    /// A guard that reads source has to read the code and not the prose around it. The word
    /// "using" appears in a comment of the very method read here, so a refusal stated on
    /// that keyword would be answered — or worse, triggered — by an English sentence.
    /// Parentheses and braces written inside a message would be counted as the code's, and
    /// <c>OptionalStep.Ran(</c> quoted in a comment would open a door that does not exist.
    /// Interpolation holes are kept: they are code.
    /// </para>
    /// </summary>
    private static string Code(string source)
    {
        Assert.True(!source.Contains("\"\"\"", StringComparison.Ordinal),
            "Une chaîne brute est apparue dans ce fichier. Ce blanchiment ne sait pas les "
            + "lire, et une garde qui lit mal est une garde qui passe : la lui apprendre "
            + "ici avant de l'écrire là-bas.");

        var text = source.ToCharArray();

        for (var i = 0; i < text.Length;)
        {
            var next = i + 1 < text.Length ? text[i + 1] : '\0';

            if (text[i] == '/' && next == '/')
            {
                while (i < text.Length && text[i] != '\n')
                {
                    text[i++] = ' ';
                }
            }
            else if (text[i] == '/' && next == '*')
            {
                var closes = source.IndexOf("*/", i, StringComparison.Ordinal);
                var stop = closes < 0 ? text.Length : closes + 2;

                for (; i < stop; i++)
                {
                    if (text[i] != '\n')
                    {
                        text[i] = ' ';
                    }
                }
            }
            else if (text[i] == '\'')
            {
                var end = i + 1;

                while (end < text.Length && text[end] != '\'')
                {
                    end += text[end] == '\\' ? 2 : 1;
                }

                for (var blank = i + 1; blank < Math.Min(end, text.Length); blank++)
                {
                    text[blank] = ' ';
                }

                i = Math.Min(end + 1, text.Length);
            }
            else if (text[i] == '"')
            {
                i = BlankQuoted(text, i);
            }
            else
            {
                i++;
            }
        }

        return new string(text);
    }

    /// <summary>
    /// Blanks one string literal from its opening quote, and answers where it ends. The
    /// prefix decides how: <c>@</c> makes a doubled quote an escaped one rather than the
    /// end, <c>$</c> makes what sits between braces code and not text.
    /// </summary>
    private static int BlankQuoted(char[] text, int quote)
    {
        var prefix = quote;

        while (prefix > 0 && (text[prefix - 1] == '$' || text[prefix - 1] == '@'))
        {
            prefix--;
        }

        var verbatim = new string(text, prefix, quote - prefix).Contains('@');
        var interpolated = new string(text, prefix, quote - prefix).Contains('$');
        var hole = 0;

        for (var i = quote + 1; i < text.Length;)
        {
            var next = i + 1 < text.Length ? text[i + 1] : '\0';

            if (hole > 0)
            {
                hole += text[i] switch { '{' => 1, '}' => -1, _ => 0 };
                i++;
            }
            else if (interpolated && text[i] == '{' && next == '{')
            {
                text[i] = ' ';
                text[i + 1] = ' ';
                i += 2;
            }
            else if (interpolated && text[i] == '{')
            {
                hole = 1;
                i++;
            }
            else if (!verbatim && text[i] == '\\')
            {
                text[i] = ' ';

                if (i + 1 < text.Length)
                {
                    text[i + 1] = ' ';
                }

                i += 2;
            }
            else if (text[i] == '"' && verbatim && next == '"')
            {
                text[i] = ' ';
                text[i + 1] = ' ';
                i += 2;
            }
            else if (text[i] == '"')
            {
                return i + 1;
            }
            else
            {
                if (text[i] != '\n')
                {
                    text[i] = ' ';
                }

                i++;
            }
        }

        return text.Length;
    }

    /// <summary>The line an offset falls on, trimmed — what a refusal has to name.</summary>
    private static string LineAt(string body, int offset)
    {
        var start = body.LastIndexOf('\n', Math.Min(offset, body.Length - 1)) + 1;
        var end = body.IndexOf('\n', offset);

        return body[start..(end < 0 ? body.Length : end)].Trim();
    }

    private static string Join(IEnumerable<string> lines)
    {
        var listed = lines.ToList();
        return listed.Count == 0 ? "aucune" : string.Join(" | ", listed);
    }
}
