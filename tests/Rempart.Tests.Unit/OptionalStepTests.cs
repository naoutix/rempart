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
/// This is the layer nothing held: <c>grep -rln ScanCommand tests/</c> returned nothing
/// before this file. Two of #162's five lines are in it, and a third — the seal note — is
/// called from it and nowhere else. <c>Rempart.Cli</c> targets
/// <c>net10.0-windows</c> and the Linux job does not compile it, so a test referencing
/// <c>ScanCommand</c> would never run in CI — the source is read instead, the technique
/// <c>CommandSurfaceTests</c> and <c>FieldCollectorRegistrationTests</c> already use, for
/// that same reason. <see cref="Path"/> is legitimate here: these are paths on the machine
/// running the test.
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
/// A guard that reads source can be green because it matches the right thing or green
/// because it stopped looking, and the two are indistinguishable from the pass. So what the
/// reading <em>refuses</em> is pinned below against bodies written in this file — the real
/// body is well-formed, so no assertion on it can exercise a refusal.
/// </para>
/// </summary>
public sealed class ScanCommandStepTests
{
    private const string Door = "OptionalStep.Ran(";

    /// <summary>
    /// An assignment to the scan being built, and what it is assigned. The declaration is
    /// told apart by its <c>var</c>: it is the one assignment that cannot go through the
    /// door, since there is nothing to hand it yet.
    /// </summary>
    private static readonly Regex AssignsTheScan = new(
        @"(?<declaration>\bvar\s+)?\bresult\s*=(?!=)\s*(?<value>[^;\r\n]*)",
        RegexOptions.Compiled);

    /// <summary>
    /// Something the command opens and must close. Anything else it builds — the engine,
    /// a resolution — is a value, not a resource reaching out to a machine or a network.
    /// </summary>
    private static readonly Regex Opened = new(
        @"using\s+var\s+(?<name>\w+)\s*=\s*new\s+(?<type>\w+)\s*\(",
        RegexOptions.Compiled);

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
        var (declarations, assignments) = ScanAssignments(RunBody());

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
    /// </summary>
    [Fact]
    public void Every_source_the_command_opens_is_opened_inside_the_door()
    {
        var body = RunBody();
        var opened = Opened.Matches(body);

        Assert.True(opened.Count > 0,
            "Aucune source ouverte dans ScanCommand.Run : la garde ne lit plus rien.");

        var outside = opened
            .Where(match => !Inside(body, match.Index))
            .Select(match => $"{match.Groups["name"].Value} = new {match.Groups["type"].Value}()")
            .ToList();

        Assert.True(outside.Count == 0,
            $"Construites hors de la porte : {Join(outside)}. Un constructeur qui lève coûte "
            + "le rapport entier, et l'enrichissement en dessous n'y peut rien — sa garantie "
            + "commence à son propre appel.");
    }

    /// <summary>
    /// The grammar of both guards, pinned against bodies written here. Each case is a
    /// mutation that leaves the real file's shape almost intact.
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
    /// The shape #162 reports, and the one the assignment guard alone accepts: the source
    /// built outside, used inside. Refused by the second guard, which is why there are two.
    /// </summary>
    [Fact]
    public void A_source_built_outside_the_door_and_used_inside_it_is_refused()
    {
        const string Body = """
            var result = Engine.Run();
            using var reputation = new VirusTotalReputation(key);
            result = OptionalStep.Ran(result, "--virustotal-key", scan => scan with
            {
                Findings = [.. FindingEnrichment.WithReputation(scan.Findings, reputation)],
            });
            """;

        var (_, assignments) = ScanAssignments(Body);

        Assert.True(
            assignments.All(value => value.StartsWith(Door, StringComparison.Ordinal)),
            "La garde d'affectation doit accepter cette forme : c'est bien par la porte que "
            + "le scan est modifié. Sinon la seconde garde ne prouve rien de plus.");

        var opened = Opened.Matches(Body).Single();

        Assert.False(Inside(Body, opened.Index),
            "La construction hors de la porte doit être vue comme telle ; sinon la garde "
            + "passe sur exactement le défaut que #162 rapporte.");
    }

    /// <summary>
    /// The reading half of the same grammar: a source opened inside the door is not
    /// reported. Without this, a guard that answered "outside" to everything would look
    /// just as green on the real file the day the real file stopped conforming.
    /// </summary>
    [Fact]
    public void A_source_built_inside_the_door_is_read_as_inside()
    {
        const string Body = """
            var result = Engine.Run();
            result = OptionalStep.Ran(result, "--fetch-pac", scan =>
            {
                using var fetcher = new LivePacFetcher();
                return scan with { Findings = [.. PacEnrichment.WithRouting(scan.Findings, fetcher)] };
            });
            """;

        var opened = Opened.Matches(Body).Single();

        Assert.True(Inside(Body, opened.Index),
            "Une source construite dans la porte doit être lue comme telle, sinon la garde "
            + "refuse la forme même qu'elle exige.");
    }

    /// <summary>
    /// Whether an offset falls inside one of the door's argument lists, by counting
    /// parentheses from each call. Brace and bracket depth are irrelevant — only the call's
    /// own parentheses close it — and a string literal holding an unbalanced one would be
    /// miscounted, which is why <see cref="Door"/> is the only call scanned.
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
    /// The body of <c>ScanCommand.Run</c>, braces matched from its signature.
    ///
    /// <para>
    /// Sliced rather than read whole, so that a <c>using var</c> legitimately opened by
    /// another method of the file — writing the report bundle, say — is not held to a rule
    /// about the scan. Both ends are checked: a method renamed or reshaped fails here,
    /// loudly, rather than yielding a slice that matches nothing and a green test.
    /// </para>
    /// </summary>
    private static string RunBody()
    {
        const string Signature = "public static int Run(string[] args)";

        var source = RepositoryFiles.Read("src/Rempart.Cli/Commands/ScanCommand.cs");
        var start = source.IndexOf(Signature, StringComparison.Ordinal);

        Assert.True(start >= 0,
            $"« {Signature} » est introuvable dans src/Rempart.Cli/Commands/ScanCommand.cs : "
            + "la commande a été renommée ou déplacée, et cette garde ne lit plus rien.");

        var open = source.IndexOf('{', start);

        Assert.True(open > start,
            $"« {Signature} » n'ouvre aucun bloc : la commande n'a plus la forme que cette "
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

        Assert.Fail($"« {Signature} » ne se referme pas : accolades déséquilibrées.");
        return string.Empty;
    }

    private static string Join(IEnumerable<string> lines)
    {
        var listed = lines.ToList();
        return listed.Count == 0 ? "aucune" : string.Join(" | ", listed);
    }
}
