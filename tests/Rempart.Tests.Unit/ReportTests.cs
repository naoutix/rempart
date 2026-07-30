using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Reports;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The report renderers. Two properties matter more than the layout, and both come from
/// the same fact: a report is built out of strings chosen by whoever is on the audited
/// machine — service names, command lines, extension titles.
///
/// <list type="number">
///   <item>Markup planted in those strings must appear as text, never execute in the
///   browser of the person reading the audit.</item>
///   <item>A pipe in a path must not shift a Markdown table by one column, which would
///   attribute a value to the wrong field while still looking plausible.</item>
/// </list>
/// </summary>
public sealed class ReportTests
{
    /// <summary>
    /// The payload planted in every machine-supplied field.
    ///
    /// One payload for both renderers rather than one each: a tag, a quote, a pipe, a
    /// link, a code fence and a line break travel together, so neither format can be
    /// exercised on only the half of the hazard that happens to suit it. That split is
    /// exactly how the Markdown findings section came to interpolate five values raw
    /// while thirteen other sites escaped.
    /// </summary>
    private const string Payload =
        "<script>alert('xss')</script> | [rapport](javascript:alert(1)) `fence` <img src=x>\nsuite";

    [Fact]
    public void Html_escapes_markup_planted_in_every_machine_supplied_field()
    {
        var html = HtmlReport.Render(Hostile());

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.DoesNotContain("</script>alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", html,
            StringComparison.Ordinal);

        // The document still closes its own single script block, and only that one.
        Assert.Equal(1, Occurrences(html, "<script>"));
        Assert.Equal(1, Occurrences(html, "</script>"));
    }

    [Fact]
    public void Html_escapes_a_quote_that_would_break_out_of_an_attribute()
    {
        var result = Minimal() with
        {
            Findings = [new Finding("autorun", "HKLM\\…\\Run", "\" onmouseover=\"steal()",
                FindingSeverity.Suspicious, ["non signé"], new Dictionary<string, string>())],
        };

        var html = HtmlReport.Render(result);

        Assert.DoesNotContain("onmouseover=\"steal()", html, StringComparison.Ordinal);
        Assert.Contains("&quot; onmouseover=&quot;steal()", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// "Standalone" is a promise, not a description. A single external reference would
    /// turn opening the report into a network call from the reader's machine — and
    /// would report back that it was opened, and when.
    ///
    /// <para>
    /// What is forbidden is a <em>reference</em>, not the character sequence of a URL:
    /// audit data legitimately contains URLs — an extension's host permissions, a PAC
    /// address, a proxy — and hiding them would defeat the point of the report. They
    /// are rendered as inert escaped text, which the next test pins down.
    /// </para>
    /// </summary>
    [Fact]
    public void Html_references_nothing_outside_itself()
    {
        var html = HtmlReport.Render(Populated());

        foreach (var reference in new[]
                 {
                     "<link", "<img", "<iframe", "<object", "<embed", "<base",
                     "@import", "url(", " src=", " href=", "srcset",
                 })
        {
            Assert.DoesNotContain(reference, html, StringComparison.OrdinalIgnoreCase);
        }

        // Nor may the script reach out on its own.
        foreach (var call in new[]
                 {
                     "fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import(",
                     "eval(", "innerHTML",
                 })
        {
            Assert.DoesNotContain(call, html, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// A URL found on the machine is shown, and stays text. Turning it into a link
    /// would put one click between an audit report and the very address it flags.
    /// </summary>
    [Fact]
    public void A_url_found_on_the_machine_is_displayed_without_becoming_a_link()
    {
        var result = Minimal() with
        {
            Findings =
            [
                new Finding("proxy", "AutoConfigURL", "http://attaquant.example/proxy.pac",
                    FindingSeverity.Suspicious, ["PAC externe non imposé par stratégie"],
                    new Dictionary<string, string>
                    {
                        ["pac"] = "http://attaquant.example/proxy.pac",
                    }),
            ],
        };

        var html = HtmlReport.Render(result);

        Assert.Contains("http://attaquant.example/proxy.pac", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<a ", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(" href=", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Html_shows_the_failures_the_findings_and_the_score()
    {
        var html = HtmlReport.Render(Populated());

        Assert.Contains("WIN-CRED-001", html, StringComparison.Ordinal);
        Assert.Contains("LSA Protection", html, StringComparison.Ordinal);
        Assert.Contains("pilote-douteux.sys", html, StringComparison.Ordinal);
        Assert.Contains("72 %", html, StringComparison.Ordinal);
        Assert.Contains("POSTE-01", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A partial score read without its caveat is a score that misleads: the reader
    /// takes 100 % of what could be read for 100 % of the machine.
    /// </summary>
    [Fact]
    public void Html_and_markdown_open_on_the_caveat_when_the_scan_was_not_elevated()
    {
        var result = Populated();

        Assert.Contains("Scan non élevé", HtmlReport.Render(result), StringComparison.Ordinal);
        Assert.Contains("Score partiel", HtmlReport.Render(result), StringComparison.Ordinal);
        Assert.Contains("Scan non élevé", MarkdownReport.Render(result), StringComparison.Ordinal);
    }

    /// <summary>
    /// The notes travel inside the result, so that re-rendering from the JSON keeps
    /// them (ADR-002, D17): "the update was refused" is the sentence that must never
    /// go missing between a scan and the report someone reads.
    /// </summary>
    [Fact]
    public void Reports_state_whether_an_update_was_applied_or_refused()
    {
        var result = Minimal() with
        {
            UpdateNote = "Mise à jour présente mais refusée : signature inconnue.",
            IntegrityNote = "Sceau vérifié : 3 fichiers conformes.",
        };

        Assert.Contains("signature inconnue", HtmlReport.Render(result), StringComparison.Ordinal);
        Assert.Contains("Sceau vérifié", MarkdownReport.Render(result), StringComparison.Ordinal);

        var reread = RempartJson.DeserialiseScanResult(RempartJson.Serialise(result));
        Assert.Contains("signature inconnue", HtmlReport.Render(reread), StringComparison.Ordinal);
    }

    /// <summary>
    /// An unescaped pipe does not break the render — it shifts every following column by
    /// one, so the row stays plausible while naming the wrong value. Service paths and
    /// command lines carry pipes routinely.
    /// </summary>
    [Fact]
    public void Markdown_keeps_a_table_row_intact_when_a_value_contains_a_pipe()
    {
        var result = Minimal() with
        {
            Verdicts =
            [
                new Verdict("WIN-X-001", "Contrôle", Severity.High, "réseau",
                    VerdictStatus.Fail, @"cmd.exe /c a | b", "aucun"),
            ],
            Score = new ScoreCard(0, [new DomainScore("réseau", 0, 1, 0, 0, 0)], 0),
        };

        var markdown = MarkdownReport.Render(result);
        var row = markdown.Split('\n').Single(l => l.Contains("WIN-X-001", StringComparison.Ordinal));

        Assert.Contains(@"a \| b", row, StringComparison.Ordinal);

        // Five columns, so six delimiters — counting only the pipes that still act as
        // one. That count is the whole point: an escaped pipe stays inside its cell,
        // an unescaped one would open a sixth column and shift every value right.
        Assert.Equal(6, Delimiters(row));
    }

    [Fact]
    public void Markdown_flattens_a_newline_that_would_end_a_table_row()
    {
        var result = Minimal() with
        {
            Collectors =
            [
                new CollectorResult("inventory", CollectorStatus.Ok,
                    new Dictionary<string, string?> { ["note"] = "deux\nlignes" }, []),
            ],
        };

        var row = MarkdownReport.Render(result).Split('\n')
            .Single(l => l.Contains("deux", StringComparison.Ordinal));

        Assert.Contains("deux lignes", row, StringComparison.Ordinal);
    }

    /// <summary>
    /// The backslash rule, which is the one part of <c>Cell</c> a later simplification
    /// would get wrong in either direction.
    ///
    /// <para>
    /// Doubling every backslash would double them through every Windows path in the
    /// report, in a format read as plain text as often as it is rendered. Doubling none
    /// would let a backslash already in the value absorb the one we add and hand back a
    /// live <c>[</c> — the very character the escape exists to kill.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(@"C:\Windows\System32", @"C:\Windows\System32")]
    [InlineData(@"x\[y", @"x\\\[y")]
    [InlineData("[Rapport complet](javascript:alerte)", @"\[Rapport complet](javascript:alerte)")]
    public void Markdown_doubles_a_backslash_only_where_it_would_absorb_an_escape(
        string value, string expected) =>
        Assert.Equal(expected, MarkdownReport.Cell(value));

    /// <summary>
    /// The Markdown counterpart of
    /// <see cref="Html_escapes_markup_planted_in_every_machine_supplied_field"/>, and
    /// deliberately not written as one assertion per interpolation.
    ///
    /// <para>
    /// A list of sites is only right on the day it is written: the findings section
    /// interpolated five values raw while thirteen other sites in the same file escaped,
    /// and no test noticed because every Markdown assertion named a site. What is pinned
    /// here are properties of the whole document instead — nothing lands raw, no link can
    /// be formed, no code span outlives its line, no row shifts a column. A fourteenth
    /// interpolation written without <c>Cell</c> fails this test wherever it is added.
    /// </para>
    /// </summary>
    [Fact]
    public void Markdown_leaves_no_live_construct_when_every_field_is_hostile()
    {
        var markdown = MarkdownReport.Render(Hostile());

        // Not vacuous: the section the payload has to come out of intact is there.
        Assert.Contains("Constats — ce qui est présent", markdown, StringComparison.Ordinal);

        // Nothing lands raw. A site that skips Cell puts the payload back verbatim,
        // line break included, whichever section it sits in.
        Assert.DoesNotContain(Payload, markdown, StringComparison.Ordinal);

        // No link and no image can be formed anywhere. This report writes no "[" of its
        // own, so a live one could only have been assembled out of machine text — the
        // Markdown twin of "no href exists in the HTML".
        Assert.Equal(0, Live(markdown, '['));

        foreach (var line in markdown.Split('\n'))
        {
            // No code span outlives its line: one that fails to close swallows what
            // follows and shows it as part of the previous finding.
            Assert.Equal(0, Live(line, '`') % 2);

            // And no escaped value sits inside a span. Backslash escapes are inert in
            // code spans, so a fenced value is by construction an unescaped one.
            foreach (var span in CodeSpans(line))
            {
                Assert.DoesNotContain("\\", span, StringComparison.Ordinal);
            }
        }

        // No row shifts a column: inside one table, every line separates the same
        // number of cells as its header.
        foreach (var table in Tables(markdown))
        {
            Assert.Single(table.Select(Delimiters).Distinct());
        }
    }

    [Fact]
    public void Markdown_lists_the_flagged_findings_with_their_reasons()
    {
        var markdown = MarkdownReport.Render(Populated());

        Assert.Contains("pilote-douteux.sys", markdown, StringComparison.Ordinal);
        Assert.Contains("signature absente", markdown, StringComparison.Ordinal);
        Assert.Contains("pilotes chargés", markdown, StringComparison.Ordinal);
    }

    /// <summary>
    /// Benign findings are counted, not listed: a report that drowns two problems in
    /// two hundred green lines does not get read. The JSON keeps them all.
    /// </summary>
    [Fact]
    public void Benign_findings_are_counted_in_the_summaries_but_not_detailed()
    {
        var markdown = MarkdownReport.Render(Populated());

        Assert.Contains("| pilotes chargés | 2 | 1 |", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("pilote-sain.sys", markdown, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("POSTE-01", "POSTE-01-2026-07-24")]
    [InlineData("anon:3f2ab9", "anon-3f2ab9-2026-07-24")]
    [InlineData("machine..avec...points", "machine-avec-points-2026-07-24")]
    [InlineData("////", "machine-2026-07-24")]
    public void Folder_name_survives_a_machine_name_that_is_not_a_hostname(
        string machineName, string expected)
    {
        var result = Minimal() with
        {
            StartedAtUtc = "2026-07-24T09:15:00.0000000Z",
            Collectors =
            [
                new CollectorResult("inventory", CollectorStatus.Ok,
                    new Dictionary<string, string?> { ["machine.name"] = machineName }, []),
            ],
        };

        Assert.Equal(expected, ReportBundle.FolderName(result));
    }

    [Fact]
    public void Bundle_produces_the_three_files_and_the_json_reads_back()
    {
        var files = ReportBundle.Build(Populated());

        Assert.Equal(
            [ReportBundle.HtmlName, ReportBundle.MarkdownName, ReportBundle.JsonName],
            files.Select(f => f.Name));

        var json = files.Single(f => f.Name == ReportBundle.JsonName).Content;
        var reread = RempartJson.DeserialiseScanResult(json);

        // The JSON is the complete artifact: re-rendering from it must give back the
        // very same HTML, otherwise "rempart report --from" would not reproduce the
        // report it re-renders.
        Assert.Equal(HtmlReport.Render(Populated()), HtmlReport.Render(reread));
        Assert.Equal(3, reread.Findings.Count);
    }

    /// <summary>
    /// Each gauge is exactly as long as its score.
    ///
    /// The first version sized the bar against the table cell and capped it, which drew
    /// 67 %, 88 % and 100 % at the same width — measured in a browser at 136, 142 and
    /// 142 pixels. A posture chart that makes a mediocre domain look perfect is worse
    /// than no chart.
    /// </summary>
    [Fact]
    public void Every_domain_gauge_is_as_long_as_its_score()
    {
        var result = Minimal() with
        {
            Score = new ScoreCard(
                80,
                [
                    new DomainScore("a", 1, 0, 0, 0, 67),
                    new DomainScore("b", 1, 0, 0, 0, 88),
                    new DomainScore("c", 1, 0, 0, 0, 100),
                    new DomainScore("d", 0, 0, 1, 0, null),
                ],
                1),
        };

        var html = HtmlReport.Render(result);

        foreach (var score in new[] { 67, 88, 100 })
        {
            Assert.Contains($"style=\"width:{score}%\"", html, StringComparison.Ordinal);
        }

        // A domain nothing could be read in gets an empty track, never a zero-length
        // bar that would read as "scored zero".
        Assert.Contains("<span class=\"track\"></span><span class=\"pct none\">n/d</span>",
            html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The sentence the three renderings share when a control said nothing about what stopped
    /// it. Written once here because the point of the tests below is that the three agree.
    /// </summary>
    private const string ElevationAnswersIt = "un scan élevé tranchera";

    /// <summary>
    /// A control that came back unverifiable because the read <em>failed</em> is not a control
    /// nobody had the rights for, and the three renderings stopped saying it was.
    ///
    /// <para>
    /// The reason existed before this: <c>CheckReader</c> puts the provider diagnostic in
    /// <c>Verdict.Observed</c>, and it reached the JSON and stopped there. Console, HTML and
    /// Markdown each printed the rule identifier and the title under a heading that read
    /// « non vérifiable — accès refusé », so a WMI repository that had stopped serving, a
    /// service control manager that would not open and a firewall nobody could read all
    /// arrived as missing privileges — the one remedy that cannot help.
    /// </para>
    ///
    /// <para>
    /// Run both elevated and not, because the two prove different halves. Elevated, no word
    /// anywhere in the document may send the reader to elevate, which is the strongest form of
    /// the assertion. Non-elevated, the banner legitimately says « relancer en administrateur »
    /// and would satisfy that search on its own — so what is asserted there is narrower and is
    /// the half that matters here: a control that named its failure draws no advice, and the
    /// suppression comes from the reason rather than from the elevation.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void The_three_renderings_print_why_a_control_could_not_be_read(bool elevated)
    {
        const string Reason = "Le gestionnaire de services a répondu 0x5b4 sans jamais ouvrir.";

        foreach (var rendering in Renderings(Unverifiable(Reason, elevated)))
        {
            Assert.Contains("WIN-SVC-001", rendering, StringComparison.Ordinal);
            Assert.Contains(Reason, rendering, StringComparison.Ordinal);

            foreach (var advice in
                     new[] { "accès refusé", ElevationAnswersIt })
            {
                Assert.DoesNotContain(advice, rendering, StringComparison.OrdinalIgnoreCase);
            }

            if (elevated)
            {
                foreach (var advice in new[] { "élévation", "administrateur" })
                {
                    Assert.DoesNotContain(advice, rendering, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    /// <summary>
    /// The counterweight, without which the test above would be satisfied by three renderings
    /// that stopped giving any advice at all. A control that explained nothing may be one a
    /// right was missing for, and on a scan that has not tried elevation the three still offer
    /// it.
    /// </summary>
    [Fact]
    public void A_control_that_explained_nothing_still_says_what_might_answer_it()
    {
        foreach (var rendering in Renderings(Unverifiable(null, elevated: false)))
        {
            Assert.Contains("WIN-SVC-001", rendering, StringComparison.Ordinal);
            Assert.Contains(ElevationAnswersIt, rendering, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The mutation that survived every rendering: <c>Any</c> to <c>All</c> on the test that
    /// decides whether the remedy is printed.
    ///
    /// <para>
    /// It survived because no test ever rendered a section holding more than one
    /// <c>Unknown</c>, and on a section of one the two are the same predicate. On a mixed
    /// section they are opposites, and <c>All</c> is the wrong one: the control that named its
    /// failure silences the remedy owed to the control beside it that named nothing — the one
    /// case where elevation may be the whole answer. The scan is not elevated, so the remedy
    /// is genuinely available and its absence can only be the bug.
    /// </para>
    /// </summary>
    [Fact]
    public void One_control_that_explained_itself_does_not_silence_the_one_that_did_not()
    {
        var mixed = Unverifiable(null, elevated: false) with
        {
            Verdicts =
            [
                new Verdict("WIN-SVC-001", "Service de pare-feu actif", Severity.High, "réseau",
                    VerdictStatus.Unknown, null, null),
                new Verdict("WIN-WMI-002", "Abonnements WMI permanents", Severity.High, "réseau",
                    VerdictStatus.Unknown,
                    "Le dépôt WMI a cessé de répondre (0x8004100e).", null),
            ],
            Score = new ScoreCard(null, [new DomainScore("réseau", 0, 0, 2, 0, null)], 2),
        };

        foreach (var rendering in Renderings(mixed))
        {
            // The premise, asserted rather than assumed: a section of one would make this
            // test pass against the mutant it exists to kill.
            Assert.Contains("WIN-SVC-001", rendering, StringComparison.Ordinal);
            Assert.Contains("WIN-WMI-002", rendering, StringComparison.Ordinal);

            Assert.Contains(ElevationAnswersIt, rendering, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Nobody is told to become an administrator they already are.
    ///
    /// <para>
    /// Two committed goldens printed the advice over captures recording
    /// <c>"isElevated": true</c>, and a test asserted it did. The information was there all
    /// along — <see cref="ReportView.Elevated"/> already decides the non-elevated banner in
    /// two of the three renderings — and the sentence ignored it.
    /// </para>
    /// </summary>
    [Fact]
    public void An_elevated_scan_is_never_sent_to_elevate()
    {
        foreach (var rendering in Renderings(Unverifiable(null, elevated: true)))
        {
            Assert.Contains("WIN-SVC-001", rendering, StringComparison.Ordinal);

            foreach (var advice in new[] { ElevationAnswersIt, "un scan élevé" })
            {
                Assert.DoesNotContain(advice, rendering, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>
    /// A control that gave no reason was not necessarily refused, and no rendering says it
    /// was.
    ///
    /// <para>
    /// The producer, not a hand-built verdict: <c>CheckReader</c> reading a WMI class that
    /// holds no instance — BitLocker on an edition without volume encryption — answers
    /// <c>Denied: true</c> with a null diagnostic, and that silence means « rien à évaluer ».
    /// The first draft of the sentence read « Sans raison indiquée, la lecture a été refusée »
    /// and turned every one of those into an accusation of a refusal that never happened. The
    /// remedy may still be offered — a missing right produces the same silence — but the cause
    /// may not be asserted.
    /// </para>
    /// </summary>
    [Fact]
    public void A_control_with_nothing_to_evaluate_is_not_called_a_refusal()
    {
        var absent = CheckReader.Read(
            new CheckSpec(
                CheckKind.Wmi,
                @"root\CIMV2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume",
                "ProtectionStatus", CheckOperator.Equals, "1", "0"),
            new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider(),
                wmi: new AbsentClassWmi()));

        // The premise: this is the shape that reaches the renderings as a reasonless Unknown.
        Assert.True(absent.Denied);
        Assert.Null(absent.Found);

        foreach (var rendering in Renderings(Unverifiable(absent.Found, elevated: false)))
        {
            // The remedy is still offered — a missing right leaves the same silence, and
            // withdrawing it would be the opposite mistake.
            Assert.Contains(ElevationAnswersIt, rendering, StringComparison.Ordinal);

            foreach (var claim in new[] { "a été refusée", "a été refusé", "accès refusé" })
            {
                Assert.DoesNotContain(claim, rendering, StringComparison.OrdinalIgnoreCase);
            }
        }

        // On the sentence itself as well as on the renderings that carry it: a rewrite that
        // puts the claim back is the defect, wherever the words end up being printed.
        foreach (var claim in new[] { "refus", "denied" })
        {
            Assert.DoesNotContain(claim, ReportLabels.UnexplainedAdvice,
                StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>A namespace whose class holds nothing — an absence, not a denial.</summary>
    private sealed class AbsentClassWmi : IWmiProvider
    {
        public WmiRead Query(string ns, string className, IReadOnlyList<string> properties) =>
            WmiRead.NotFound;
    }

    private static IEnumerable<string> Renderings(ScanResult result) =>
    [
        ConsoleReport.HumanReadable(result),
        HtmlReport.Render(result),
        MarkdownReport.Render(result),
    ];

    /// <summary>
    /// A scan with one control it could not conclude, carrying <paramref name="reason"/> where
    /// the read put its diagnostic — null being the read that explained nothing.
    /// </summary>
    /// <param name="elevated">
    /// Whether the scan already ran as administrator. A parameter rather than a constant
    /// because the advice now turns on it, and the two cases are opposite assertions.
    /// </param>
    private static ScanResult Unverifiable(string? reason, bool elevated) => Minimal() with
    {
        Collectors =
        [
            new CollectorResult("inventory", CollectorStatus.Ok,
                new Dictionary<string, string?>
                {
                    ["machine.name"] = "POSTE-01",
                    ["scan.elevated"] = elevated ? "True" : "False",
                },
                []),
        ],
        Verdicts =
        [
            new Verdict("WIN-SVC-001", "Service de pare-feu actif", Severity.High, "réseau",
                VerdictStatus.Unknown, reason, null),
        ],
        Score = new ScoreCard(null, [new DomainScore("réseau", 0, 0, 1, 0, null)], 1),
    };

    [Fact]
    public void Rendering_twice_gives_the_same_bytes()
    {
        Assert.Equal(HtmlReport.Render(Populated()), HtmlReport.Render(Populated()));
        Assert.Equal(MarkdownReport.Render(Populated()), MarkdownReport.Render(Populated()));
    }

    /// <summary>Pipes that still separate cells — the escaped ones do not.</summary>
    private static int Delimiters(string row) => Live(row, '|');

    /// <summary>Occurrences a Markdown reader still takes as syntax rather than as text.</summary>
    private static int Live(string text, char syntax) =>
        text.Where((character, index) =>
            character == syntax && (index == 0 || text[index - 1] != '\\')).Count();

    /// <summary>Runs of consecutive table lines, header and separator included.</summary>
    private static IEnumerable<List<string>> Tables(string markdown)
    {
        var table = new List<string>();

        foreach (var line in markdown.Split('\n'))
        {
            if (line.StartsWith('|'))
            {
                table.Add(line);
            }
            else if (table.Count > 0)
            {
                yield return table;
                table = [];
            }
        }

        if (table.Count > 0)
        {
            yield return table;
        }
    }

    /// <summary>
    /// What a renderer reads as code on one line. An escaped backtick opens nothing: it
    /// is text, which is the whole point of escaping it.
    /// </summary>
    private static IEnumerable<string> CodeSpans(string line)
    {
        var opened = -1;

        for (var index = 0; index < line.Length; index++)
        {
            if (line[index] != '`' || (index > 0 && line[index - 1] == '\\'))
            {
                continue;
            }

            if (opened < 0)
            {
                opened = index;
            }
            else
            {
                yield return line[(opened + 1)..index];
                opened = -1;
            }
        }
    }

    private static int Occurrences(string haystack, string needle)
    {
        var count = 0;
        var index = haystack.IndexOf(needle, StringComparison.Ordinal);

        while (index >= 0)
        {
            count++;
            index = haystack.IndexOf(needle, index + needle.Length, StringComparison.Ordinal);
        }

        return count;
    }

    private static ScanResult Minimal() => new(
        ToolVersion: "0.6.0",
        StartedAtUtc: "2026-07-24T09:15:00.0000000Z",
        Collectors: [],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "sha256:abcdef",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));

    /// <summary>A scan with something in every section, and a machine that is not clean.</summary>
    private static ScanResult Populated() => Minimal() with
    {
        Collectors =
        [
            new CollectorResult("inventory", CollectorStatus.InsufficientPrivileges,
                new Dictionary<string, string?>
                {
                    ["machine.name"] = "POSTE-01",
                    ["os.name"] = "Windows 11 Pro",
                    ["scan.elevated"] = "False",
                },
                ["Accès refusé : HKLM\\SECURITY"]),
        ],
        Verdicts =
        [
            new Verdict("WIN-CRED-001", "LSA Protection (RunAsPPL) désactivée", Severity.High,
                "credentials", VerdictStatus.Fail, "0", "1"),
            new Verdict("WIN-DEF-001", "Defender actif", Severity.Critical, "malware",
                VerdictStatus.Pass, "1", "1"),
            new Verdict("WIN-BIT-001", "BitLocker", Severity.High, "chiffrement",
                VerdictStatus.Unknown, null, null),
        ],
        Findings =
        [
            new Finding("driver", "Win32_SystemDriver", "pilote-douteux.sys",
                FindingSeverity.Suspicious, ["signature absente"],
                new Dictionary<string, string> { ["sha256"] = "0f1e2d", ["éditeur"] = "—" }),
            new Finding("driver", "Win32_SystemDriver", "pilote-sain.sys",
                FindingSeverity.Benign, [], new Dictionary<string, string>()),
            new Finding("software", "Uninstall", "Bloatware OEM",
                FindingSeverity.Notable, ["catalogue bloatware"],
                new Dictionary<string, string> { ["catalogue"] = "oem-tools" }),
        ],
        Score = new ScoreCard(
            72,
            [
                new DomainScore("credentials", 0, 1, 0, 0, 0),
                new DomainScore("malware", 1, 0, 0, 0, 100),
                new DomainScore("chiffrement", 0, 0, 1, 0, null),
            ],
            1),
    };

    /// <summary>Every field a machine can influence, carrying the same markup payload.</summary>
    private static ScanResult Hostile() => Minimal() with
    {
        Collectors =
        [
            new CollectorResult("inventory", CollectorStatus.Ok,
                new Dictionary<string, string?>
                {
                    ["machine.name"] = Payload,
                    [Payload] = Payload,
                    ["scan.elevated"] = "True",
                },
                [Payload]),
        ],
        Verdicts =
        [
            new Verdict(Payload, Payload, Severity.High, Payload, VerdictStatus.Fail,
                Payload, Payload),
            // Observed carries the payload here too: on an Unknown verdict that field holds
            // the diagnostic the read handed back — machine text, and the renderings print
            // it. Left null, the whole "unverifiable" section escaped nothing because it
            // interpolated nothing, and the guards below would have covered the new
            // interpolation by not reaching it.
            new Verdict($"U-{Payload}", Payload, Severity.Low, Payload, VerdictStatus.Unknown,
                Payload, null),
        ],
        Findings =
        [
            new Finding(Payload, Payload, Payload, FindingSeverity.Suspicious, [Payload],
                new Dictionary<string, string> { [Payload] = Payload }),
        ],
        Score = new ScoreCard(50, [new DomainScore(Payload, 0, 1, 0, 0, 50)], 0),
    };
}
