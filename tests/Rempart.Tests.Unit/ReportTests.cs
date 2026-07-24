using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
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
    /// <summary>The payload planted in every machine-supplied field.</summary>
    private const string Payload = "<script>alert('xss')</script>";

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

    [Fact]
    public void Rendering_twice_gives_the_same_bytes()
    {
        Assert.Equal(HtmlReport.Render(Populated()), HtmlReport.Render(Populated()));
        Assert.Equal(MarkdownReport.Render(Populated()), MarkdownReport.Render(Populated()));
    }

    /// <summary>Pipes that still separate cells — the escaped ones do not.</summary>
    private static int Delimiters(string row) =>
        row.Where((character, index) =>
            character == '|' && (index == 0 || row[index - 1] != '\\')).Count();

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
            new Verdict($"U-{Payload}", Payload, Severity.Low, Payload, VerdictStatus.Unknown,
                null, null),
        ],
        Findings =
        [
            new Finding(Payload, Payload, Payload, FindingSeverity.Suspicious, [Payload],
                new Dictionary<string, string> { [Payload] = Payload }),
        ],
        Score = new ScoreCard(50, [new DomainScore(Payload, 0, 1, 0, 0, 50)], 0),
    };
}
