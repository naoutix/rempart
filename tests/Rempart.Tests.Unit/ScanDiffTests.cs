using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Comparing two scans.
///
/// The distinctions pinned here are the ones that decide whether a diff is worth
/// reading: a check that became unreadable is not a check that started failing; a
/// startup entry now launching a different binary is not two unrelated lines; and a
/// disappearance Windows causes by itself is not news.
/// </summary>
public sealed class ScanDiffTests
{
    // ---- verdicts ----------------------------------------------------------

    /// <summary>
    /// The distinction the whole classification exists for. An audit that lost sight of
    /// a control calls for elevation; a control that started failing calls for a fix.
    /// Reporting both as "regression" would bury the first under the second — and the
    /// first is the one nobody would otherwise notice.
    /// </summary>
    [Theory]
    [InlineData(VerdictStatus.Pass, VerdictStatus.Fail, VerdictShift.Regression)]
    [InlineData(VerdictStatus.Fail, VerdictStatus.Pass, VerdictShift.Correction)]
    [InlineData(VerdictStatus.Pass, VerdictStatus.Unknown, VerdictShift.VisibilityLost)]
    [InlineData(VerdictStatus.Fail, VerdictStatus.Unknown, VerdictShift.VisibilityLost)]
    [InlineData(VerdictStatus.Unknown, VerdictStatus.Fail, VerdictShift.VisibilityGained)]
    [InlineData(VerdictStatus.Pass, VerdictStatus.NotApplicable, VerdictShift.Other)]
    public void A_verdict_move_is_classified_for_what_it_is(
        VerdictStatus before, VerdictStatus after, VerdictShift expected)
    {
        var diff = ScanDiff.Compare(
            Scan() with { Verdicts = [Rule("WIN-X-001", before)] },
            Scan() with { Verdicts = [Rule("WIN-X-001", after)] });

        Assert.Equal(expected, Assert.Single(diff.Verdicts).Shift);
    }

    [Fact]
    public void An_unchanged_verdict_is_not_reported()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Verdicts = [Rule("WIN-X-001", VerdictStatus.Fail)] },
            Scan() with { Verdicts = [Rule("WIN-X-001", VerdictStatus.Fail)] });

        Assert.Empty(diff.Verdicts);
        Assert.True(diff.NothingToReport);
    }

    [Fact]
    public void A_rule_present_on_one_side_only_is_named_as_such()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Verdicts = [Rule("WIN-OLD-001", VerdictStatus.Pass)] },
            Scan() with { Verdicts = [Rule("WIN-NEW-001", VerdictStatus.Fail)] });

        Assert.Equal(VerdictShift.Disappeared, diff.Verdicts.Single(v => v.RuleId == "WIN-OLD-001").Shift);
        Assert.Equal(VerdictShift.Appeared, diff.Verdicts.Single(v => v.RuleId == "WIN-NEW-001").Shift);
    }

    // ---- comparability -----------------------------------------------------

    /// <summary>
    /// Refusing to compare across catalogs would make the command useless the day after
    /// any update — which is most days. It compares, and says loudly why the numbers may
    /// not mean what they look like.
    /// </summary>
    [Fact]
    public void Two_catalogs_are_compared_anyway_and_the_gap_is_stated()
    {
        var diff = ScanDiff.Compare(
            Scan() with { RulesFingerprint = "82:aaaa", Verdicts = [Rule("WIN-X-001", VerdictStatus.Pass)] },
            Scan() with { RulesFingerprint = "91:bbbb", Verdicts = [Rule("WIN-X-001", VerdictStatus.Fail)] });

        Assert.False(diff.Comparable);
        Assert.Contains("82:aaaa", diff.ComparabilityNote, StringComparison.Ordinal);
        Assert.Contains("91:bbbb", diff.ComparabilityNote, StringComparison.Ordinal);

        // And it still did the work.
        Assert.Equal(VerdictShift.Regression, Assert.Single(diff.Verdicts).Shift);
    }

    [Fact]
    public void The_same_catalog_on_both_sides_is_stated_too() =>
        Assert.True(ScanDiff.Compare(Scan(), Scan()).Comparable);

    // ---- findings ----------------------------------------------------------

    /// <summary>
    /// The strongest signal a diff can carry: same startup key, same path, a different
    /// binary behind it. A comparison looking only at severities would let it pass in
    /// silence, since nothing about the judgement changed.
    /// </summary>
    [Fact]
    public void A_binary_swapped_at_the_same_place_is_reported()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = [Autorun(@"HKLM\…\Run\Agent", @"C:\a\agent.exe", "aaaaaaaaaaaa11")] },
            Scan() with { Findings = [Autorun(@"HKLM\…\Run\Agent", @"C:\a\agent.exe", "bbbbbbbbbbbb22")] });

        var change = Assert.Single(diff.Findings);
        Assert.Equal(ChangeKind.Changed, change.Change);
        Assert.Contains(change.Notes, note =>
            note.Contains("Empreinte", StringComparison.Ordinal)
            && note.Contains("fichier différent", StringComparison.Ordinal));
    }

    /// <summary>
    /// A startup key repointed elsewhere is one event, not a removal plus an unrelated
    /// addition the reader has to piece back together.
    /// </summary>
    [Fact]
    public void A_startup_entry_pointing_somewhere_else_becomes_one_change()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = [Autorun(@"HKLM\…\Run\Agent", @"C:\a\agent.exe", "aa")] },
            Scan() with { Findings = [Autorun(@"HKLM\…\Run\Agent", @"C:\tmp\autre.exe", "bb")] });

        var change = Assert.Single(diff.Findings);
        Assert.Equal(ChangeKind.Changed, change.Change);
        Assert.Equal(@"C:\tmp\autre.exe", change.Target);
        Assert.Contains(change.Notes, note => note.Contains("lance autre chose", StringComparison.Ordinal));
    }

    /// <summary>
    /// The merge above must not fire where a family shares one source across everything
    /// it enumerates. Every loaded driver comes from <c>Win32_SystemDriver</c>: a driver
    /// removed and another added have nothing to do with each other, and presenting them
    /// as one substitution would invent a link.
    /// </summary>
    [Fact]
    public void Two_unrelated_drivers_are_not_merged_into_a_substitution()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings =
                [
                    Driver("ancien.sys"), Driver("commun.sys"),
                ],
            },
            Scan() with
            {
                Findings =
                [
                    Driver("nouveau.sys"), Driver("commun.sys"),
                ],
            });

        Assert.Equal(2, diff.Findings.Count);
        Assert.Contains(diff.Findings, c => c.Change == ChangeKind.Disappeared && c.Target == "ancien.sys");
        Assert.Contains(diff.Findings, c => c.Change == ChangeKind.Appeared && c.Target == "nouveau.sys");
    }

    [Fact]
    public void A_severity_that_moved_is_reported_with_both_ends()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = [Driver("pilote.sys", FindingSeverity.Benign)] },
            Scan() with { Findings = [Driver("pilote.sys", FindingSeverity.Suspicious)] });

        var change = Assert.Single(diff.Findings);
        Assert.Equal(FindingSeverity.Benign, change.Before);
        Assert.Equal(FindingSeverity.Suspicious, change.After);
    }

    // ---- transients --------------------------------------------------------

    /// <summary>
    /// Two scans either side of a restart differ on <c>RunOnce</c> entries without
    /// anything having happened. A diff that always shows movement stops being read, so
    /// these leave the posture delta — and are listed rather than dropped.
    /// </summary>
    [Fact]
    public void A_transient_that_vanished_leaves_the_posture_delta()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = [RunOnce(@"HKLM\…\RunOnce\Nettoyage")] },
            Scan() with { Findings = [] });

        Assert.Empty(diff.Findings);
        Assert.True(diff.NothingToReport);

        var transient = Assert.Single(diff.Transients);
        Assert.Equal(ChangeKind.Disappeared, transient.Change);
        Assert.Equal(@"HKLM\…\RunOnce\Nettoyage", transient.Source);
    }

    /// <summary>
    /// Only the disappearance is expected. A <c>RunOnce</c> entry <em>appearing</em> is
    /// news like any other — it is a way to get code run at the next boot.
    /// </summary>
    [Fact]
    public void A_transient_that_appeared_is_news()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = [] },
            Scan() with { Findings = [RunOnce(@"HKLM\…\RunOnce\Charge")] });

        Assert.Empty(diff.Transients);
        Assert.Equal(ChangeKind.Appeared, Assert.Single(diff.Findings).Change);
    }

    /// <summary>
    /// An ephemeral socket is not "self-removing", it is renumbered: the one that
    /// vanished and the one that appeared are the same fact. Suppressing only the
    /// disappearance would halve the noise and leave the report wrong.
    ///
    /// <para>
    /// Found by running the comparison, not by reasoning about it: two scans fourteen
    /// seconds apart on the test machine differed by three Chrome UDP sockets and
    /// nothing else.
    /// </para>
    /// </summary>
    [Fact]
    public void A_renumbered_ephemeral_socket_is_not_movement_in_either_direction()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = [Ephemeral(49601), Ephemeral(54559)] },
            Scan() with { Findings = [Ephemeral(56092)] });

        Assert.Empty(diff.Findings);
        Assert.True(diff.NothingToReport);
        Assert.Equal(3, diff.Transients.Count);
    }

    /// <summary>
    /// The marker silences noise, never a judgement. An unsigned binary reachable on a
    /// high port is news every time — which is why the collector only marks what it
    /// already judged benign.
    /// </summary>
    [Fact]
    public void A_flagged_port_is_reported_whatever_its_number()
    {
        var flagged = new Finding("listening-port", "UDP 0.0.0.0:51000", @"C:\tmp\x.exe",
            FindingSeverity.Suspicious, ["binaire non attesté, joignable"],
            new Dictionary<string, string>());

        var diff = ScanDiff.Compare(Scan(), Scan() with { Findings = [flagged] });

        Assert.Equal(ChangeKind.Appeared, Assert.Single(diff.Findings).Change);
        Assert.Empty(diff.Transients);
    }

    // ---- inventory ---------------------------------------------------------

    /// <summary>
    /// An uptime differs on every run. Reporting it would put a line of noise at the top
    /// of every comparison — which is what <see cref="FieldSemantics"/> was written for,
    /// back in M0, with this command in mind.
    /// </summary>
    [Fact]
    public void A_volatile_field_is_not_a_change()
    {
        var diff = ScanDiff.Compare(
            Scan(uptime: "1000"),
            Scan(uptime: "99999"));

        Assert.Empty(diff.Fields);
        Assert.True(diff.NothingToReport);
    }

    [Fact]
    public void A_real_inventory_difference_is_reported()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Collectors = [Inventory("POSTE-01", ("os.build", "26100"))],
            },
            Scan() with
            {
                Collectors = [Inventory("POSTE-01", ("os.build", "26200"))],
            });

        var change = Assert.Single(diff.Fields);
        Assert.Equal("os.build", change.Field);
        Assert.Equal("26100", change.Before);
        Assert.Equal("26200", change.After);
    }

    /// <summary>
    /// Between two machines an inventory difference is context; on one machine over time
    /// it is an event. The renderers phrase it differently, so the fact is established
    /// here rather than guessed there.
    /// </summary>
    [Fact]
    public void The_comparison_knows_whether_it_spans_two_machines()
    {
        Assert.True(ScanDiff.Compare(Scan(), Scan()).SameMachine);

        Assert.False(ScanDiff.Compare(
            Scan() with { Collectors = [Inventory("POSTE-01")] },
            Scan() with { Collectors = [Inventory("POSTE-02")] }).SameMachine);
    }

    // ---- score -------------------------------------------------------------

    [Fact]
    public void The_score_delta_is_computed_per_domain_and_overall()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Score = Card(58, ("réseau", 40), ("defender", 92)) },
            Scan() with { Score = Card(71, ("réseau", 80), ("defender", 92)) });

        Assert.Equal(13, diff.ScoreDelta);
        Assert.Equal((40, 80), Pair(diff.Domains.Single(d => d.Domain == "réseau")));
        Assert.Equal((92, 92), Pair(diff.Domains.Single(d => d.Domain == "defender")));
    }

    [Fact]
    public void An_unscorable_side_gives_no_delta_rather_than_zero()
    {
        var diff = ScanDiff.Compare(Scan() with { Score = Card(58) }, Scan() with { Score = null });

        Assert.Null(diff.ScoreDelta);
        Assert.Equal(58, diff.ScoreBefore);
        Assert.Null(diff.ScoreAfter);
    }

    // ---- determinism -------------------------------------------------------

    [Fact]
    public void Comparing_twice_gives_the_same_ordering()
    {
        var before = Scan() with
        {
            Findings = [Driver("a.sys"), Driver("b.sys"), RunOnce(@"HK\RunOnce\x")],
            Verdicts = [Rule("WIN-A-001", VerdictStatus.Pass), Rule("WIN-B-001", VerdictStatus.Pass)],
        };
        var after = Scan() with
        {
            Findings = [Driver("b.sys"), Driver("c.sys")],
            Verdicts = [Rule("WIN-A-001", VerdictStatus.Fail), Rule("WIN-B-001", VerdictStatus.Unknown)],
        };

        var first = ScanDiff.Compare(before, after);
        var second = ScanDiff.Compare(before, after);

        Assert.Equal(
            first.Findings.Select(c => $"{c.Kind}|{c.Source}|{c.Target}|{c.Change}"),
            second.Findings.Select(c => $"{c.Kind}|{c.Source}|{c.Target}|{c.Change}"));
        Assert.Equal(
            first.Verdicts.Select(v => $"{v.RuleId}|{v.Shift}"),
            second.Verdicts.Select(v => $"{v.RuleId}|{v.Shift}"));
    }

    // ---- builders ----------------------------------------------------------

    private static (int?, int?) Pair(DomainScoreChange change) => (change.Before, change.After);

    private static ScanResult Scan(string uptime = "1000") => new(
        ToolVersion: "0.6.0",
        StartedAtUtc: "2026-07-24T09:15:00Z",
        Collectors: [Inventory("POSTE-01", ("machine.uptimeSeconds", uptime))],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "82:c3e6e3029b12",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));

    private static CollectorResult Inventory(
        string machine, params (string Field, string Value)[] fields)
    {
        var values = new Dictionary<string, string?> { ["machine.name"] = machine };

        foreach (var (field, value) in fields)
        {
            values[field] = value;
        }

        return new CollectorResult("inventory", CollectorStatus.Ok, values, []);
    }

    private static Verdict Rule(string id, VerdictStatus status) =>
        new(id, $"Contrôle {id}", Severity.High, "réseau", status, "0", "1");

    private static ScoreCard Card(int overall, params (string Domain, int Score)[] domains) =>
        new(overall,
            [.. domains.Select(d => new DomainScore(d.Domain, 1, 0, 0, 0, d.Score))],
            0);

    private static Finding Autorun(string source, string target, string sha256) =>
        new("autorun", source, target, FindingSeverity.Notable, ["au démarrage"],
            new Dictionary<string, string> { ["sha256"] = sha256 });

    private static Finding Driver(string name, FindingSeverity severity = FindingSeverity.Benign) =>
        new("driver", "Win32_SystemDriver", name, severity, [],
            new Dictionary<string, string>());

    private static Finding Ephemeral(int port) =>
        new("listening-port", $"UDP 0.0.0.0:{port}",
            @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            FindingSeverity.Benign, [],
            new Dictionary<string, string>
            {
                [FindingDetails.Ephemeral] = "Port de la plage dynamique.",
            });

    private static Finding RunOnce(string source) =>
        new("autorun", source, @"C:\Windows\System32\cleanup.exe", FindingSeverity.Benign, [],
            new Dictionary<string, string>
            {
                [FindingDetails.Transient] =
                    "Entrée RunOnce : Windows l'exécute au prochain démarrage puis la supprime.",
            });
}
