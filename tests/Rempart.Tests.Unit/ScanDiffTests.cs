using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
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
    /// The merge above must not fire where a family shares one source across everything it
    /// enumerates. Every redirection of the <c>hosts</c> file comes from the one file, so a
    /// line removed and another added have nothing to do with each other, and presenting
    /// them as one substitution would invent a link on a hijack surface.
    ///
    /// <para>
    /// The counter-example this test used to carry was <c>Win32_SystemDriver</c>, quoting the
    /// sentence still written beside the guard. No driver finding has ever borne it:
    /// <c>LoadedDriversCollector</c> has keyed each one by <c>driver.Name</c> since #29, so
    /// two drivers never share a source and the guard was being exercised on a shape no
    /// machine produces. The hosts file is a family that really does share one — built here
    /// by the shipped collector rather than by hand, so the claim cannot drift from it.
    /// </para>
    /// </summary>
    [Fact]
    public void Two_redirections_of_one_hosts_file_are_not_merged_into_a_substitution()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = Hosts("203.0.113.7 intranet.example", "198.51.100.20 ancien.example"),
            },
            Scan() with
            {
                Findings = Hosts("203.0.113.7 intranet.example", "198.51.100.21 nouveau.example"),
            });

        Assert.Equal(2, diff.Findings.Count);
        Assert.Contains(diff.Findings, c =>
            c.Change == ChangeKind.Disappeared && c.Target == "ancien.example → 198.51.100.20");
        Assert.Contains(diff.Findings, c =>
            c.Change == ChangeKind.Appeared && c.Target == "nouveau.example → 198.51.100.21");
    }

    // ---- one source, several places ----------------------------------------

    /// <summary>
    /// A resolver repointed on a card that resolves on both stacks — that is, on most cards.
    ///
    /// <para>
    /// Windows binds the two TCP/IP stacks of one adapter under the same GUID (#193), so such
    /// a card carries two <c>dns-resolver</c> findings under one source, told apart by the
    /// stack alone. Keyed on the source, the merge refused: the reader got « disparu » plus
    /// « apparu », two lines with no visible link, for the hijack this collector exists to
    /// catch and on the command written to spot drift.
    /// </para>
    ///
    /// <para>
    /// Built by the shipped collector, not by a hand-written finding: what makes this case
    /// exist at all is the shape <c>DnsResolverCollector</c> really emits, down to the
    /// details it writes.
    /// </para>
    /// </summary>
    [Fact]
    public void A_resolver_repointed_on_a_dual_stack_card_is_one_change()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = Resolvers(
                    Static(Adapter, "9.9.9.9", DnsStack.IPv4),
                    Static(Adapter, "2620:fe::fe", DnsStack.IPv6)),
            },
            Scan() with
            {
                Findings = Resolvers(
                    Static(Adapter, "203.0.113.9", DnsStack.IPv4),
                    Static(Adapter, "2620:fe::fe", DnsStack.IPv6)),
            });

        var change = Assert.Single(diff.Findings);

        Assert.Equal(ChangeKind.Changed, change.Change);
        Assert.Equal("203.0.113.9", change.Target);
        Assert.Contains(change.Notes, note =>
            note.Contains("9.9.9.9 → 203.0.113.9", StringComparison.Ordinal)
            && note.Contains("lance autre chose", StringComparison.Ordinal));

        // And the judgement travelled with it: a recognised operator gave way to an
        // unrecognised server, which is the reason the line is worth reading.
        Assert.Equal(FindingSeverity.Benign, change.Before);
        Assert.Equal(FindingSeverity.Notable, change.After);
    }

    /// <summary>
    /// The trap of the merge above, and it is not hypothetical: on main it fired.
    ///
    /// <para>
    /// A card whose v4 resolver is dropped while a v6 one is set carries one finding on each
    /// side, under one source — so the source « designated exactly one thing » both times and
    /// the two were folded into « le même emplacement lance autre chose ». They are two
    /// places: <c>netsh interface ipv4</c> undoes one and <c>netsh interface ipv6</c> the
    /// other, and nothing was substituted for anything.
    /// </para>
    /// </summary>
    [Fact]
    public void A_v4_resolver_dropped_and_a_v6_one_set_are_not_one_substitution()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = Resolvers(Static(Adapter, "9.9.9.9", DnsStack.IPv4)) },
            Scan() with { Findings = Resolvers(Static(Adapter, "2620:fe::fe", DnsStack.IPv6)) });

        Assert.Equal(2, diff.Findings.Count);
        Assert.Contains(diff.Findings, c =>
            c.Change == ChangeKind.Disappeared && c.Target == "9.9.9.9");
        Assert.Contains(diff.Findings, c =>
            c.Change == ChangeKind.Appeared && c.Target == "2620:fe::fe");
        Assert.DoesNotContain(diff.Findings, c => c.Change == ChangeKind.Changed);
    }

    /// <summary>
    /// Both resolvers of one card repointed at once, which is what a hijack that bothered to
    /// cover the second stack looks like. Two changes, and each paired with its own stack.
    ///
    /// <para>
    /// Splitting the key is not enough on its own here: the disappearance and the appearance
    /// have to be matched on the place too. Matched on the source alone, the v4 line would
    /// have been offered the v6 arrival — a substitution across two stacks, undone by two
    /// different commands, reported as one event. The pairing is what this asserts, not the
    /// count.
    /// </para>
    /// </summary>
    [Fact]
    public void Both_stacks_repointed_at_once_are_paired_stack_by_stack()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = Resolvers(
                    Static(Adapter, "9.9.9.9", DnsStack.IPv4),
                    Static(Adapter, "2620:fe::fe", DnsStack.IPv6)),
            },
            Scan() with
            {
                Findings = Resolvers(
                    Static(Adapter, "203.0.113.9", DnsStack.IPv4),
                    Static(Adapter, "2001:db8::5", DnsStack.IPv6)),
            });

        Assert.Equal(2, diff.Findings.Count);
        Assert.All(diff.Findings, change => Assert.Equal(ChangeKind.Changed, change.Change));

        Assert.Contains(diff.Findings, change =>
            change.Target == "203.0.113.9"
            && change.Notes.Any(note =>
                note.Contains("9.9.9.9 → 203.0.113.9", StringComparison.Ordinal)));

        Assert.Contains(diff.Findings, change =>
            change.Target == "2001:db8::5"
            && change.Notes.Any(note =>
                note.Contains("2620:fe::fe → 2001:db8::5", StringComparison.Ordinal)));
    }

    /// <summary>
    /// A source addressed along two axes has to name both, and the key has to read both.
    ///
    /// <para>
    /// Naming one of two is how a false merge comes back: the findings differing only on the
    /// unnamed axis collapse onto one place again, and one gets folded into the other. The
    /// diff cannot detect that — it sees details, never the surface behind them — so what is
    /// pinned here is that a collector <em>can</em> say it. Read on the first axis only, this
    /// comparison gives back the two lines it gave before.
    /// </para>
    ///
    /// <para>
    /// Hand-written, the first of the three that are: no shipped collector names two axes
    /// today — <c>dns-resolver</c> names the stack and nothing else — so this shape belongs to
    /// the mechanism and not to a machine, and it is written down as such rather than dressed
    /// up as a capture.
    /// </para>
    /// </summary>
    [Fact]
    public void A_source_addressed_along_two_axes_is_keyed_on_both()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings =
                [
                    Placed("gauche", ("axe", "1"), ("volet", "A")),
                    Placed("ancien", ("axe", "1"), ("volet", "B")),
                ],
            },
            Scan() with
            {
                Findings =
                [
                    Placed("gauche", ("axe", "1"), ("volet", "A")),
                    Placed("nouveau", ("axe", "1"), ("volet", "B")),
                ],
            });

        var change = Assert.Single(diff.Findings);

        Assert.Equal(ChangeKind.Changed, change.Change);
        Assert.Equal("nouveau", change.Target);
    }

    /// <summary>
    /// What the key does when a collector names a detail it did not write — a typo, or a row
    /// set on one branch and not on the other.
    ///
    /// <para>
    /// It reads as no coordinate at all, which folds those findings back onto the source they
    /// share, and the merge refuses. That is the direction to fail in: two lines a reader has
    /// to join up cost a reading, an invented substitution costs a wrong one. And the diff
    /// cannot do better here — a name it cannot resolve is exactly as informative as no name.
    /// </para>
    ///
    /// <para>
    /// Hand-written, the second of the three: a collector-side slip is not a shape any shipped
    /// collector produces, which is the whole of what this pins.
    /// </para>
    /// </summary>
    [Fact]
    public void A_coordinate_named_but_not_written_does_not_split_a_shared_source()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings =
                [
                    Placed("gauche", ("absente", "")),
                    Placed("ancien", ("absente", "")),
                ],
            },
            Scan() with
            {
                Findings =
                [
                    Placed("gauche", ("absente", "")),
                    Placed("nouveau", ("absente", "")),
                ],
            });

        Assert.Equal(2, diff.Findings.Count);
        Assert.DoesNotContain(diff.Findings, c => c.Change == ChangeKind.Changed);
    }

    /// <summary>
    /// Two places of one source addressed along different axes, carrying the same value.
    ///
    /// <para>
    /// What holds them apart is that a family's axes are one fixed vector every finding of the
    /// family is read against, so a value sits in its own axis's field and nowhere else. Read as
    /// the naked value of whichever axis each finding happens to name, both places read
    /// « IPv4 », neither designates one thing any more, and the repointed one falls back to the
    /// two lines it had.
    /// </para>
    ///
    /// <para>
    /// Hand-written, the third of the three, and for the first one's reason: no shipped collector
    /// addresses one source along two axes, so the shape belongs to the mechanism.
    /// </para>
    /// </summary>
    [Fact]
    public void Two_axes_carrying_the_same_value_stay_two_places()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = [Placed("voisin", ("zone", "IPv4")), Placed("ancien", ("pile", "IPv4"))],
            },
            Scan() with
            {
                Findings = [Placed("voisin", ("zone", "IPv4")), Placed("nouveau", ("pile", "IPv4"))],
            });

        var change = Assert.Single(diff.Findings);

        Assert.Equal(ChangeKind.Changed, change.Change);
        Assert.Equal("nouveau", change.Target);
    }

    // ---- a baseline written by another build -------------------------------

    /// <summary>
    /// The comparison a user makes first: <c>rempart diff &lt;scan&gt;</c> reads the stick's
    /// baseline, and a baseline is deliberately stable — so it was written by an earlier build,
    /// and its resolver findings carry the stack without saying it is a coordinate.
    ///
    /// <para>
    /// Read off each finding alone, that baseline's places were all coordinate-less, none of
    /// them matched the day's scan, and the two lines #195 exists to remove came back on the
    /// commonest card there is — a single-stack one, which the doc of the collector explains is
    /// most of them, a v6 interface served by DHCPv6 alone emitting nothing. The axes are the
    /// family's rather than the finding's for this: the names still come from a collector, and
    /// either side of the comparison may be the side that says them.
    /// </para>
    /// </summary>
    [Fact]
    public void A_baseline_written_before_the_coordinate_was_named_still_merges()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = AsWrittenBeforeTheMarker(
                    Resolvers(Static(Adapter, "9.9.9.9", DnsStack.IPv4))),
            },
            Scan() with { Findings = Resolvers(Static(Adapter, "203.0.113.9", DnsStack.IPv4)) });

        var change = Assert.Single(diff.Findings);

        Assert.Equal(ChangeKind.Changed, change.Change);
        Assert.Equal("203.0.113.9", change.Target);
        Assert.Contains(change.Notes, note =>
            note.Contains("9.9.9.9 → 203.0.113.9", StringComparison.Ordinal));
    }

    /// <summary>
    /// And the trap does not reopen on that older baseline: reading the family's axes off the
    /// day's scan is not the same as matching anything under the source.
    ///
    /// <para>
    /// A v4 resolver dropped while a v6 one is set is two places whatever build wrote either
    /// side — the value telling them apart is in the older report too, it is only its name that
    /// is younger. Excusing an unnamed coordinate instead of reading the family's would merge
    /// these two, which is the substitution that never happened.
    /// </para>
    /// </summary>
    [Fact]
    public void A_baseline_written_before_the_coordinate_was_named_does_not_pair_two_stacks()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = AsWrittenBeforeTheMarker(
                    Resolvers(Static(Adapter, "9.9.9.9", DnsStack.IPv4))),
            },
            Scan() with { Findings = Resolvers(Static(Adapter, "2620:fe::fe", DnsStack.IPv6)) });

        Assert.Equal(2, diff.Findings.Count);
        Assert.DoesNotContain(diff.Findings, c => c.Change == ChangeKind.Changed);
    }

    // ---- the guard, one half at a time --------------------------------------

    /// <summary>
    /// One redirection removed from the <c>hosts</c> file and two added. The half of the guard
    /// that reads the later scan is the only thing refusing here — the earlier one really did
    /// hold a single line — and without it the removed redirection is paired with whichever
    /// arrival comes first, which is a substitution picked at random on a hijack surface.
    /// </summary>
    [Fact]
    public void One_hosts_line_removed_and_two_added_are_not_a_substitution()
    {
        var diff = ScanDiff.Compare(
            Scan() with { Findings = Hosts("198.51.100.20 ancien.example") },
            Scan() with
            {
                Findings = Hosts("203.0.113.7 banque.example", "198.51.100.21 nouveau.example"),
            });

        Assert.Equal(3, diff.Findings.Count);
        Assert.DoesNotContain(diff.Findings, c => c.Change == ChangeKind.Changed);
    }

    /// <summary>
    /// The mirror, and the other half: two redirections removed and one added. Here the later
    /// scan holds a single line, so only the half reading the earlier one refuses.
    /// </summary>
    [Fact]
    public void Two_hosts_lines_removed_and_one_added_are_not_a_substitution()
    {
        var diff = ScanDiff.Compare(
            Scan() with
            {
                Findings = Hosts("198.51.100.20 ancien.example", "203.0.113.7 banque.example"),
            },
            Scan() with { Findings = Hosts("198.51.100.21 nouveau.example") });

        Assert.Equal(3, diff.Findings.Count);
        Assert.DoesNotContain(diff.Findings, c => c.Change == ChangeKind.Changed);
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

    /// <summary>
    /// Keyed by the driver's own name, as <c>LoadedDriversCollector</c> keys it. It used to
    /// be keyed by <c>Win32_SystemDriver</c> here, which no scan has ever written.
    /// </summary>
    private static Finding Driver(string name, FindingSeverity severity = FindingSeverity.Benign) =>
        new("driver", name, $@"C:\Windows\System32\drivers\{name}", severity, [],
            new Dictionary<string, string>());

    /// <summary>
    /// An adapter GUID, the shape <c>RegistryDnsProvider</c> reads off the interface subkeys
    /// — the same one under <c>Tcpip</c> and under <c>Tcpip6</c>.
    /// </summary>
    private const string Adapter = "{7C2B4A1E-9F3D-4E58-B0A6-5C1D2E3F4A5B}";

    private static DnsInterface Static(string card, string server, DnsStack stack) =>
        new(card, [server], [], stack);

    /// <summary>
    /// The findings the shipped DNS collector makes of those interfaces — details included,
    /// which is where the stack is written down.
    /// </summary>
    private static List<Finding> Resolvers(params DnsInterface[] interfaces) =>
        [.. new DnsResolverCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            dns: new FakeDnsProvider(interfaces)))];

    /// <summary>
    /// A finding at a place named by <paramref name="axes"/>, under one shared source. An axis
    /// given an empty value is named and not written — the collector-side slip the key has to
    /// survive.
    /// </summary>
    private static Finding Placed(string target, params (string Axis, string Value)[] axes)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [FindingDetails.Place] = string.Join(", ", axes.Select(axis => axis.Axis)),
        };

        foreach (var (axis, value) in axes.Where(axis => axis.Value.Length > 0))
        {
            details[axis] = value;
        }

        return new Finding("surface", "une seule source", target,
            FindingSeverity.Notable, [], details);
    }

    /// <summary>
    /// The same findings as the build before #195 wrote them: the shipped collector's, minus
    /// the row naming the coordinate, which is the one thing that release did not write. Taken
    /// off the collector rather than typed out, so what a baseline on a stick really holds
    /// cannot drift from what this compares against.
    /// </summary>
    private static List<Finding> AsWrittenBeforeTheMarker(IEnumerable<Finding> findings) =>
    [
        .. findings.Select(finding => finding with
        {
            Details = finding.Details
                .Where(detail => detail.Key != FindingDetails.Place)
                .ToDictionary(detail => detail.Key, detail => detail.Value, StringComparer.Ordinal),
        }),
    ];

    /// <summary>The findings the shipped hosts collector makes of those lines.</summary>
    private static List<Finding> Hosts(params string[] lines) =>
        [.. new HostsFileCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            hostsFile: new FakeHostsFileProvider(lines)))];

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
