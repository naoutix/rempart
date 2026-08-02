using Rempart.Core.Collectors;
using Rempart.Core.Diff;
using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Promoting a report to the reference every later comparison is held to.
///
/// <para>
/// The whole point is what this refuses. A baseline is copied into place once and read
/// silently forever after: a truncated file, a report of another machine, or one produced
/// by another catalog poisons every comparison that follows, and nothing downstream can
/// tell. That is the shape of defect this repository has closed five times elsewhere —
/// something that looks like it worked.
/// </para>
/// </summary>
public sealed class BaselinePromotionTests
{
    /// <summary>
    /// The case the issue names: a copy cut in half. Judged from the text rather than from a
    /// parsed report, so the refusal is a decision of Core and not an exception caught
    /// somewhere in the command.
    /// </summary>
    [Fact]
    public void A_truncated_report_is_refused()
    {
        var truncated = Json(Scan())[..40];

        var decision = BaselinePromotion.Judge(truncated, current: null, force: false);

        Assert.Equal(PromotionVerdict.NotAReport, decision.Verdict);
        Assert.False(decision.Writes);
    }

    /// <summary>
    /// Valid JSON is not the same thing as a report. A capture, a diff, or any other file
    /// this tool writes parses far enough to carry no scan date — and a baseline with no
    /// date is a reference nothing can be compared against.
    /// </summary>
    [Fact]
    public void Well_formed_json_that_is_not_a_report_is_refused()
    {
        var decision = BaselinePromotion.Judge(
            Json(Scan() with { StartedAtUtc = "" }), current: null, force: false);

        Assert.Equal(PromotionVerdict.NotAReport, decision.Verdict);
        Assert.False(decision.Writes);
    }

    [Fact]
    public void A_first_reference_is_accepted_and_says_there_was_none()
    {
        var decision = BaselinePromotion.Judge(Json(Scan()), current: null, force: false);

        Assert.Equal(PromotionVerdict.Accepted, decision.Verdict);
        Assert.True(decision.Writes);
        Assert.Contains("aucune référence", decision.Sentence);
    }

    /// <summary>
    /// Overwriting a reference is a loss, not an update: the sentence names the date of what
    /// it replaces, so nobody discovers afterwards which posture was traded away.
    /// </summary>
    [Fact]
    public void Replacing_a_reference_says_the_date_of_the_one_it_replaces()
    {
        var decision = BaselinePromotion.Judge(
            Json(Scan("2026-08-02T10:00:00Z")),
            Json(Scan("2026-05-01T10:00:00Z")),
            force: false);

        Assert.True(decision.Writes);
        Assert.Contains("2026-05-01", decision.Sentence);
    }

    [Fact]
    public void A_report_of_another_machine_is_refused_and_both_names_are_said()
    {
        var decision = BaselinePromotion.Judge(
            Json(Scan(machine: "POSTE-02")), Json(Scan(machine: "POSTE-01")), force: false);

        Assert.Equal(PromotionVerdict.OtherMachine, decision.Verdict);
        Assert.False(decision.Writes);
        Assert.Contains("POSTE-01", decision.Sentence);
        Assert.Contains("POSTE-02", decision.Sentence);
    }

    /// <summary>
    /// Both fingerprints are said whatever is decided — what the issue asks for, and what a
    /// refusal has to carry to be acted on. Two catalogs are not two versions of one scale:
    /// a percentage from either is not comparable to the other, which is why `index` already
    /// flags the case for a fleet.
    /// </summary>
    [Fact]
    public void A_report_of_another_catalog_is_refused_and_both_fingerprints_are_said()
    {
        var decision = BaselinePromotion.Judge(
            Json(Scan() with { RulesFingerprint = "91:bbb" }),
            Json(Scan() with { RulesFingerprint = "82:aaa" }),
            force: false);

        Assert.Equal(PromotionVerdict.OtherCatalog, decision.Verdict);
        Assert.False(decision.Writes);
        Assert.Contains("82:aaa", decision.Sentence);
        Assert.Contains("91:bbb", decision.Sentence);
    }

    [Fact]
    public void An_agreeing_promotion_says_the_fingerprint_it_keeps()
    {
        var decision = BaselinePromotion.Judge(Json(Scan()), Json(Scan()), force: false);

        Assert.True(decision.Writes);
        Assert.Contains("82:aaa", decision.Sentence);
    }

    /// <summary>
    /// <c>--force</c> passes a disagreement, which is a judgement call the operator is
    /// entitled to make, and never passes a file that is not a report — there is no
    /// judgement to make about a truncated copy, only a mistake to repeat.
    /// </summary>
    [Fact]
    public void Force_passes_a_disagreement_but_never_a_file_that_is_not_a_report()
    {
        Assert.True(BaselinePromotion.Judge(
            Json(Scan(machine: "POSTE-02")), Json(Scan(machine: "POSTE-01")), force: true).Writes);

        Assert.True(BaselinePromotion.Judge(
            Json(Scan() with { RulesFingerprint = "91:bbb" }),
            Json(Scan() with { RulesFingerprint = "82:aaa" }),
            force: true).Writes);

        Assert.False(BaselinePromotion.Judge(
            Json(Scan())[..40], current: null, force: true).Writes);
    }

    /// <summary>
    /// A reference already on disk and unreadable is exactly what this command exists to
    /// repair, so it does not stand in the way of its own replacement. It is still named:
    /// silently overwriting it would hide that every comparison since it was installed was
    /// worthless.
    /// </summary>
    [Fact]
    public void An_unreadable_reference_in_place_does_not_block_its_own_replacement()
    {
        var decision = BaselinePromotion.Judge(Json(Scan()), "{ tronqué", force: false);

        Assert.True(decision.Writes);
        Assert.Contains("illisible", decision.Sentence);
    }

    private static string Json(ScanResult result) => RempartJson.Serialise(result);

    private static ScanResult Scan(
        string startedAt = "2026-08-02T09:15:00Z", string machine = "POSTE-01") => new(
        ToolVersion: "1.1.0",
        StartedAtUtc: startedAt,
        Collectors:
        [
            new CollectorResult("inventory", CollectorStatus.Ok,
                new Dictionary<string, string?> { ["machine.name"] = machine }, []),
        ],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "82:aaa",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));
}
