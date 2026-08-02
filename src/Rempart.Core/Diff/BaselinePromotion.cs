using System.Text.Json;
using Rempart.Core.Engine;
using Rempart.Core.Json;

namespace Rempart.Core.Diff;

/// <summary>Why a promotion was accepted, or what stopped it.</summary>
public enum PromotionVerdict
{
    Accepted,

    /// <summary>Unparsable, or parsed and carrying no scan date. Never forced past.</summary>
    NotAReport,

    /// <summary>A report of a different machine than the reference in place.</summary>
    OtherMachine,

    /// <summary>Produced by a different rule catalog than the reference in place.</summary>
    OtherCatalog,
}

/// <summary>A decision and the sentence that goes with it. Nothing is refused in silence.</summary>
public sealed record PromotionDecision(PromotionVerdict Verdict, string Sentence)
{
    public bool Writes => Verdict == PromotionVerdict.Accepted;
}

/// <summary>
/// Whether a report may become the baseline every later comparison is held to.
///
/// <para>
/// Today the reference is put in place by a copy, and that is the problem: <b>a corrupted
/// baseline poisons every comparison that follows, silently.</b> A truncated copy, a report
/// of another machine, a report produced by another rule catalog — in all three cases
/// <c>diff</c> then compares against a reference that means nothing, and nothing downstream
/// can tell. It is the shape of defect this repository has closed five times elsewhere:
/// something that looks like it worked.
/// </para>
///
/// <para>
/// The judgement takes <em>text</em> rather than parsed reports so that the refusal of a
/// truncated file is a decision made here, testable without a disk, rather than an exception
/// caught in a command no test project can reach — <c>Rempart.Cli</c> targets
/// <c>net10.0-windows</c> and neither suite references it.
/// </para>
/// </summary>
public static class BaselinePromotion
{
    public static PromotionDecision Judge(string candidate, string? current, bool force)
    {
        if (Read(candidate) is not { } promoted)
        {
            // Never forced past. A disagreement is a judgement call an operator is entitled
            // to make; a truncated copy offers no judgement, only a mistake to repeat.
            return new PromotionDecision(
                PromotionVerdict.NotAReport,
                "Ce fichier n'est pas un rapport de scan lisible : rien n'a été installé. "
                + "« rempart scan --report » en produit un, et c'est ce fichier-là qu'on promeut.");
        }

        var machine = ScanDiff.MachineName(promoted);

        if (current is null)
        {
            return new PromotionDecision(
                PromotionVerdict.Accepted,
                $"Référence installée : {machine}, scan du {Day(promoted)}, catalogue "
                + $"{promoted.RulesFingerprint}. Il n'y avait aucune référence en place.");
        }

        if (Read(current) is not { } replaced)
        {
            // The very thing this command exists to repair does not stand in the way of its
            // own replacement. Named rather than overwritten in silence: an unreadable
            // reference means every comparison made since it was installed was worthless,
            // and that is worth knowing.
            return new PromotionDecision(
                PromotionVerdict.Accepted,
                $"Référence installée : {machine}, scan du {Day(promoted)}, catalogue "
                + $"{promoted.RulesFingerprint}. La référence en place était illisible — "
                + "les comparaisons faites contre elle ne voulaient rien dire.");
        }

        var previous = ScanDiff.MachineName(replaced);
        var sides = $"catalogue en place {replaced.RulesFingerprint}, "
                    + $"catalogue promu {promoted.RulesFingerprint}";

        if (!string.Equals(machine, previous, StringComparison.Ordinal) && !force)
        {
            return new PromotionDecision(
                PromotionVerdict.OtherMachine,
                $"La référence en place décrit {previous} et ce rapport décrit {machine} : "
                + $"rien n'a été installé ({sides}). Une baseline d'une autre machine rend "
                + "chaque comparaison suivante fausse sans que rien le dise. "
                + "« --force » pour passer outre.");
        }

        if (!string.Equals(replaced.RulesFingerprint, promoted.RulesFingerprint, StringComparison.Ordinal)
            && !force)
        {
            return new PromotionDecision(
                PromotionVerdict.OtherCatalog,
                $"Ce rapport n'a pas été produit par le catalogue de la référence en place "
                + $"({sides}) : rien n'a été installé. Leurs pourcentages ne sont pas sur la "
                + "même échelle. Rescanner avec le catalogue courant, ou « --force ».");
        }

        return new PromotionDecision(
            PromotionVerdict.Accepted,
            $"Référence installée : {machine}, scan du {Day(promoted)} ({sides}). "
            + $"Elle remplace la référence du {Day(replaced)}, qui est perdue.");
    }

    /// <summary>
    /// A report, or nothing. Two failures answer the same way on purpose: text that does not
    /// parse, and text that parses into something carrying no scan date. A capture and a
    /// comparison are both valid JSON this tool writes, and neither is a posture to be held
    /// to — <c>index</c> already treats a missing date as "not a report" rather than as a
    /// report with an empty field.
    /// </summary>
    private static ScanResult? Read(string json)
    {
        try
        {
            var result = RempartJson.DeserialiseScanResult(json);
            return string.IsNullOrEmpty(result.StartedAtUtc) ? null : result;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Day(ScanResult result) =>
        result.StartedAtUtc.Length >= 10 ? result.StartedAtUtc[..10] : result.StartedAtUtc;
}
