using System.Globalization;

namespace Rempart.Core.Providers;

/// <summary>
/// The band of port numbers Windows hands out to sockets that did not ask for a specific
/// one.
///
/// <para>
/// It decides nothing about security and everything about noise. A browser holds a dozen of
/// these at any moment and the system renumbers them constantly, so two scans seconds apart
/// differ on nothing else; left unmarked, every <c>rempart diff</c> opens on that churn, and
/// a comparison that always shows movement stops being read.
/// </para>
/// </summary>
public sealed record DynamicPortRange(int FirstPort, int PortCount)
{
    /// <summary>
    /// The default since Vista, and the fallback when the machine could not be asked.
    ///
    /// <para>
    /// It stays a constant on purpose — it is what an unreadable machine is compared
    /// against, and the finding says which of the two it used. What it stopped being is the
    /// <em>only</em> answer: DET-PLAGE-DYNAMIQUE was this number asserted about every
    /// machine, including the ones that had been reconfigured.
    /// </para>
    /// </summary>
    public static readonly DynamicPortRange WindowsDefault = new(49152, 16384);

    public int LastPort => FirstPort + PortCount - 1;

    public bool Contains(int port) => port >= FirstPort && port <= LastPort;

    /// <summary>Spans two ranges, lowest start to highest end.</summary>
    public DynamicPortRange SpannedWith(DynamicPortRange other)
    {
        var first = Math.Min(FirstPort, other.FirstPort);
        var last = Math.Max(LastPort, other.LastPort);
        return new DynamicPortRange(first, last - first + 1);
    }

    /// <summary>
    /// Reads the two numbers out of one <c>netsh int ipv4 show dynamicport tcp</c> table.
    ///
    /// <para>
    /// <b>Nothing here matches a label</b>, and that is the whole design. <c>netsh</c> has no
    /// <c>/English</c> switch — unlike DISM, whose parser this repository had to pin against
    /// seven translated labels — so its table comes out in the system language: on this
    /// machine « Port de démarrage » and « Nombre de ports ». Matching those would produce a
    /// range read correctly on the maintainer's workstation and nowhere else, which is worse
    /// than not reading it at all, because it would be a wrong statement instead of a
    /// declared assumption. What is stable across languages is the <em>shape</em>: two rows,
    /// each <c>label : value</c>, start first and count second. Only the values are read.
    /// </para>
    ///
    /// <para>
    /// Anything that is not exactly two plausible numbers yields null, and the caller falls
    /// back to <see cref="WindowsDefault"/> while saying so. A tool that guessed here would
    /// be inventing a machine's configuration out of a parse failure.
    /// </para>
    /// </summary>
    public static DynamicPortRange? Parse(string output)
    {
        var numbers = new List<int>();

        foreach (var line in output.Split('\n'))
        {
            var separator = line.LastIndexOf(':');
            if (separator < 0)
            {
                continue;
            }

            if (int.TryParse(line[(separator + 1)..].Trim(), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var value))
            {
                numbers.Add(value);
            }
        }

        if (numbers.Count != 2)
        {
            return null;
        }

        var (first, count) = (numbers[0], numbers[1]);

        // A range that runs off the end of the port space, or starts at zero, means the two
        // values were not the two we thought: better no reading than a band that would mark
        // a service port as ephemeral.
        return first >= 1 && count >= 1 && (long)first + count - 1 <= 65535
            ? new DynamicPortRange(first, count)
            : null;
    }

    /// <summary>How the report names it: « 49152–65535 ».</summary>
    public string Describe() => $"{FirstPort}–{LastPort}";
}

/// <summary>
/// The range, plus whether the machine could be asked at all — the channel every other read
/// on this surface already carries.
///
/// <para>
/// The distinction it holds is the point of DET-PLAGE-DYNAMIQUE: « the machine says
/// 49152–65535 » and « nobody asked, so we assumed 49152–65535 » are the same numbers and
/// not the same claim, and the report is not allowed to print the second as the first.
/// </para>
/// </summary>
public sealed record DynamicPortRangeRead(
    ReadStatus Status,
    DynamicPortRange? Range,
    string? Diagnostic = null)
{
    public static DynamicPortRangeRead Found(DynamicPortRange range) =>
        new(ReadStatus.Found, range);

    /// <summary>
    /// Nobody could ask the machine. <b>There is no refusal factory on this read at all</b>,
    /// and there is nothing to refuse: <c>netsh int ipv4 show dynamicport</c> reads a value
    /// any account may read, and the branches that reach here are a binary that is not there,
    /// a table that would not parse, and a capture taken before the range was collected. None
    /// of the three is repaired by elevating.
    /// </summary>
    public static DynamicPortRangeRead Failed(string reason) =>
        new(ReadStatus.Failed, null, reason);

    /// <summary>
    /// What the judgement uses, and whether it was read. Kept as one call so no caller can
    /// take the range without also learning where it came from — which is the whole defect
    /// this record closes.
    /// </summary>
    public (DynamicPortRange Range, bool Measured) Effective() =>
        Range is { } measured
            ? (measured, true)
            : (DynamicPortRange.WindowsDefault, false);

    /// <summary>
    /// Folds the four tables Windows configures independently — TCP and UDP, IPv4 and IPv6 —
    /// into the single band the judgement applies.
    ///
    /// <para>
    /// This is a judgement and it lives here, not beside the process that runs <c>netsh</c>:
    /// deciding what to report when three tables agree and one refuses is a decision about
    /// what the tool is allowed to claim, and it is testable on the Linux job. It did not
    /// start here, and the first version was wrong in a way no test could have caught because
    /// there was no test — it compared the tables' <em>labelled</em> descriptions, so
    /// « ipv4/tcp 49152–65535 » and « ipv4/udp 49152–65535 » counted as a disagreement and
    /// every scan on an ordinary machine carried a diagnostic saying so. Running the published
    /// binary is what showed it.
    /// </para>
    ///
    /// <para>
    /// Spanning rather than intersecting is the conservative choice <em>for this use</em>:
    /// the marker only ever quietens a finding already judged benign, so covering one port
    /// too many costs a line of diff noise, while covering one too few is the churn the
    /// marker exists to stop.
    /// </para>
    /// </summary>
    public static DynamicPortRangeRead Combine(IReadOnlyList<(string Label, DynamicPortRange? Range)> tables)
    {
        var read = tables.Where(table => table.Range is not null).ToList();
        var unreadable = tables.Where(table => table.Range is null).Select(t => t.Label).ToList();

        if (read.Count == 0)
        {
            return Failed(
                "Plage de ports dynamique illisible : aucune des tables n'a répondu "
                + $"({string.Join(", ", unreadable)}).");
        }

        var spanned = read.Select(table => table.Range!)
            .Aggregate(static (left, right) => left.SpannedWith(right));

        // On the ranges, never on the labelled descriptions: every table has a different
        // label, so comparing those makes four identical ranges look like four different ones.
        var distinct = read.Select(table => table.Range!.Describe())
            .Distinct(StringComparer.Ordinal)
            .Count();

        if (distinct == 1 && unreadable.Count == 0)
        {
            return Found(spanned);
        }

        var parts = new List<string>();

        if (distinct > 1)
        {
            // Reported, never hidden: a machine whose UDP range was moved and whose TCP range
            // was not is exactly the machine this reading exists for, and the span alone would
            // not say that anything unusual had been configured.
            parts.Add("Les tables ne déclarent pas la même plage : "
                + string.Join(", ", read.Select(t => $"{t.Label} {t.Range!.Describe()}"))
                + ". La plage retenue les couvre toutes.");
        }

        if (unreadable.Count > 0)
        {
            parts.Add($"Table(s) sans réponse : {string.Join(", ", unreadable)}.");
        }

        return new DynamicPortRangeRead(ReadStatus.Found, spanned, string.Join(" ", parts));
    }
}

/// <summary>
/// Asks the machine which ports it hands out automatically.
///
/// <para>
/// A provider rather than a call from the collector, and that is not ceremony: everything
/// read from a machine has to pass through this layer or the replay of a capture stops being
/// reproducible. A collector reading the range directly would answer from the Windows
/// workstation and from the Linux job differently, and every fixture reference would depend
/// on where the suite ran.
/// </para>
/// </summary>
public interface IDynamicPortRangeProvider
{
    DynamicPortRangeRead Read();
}
