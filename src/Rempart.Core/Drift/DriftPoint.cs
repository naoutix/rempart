using System.Globalization;
using Rempart.Core.Diff;
using Rempart.Core.Engine;

namespace Rempart.Core.Drift;

/// <summary>
/// One report, reduced to what a series reads of it.
///
/// <para>
/// The whole <see cref="ScanResult"/> is carried rather than a summary, because the series
/// hands consecutive points back to <see cref="ScanDiff.Compare"/>: a reduced copy would be
/// a second, poorer definition of what changed between two scans.
/// </para>
/// </summary>
public sealed record DriftPoint(
    string Machine,
    DateTimeOffset At,
    string RulesFingerprint,
    ScanResult Result)
{
    /// <summary>
    /// A point, or <c>null</c> when the file is not a report a series can place in time.
    ///
    /// <para>
    /// A date that cannot be read is refused rather than replaced by a default: a point
    /// placed at the epoch, or at today, would draw a slope out of a parsing failure. The
    /// caller counts the refusals and says how many — <c>index</c> already treats an
    /// unreadable report that way, and for the same reason.
    /// </para>
    /// </summary>
    public static DriftPoint? From(ScanResult result) =>
        DateTimeOffset.TryParse(
            result.StartedAtUtc,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var at)
            ? new DriftPoint(ScanDiff.MachineName(result), at, result.RulesFingerprint, result)
            : null;
}
