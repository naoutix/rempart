using Rempart.Core.Findings;

namespace Rempart.Core.Engine;

/// <summary>
/// A step that runs beside a finished scan rather than inside it — the reputation lookup,
/// the PAC fetch, the DNS probe, the stick seal — and the single door they go through.
///
/// <para>
/// Each of those already guards what it was written to guard, and every one of those
/// guarantees stops in the same place: the call. <c>FindingEnrichment</c> answers for
/// <c>IReputationSource.Lookup</c> and <c>PacEnrichment</c> for <c>IPacFetcher.Fetch</c>,
/// but the source itself is built one line above them, in <c>ScanCommand</c>, where nothing
/// stands between an exception and the catch-all of <c>Program</c>. The scan is complete at
/// that point and one statement away from being written out — losing it for an enrichment
/// the report could do without is the failure REV-08 and the VirusTotal enrichment (#157)
/// each fixed one layer too low.
/// </para>
///
/// <para>
/// So the door is above all of them, which is the only level where the invariant does not
/// depend on the source that happens to be plugged in: building it, using it and disposing
/// of it all happen inside <c>run</c>, and nothing that happens there can cost the report.
/// The <c>catch</c> names no type on purpose — a list of exception types is a list to keep
/// up to date, and three of this repository's have been caught short: REV-08 on
/// <c>NotSupportedException</c>, the VirusTotal reader on <c>FormatException</c>, and
/// <c>HttpTransport</c> on <c>InvalidOperationException</c>.
/// </para>
///
/// <para>
/// What fails becomes a line, never nothing. An unfiltered <c>catch</c> whose failure went
/// unsaid would trade a lost audit for a report that quietly omits what it was asked to
/// add, which is the worse of the two.
/// </para>
/// </summary>
public static class OptionalStep
{
    /// <summary>
    /// The finding family a missed step is filed under. One spelling, here, rather than at
    /// each call site: <c>rempart diff</c> compares findings across reports, and a family
    /// spelled two ways is two families.
    /// </summary>
    public const string Kind = "étape";

    /// <summary>
    /// Runs <paramref name="run"/> over <paramref name="scan"/>, and turns whatever it
    /// throws into a line of the report.
    ///
    /// <para>
    /// The line is an <see cref="AuditGap.Broken"/> finding, the channel a finding collector
    /// that throws already uses: it reaches the console, both reports and — the half silence
    /// used to cost — the exit code, so a scheduler is told that the enrichment asked for did
    /// not happen. <see cref="AuditGap.Refused"/> would be the wrong half of the same
    /// channel: it means "re-run elevated", and no privilege repairs a source that will not
    /// build. It is not a verdict about the machine either — nothing was observed, so nothing
    /// is accused, and <see cref="Finding.Broken"/> keeps the severity at
    /// <see cref="FindingSeverity.Notable"/>.
    /// </para>
    /// </summary>
    /// <param name="scan">The finished scan, handed to <paramref name="run"/> and kept
    /// intact should it fail.</param>
    /// <param name="step">What was asked for, as the reader asked for it — the flag, or the
    /// name of the step. It lands in <see cref="Finding.Source"/>, which is where someone
    /// looks to find out which of the things they requested is missing.</param>
    public static ScanResult Ran(ScanResult scan, string step, Func<ScanResult, ScanResult> run)
    {
        try
        {
            return run(scan);
        }
        catch (Exception ex)
        {
            return scan with
            {
                Findings =
                [
                    .. scan.Findings,
                    Finding.Broken(Kind, step, $"Étape non effectuée : {ex.Message}"),
                ],
            };
        }
    }
}
