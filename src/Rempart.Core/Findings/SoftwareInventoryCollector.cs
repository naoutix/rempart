using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Core.Findings;

/// <summary>
/// Inventory of installed software — one finding per entry, benign by default, escalated
/// when the bloatware catalog (M5b) recognises the entry.
///
/// <para>
/// The inventory alone enumerates. The catalog sits on top without rewriting this
/// collector: it can only aggravate a finding, never invent one. Unrecognised software
/// stays benign. Mirrors <see cref="LoadedDriversCollector"/> with the driver list.
/// </para>
///
/// <para>
/// The catalog is demanded, as the blocklist is next door. It used to default to
/// <see cref="BloatwareCatalog.Empty"/>, and an empty catalog recognises nothing: every
/// entry stays benign, so a collector built without it answers exactly like one facing a
/// clean machine. Dropping the argument from the registration in <c>ScanEngine</c> left the
/// whole suite green. Saying « rien à confronter » now costs a written
/// <see cref="BloatwareCatalog.Empty"/>, which is a sentence a reader can disagree with.
/// </para>
///
/// <para>
/// One demanded parameter is not the whole of it, so <c>FindingCollectorRegistrationTests</c>
/// holds two more things: that no collector grows a second, shorter constructor beside this
/// one — which carries no default and so slips past any check for one — and that the catalog
/// handed to <c>ScanEngine.DefaultFindingCollectors</c> actually arrives here, which no test
/// asserted while every one of them passed <see cref="BloatwareCatalog.Empty"/>.
/// </para>
/// </summary>
public sealed class SoftwareInventoryCollector(BloatwareCatalog catalog) : IFindingCollector
{
    public string Name => "software";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var read = providers.SoftwareInventory.Read();
        var findings = new List<Finding>();

        // Added rather than returned, for the reason the read is partial by nature: four
        // independent sources fill one list, and dropping the three that answered because the
        // fourth refused would trade one silence for another — including, on a bad day, the
        // bloatware entry the catalog was about to escalate.
        //
        // The gap follows the status and is not guessed from the sentence, which names the
        // sources and never the cause. Both are reachable here, unlike the DNS read next door:
        // the registry sources can only be denied, and the Chocolatey listing can be denied
        // (an ACL, which elevating opens — exit 3) or fail (an I/O error, which no privilege
        // repairs — exit 5).
        if (read.Status is ReadStatus.AccessDenied or ReadStatus.Failed)
        {
            var refused = read.Status is ReadStatus.AccessDenied;

            findings.Add(Finding.Unread(
                "software", "inventaire logiciel",
                refused ? AuditGap.Refused : AuditGap.Unreadable,
                read.Diagnostic,
                refused
                    ? "Inventaire logiciel refusé. Relancer en administrateur : un logiciel "
                      + "indésirable installé resterait absent du rapport."
                    : "Inventaire logiciel sans réponse : un logiciel indésirable installé "
                      + "resterait absent du rapport."));
        }

        foreach (var software in read.Software)
        {
            var details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["source"] = software.Source.ToString(),
                ["provisionné"] = software.Provisioned ? "oui" : "non",
                ["survives_feature_update"] = software.SurvivesFeatureUpdate ? "oui" : "non",
            };

            if (!string.IsNullOrEmpty(software.Version))
            {
                details["version"] = software.Version;
            }

            if (!string.IsNullOrEmpty(software.Publisher))
            {
                details["éditeur"] = software.Publisher;
            }

            var severity = FindingSeverity.Benign;
            var reasons = new List<string>();

            // The catalog can only aggravate: recognised software rises to Notable
            // (unwanted) or Suspicious (security risk). The risk is mapped here, in
            // code — the data carries no hardcoded severity.
            if (catalog.Match(software) is { } hit)
            {
                severity = hit.Risk == BloatwareRisk.SecurityRelevant
                    ? FindingSeverity.Suspicious
                    : FindingSeverity.Notable;
                reasons.Add(hit.Impact);
                details["bloatware"] = hit.Category;
                details["catalogue"] = hit.Id;
            }

            findings.Add(new Finding(
                "software", software.Source.ToString(), software.Name, severity, reasons, details));
        }

        return findings;
    }
}
