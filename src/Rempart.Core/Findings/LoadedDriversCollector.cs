using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Core.Findings;

/// <summary>
/// Loaded kernel drivers.
///
/// <para>
/// A driver executes in the kernel: nothing arbitrates what it does. Two things make
/// it relevant to an audit. First its signature — an unsigned kernel driver does not
/// belong on a Secure Boot machine, and it is the first sign of a forced load. Second
/// its hash, checked against the list of known vulnerable drivers: a properly signed
/// but exploitable driver is the tool of "BYOVD", where a legitimate driver is brought
/// along to be used as a lever.
/// </para>
///
/// <para>
/// The signature judgement is the same as for the other persistence surfaces
/// (<see cref="SignatureLadder"/>): the same missing signature must not be suspicious
/// here and harmless elsewhere. The blocklist check comes on top, and can only
/// escalate — a known vulnerable driver is suspicious even when signed.
/// </para>
/// </summary>
public sealed class LoadedDriversCollector(DriverBlocklist blocklist) : IFindingCollector
{
    public string Name => "drivers";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var read = providers.Drivers.Enumerate();
        var findings = new List<Finding>();

        if (read.Status != ReadStatus.Found)
        {
            // An unreadable driver table is not a machine without drivers. Staying silent
            // here would hide exactly what this collector exists to find: a vulnerable or
            // unsigned driver loaded in the kernel.
            //
            // Added rather than returned, the shape the ports and the scheduler took before
            // it. The WMI walk under this read hands over one driver at a time and can break
            // partway, so answering with this finding alone dropped the drivers it did
            // return — including, on a bad day, the vulnerable one. Only a total failure
            // leaves it on its own, the loop below having nothing to walk.
            findings.Add(Finding.Unread(
                "driver", "pilotes chargés", read.Diagnostic,
                "Énumération des pilotes refusée. Relancer en administrateur : un pilote "
                + "vulnérable chargé resterait invisible."));
        }

        foreach (var driver in read.Drivers)
        {
            var judgement = SignatureLadder.Judge(driver.Path, providers.Signatures);

            var details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["chemin"] = driver.Path,
            };
            SignatureLadder.Describe(judgement.Signature, details);

            var severity = judgement.Severity;
            var reasons = new List<string>(judgement.Reasons);

            // The blocklist is checked against the hash the signature verification
            // just computed — no second computation. A known vulnerable driver is
            // suspicious whatever its signature: a signed driver is precisely what an
            // attacker brings.
            if (blocklist.Match(judgement.Signature.Sha256) is { } blocked)
            {
                severity = FindingSeverity.Suspicious;
                reasons.Insert(0,
                    $"Pilote vulnérable connu ({blocked.Category}) : {blocked.Name}. " +
                    "Signé ou non, il peut servir de levier vers le noyau.");
                details["loldrivers"] = blocked.Category;
            }

            findings.Add(new Finding("driver", driver.Name, driver.Path, severity, reasons, details));
        }

        return findings;
    }
}
