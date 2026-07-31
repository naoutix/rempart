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
            //
            // The WMI rule, cited rather than assumed: this surface is a Win32_SystemDriver
            // enumeration, and WmiRead is the one channel that promises an absent diagnostic
            // on an AccessDenied means a denial — the three refusal HRESULTs come back with no
            // reason, every other code comes back carrying one. So a namespace that refused is
            // Refused, a repository that stopped serving is Unreadable, and a capture that
            // never held this surface names itself and is Unreadable too.
            //
            // LiveDriverProvider forwards that read's diagnostic untouched, null included,
            // which is what makes the rule applicable here at all: it used to substitute a
            // sentence of its own for the silence, and every refusal arrived classified as a
            // failure.
            var gap = Finding.WmiGap(read.Status, read.Diagnostic);

            // Two fallbacks, picked by the value beside them. One sentence cannot serve both:
            // advising elevation under Unreadable contradicts the marker in the same finding,
            // and this branch is reachable with no diagnostic to print instead — an absent
            // class comes back bare.
            findings.Add(Finding.Unread(
                "driver", "pilotes chargés", gap, read.Diagnostic,
                gap is AuditGap.Refused
                    ? "Énumération des pilotes refusée. Relancer en administrateur : un pilote "
                      + "vulnérable chargé resterait invisible."
                    : "Énumération des pilotes sans réponse : un pilote vulnérable chargé "
                      + "resterait invisible."));
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
