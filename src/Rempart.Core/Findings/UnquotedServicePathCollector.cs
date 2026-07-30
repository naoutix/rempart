using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Services whose executable path is not quoted and contains a space.
///
/// <para>
/// When a service declares <c>C:\Program Files\Vendor\svc.exe</c> without quotes,
/// Windows first tries <c>C:\Program.exe</c>, then <c>C:\Program Files\Vendor.exe</c>,
/// before the real file. A third party able to write to one of those intermediate
/// locations drops its binary there, and it runs under the service account — often
/// <c>SYSTEM</c>. It is a classic privilege escalation, and the fix amounts to
/// adding quotes.
/// </para>
///
/// <para>
/// The finding is <see cref="FindingSeverity.Notable"/>, not suspicious: exploitability
/// depends on being able to write into an intermediate folder, which this collector does
/// not verify yet. It reports the weakness — a recommended hardening — without claiming
/// an exploitation it has not established.
/// </para>
/// </summary>
public sealed class UnquotedServicePathCollector : IFindingCollector
{
    private const string Namespace = @"root\CIMV2";

    public string Name => "unquoted-service-path";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var read = providers.Wmi.Query(Namespace, "Win32_Service", ["Name", "PathName"]);
        var findings = new List<Finding>();

        if (read.Status == ReadStatus.AccessDenied)
        {
            // Added rather than returned: a WMI enumeration breaks one object at a time, so
            // the services handed over before it broke are still worth judging. Answering
            // with this finding alone dropped them, and an unquoted path sitting in the part
            // that was read would have gone out with the failure that came after it. Only a
            // total failure leaves the finding on its own, because Instances is then empty
            // and the loop below has nothing to walk.
            //
            // IWmiProvider straight, with no wrapper in between, so the WMI rule applies at
            // its plainest: no reason means one of the three denial HRESULTs, a reason means
            // the code that was not.
            findings.Add(Finding.Unread("unquoted-service-path", "Win32_Service",
                Finding.WmiGap(read.Diagnostic), read.Diagnostic,
                "Énumération des services refusée. Relancer en administrateur : un chemin "
                + "non quoté resterait invisible."));
        }

        foreach (var instance in read.Instances)
        {
            var pathName = instance.Find("PathName");
            if (pathName is null || !IsUnquotedWithSpace(pathName))
            {
                continue;
            }

            var name = instance.Find("Name") ?? "?";

            findings.Add(new Finding(
                "unquoted-service-path", name, pathName, FindingSeverity.Notable,
                ["Chemin d'exécutable non quoté contenant un espace. Windows résout les "
                 + "préfixes avant le vrai fichier ; un tiers qui peut écrire à un "
                 + "emplacement intermédiaire s'exécute avec le compte du service. "
                 + "Correction : entourer le chemin de guillemets."],
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["chemin"] = pathName,
                }));
        }

        return findings;
    }

    /// <summary>
    /// True when the executable path — the part before the arguments — is not quoted
    /// and contains a space.
    ///
    /// <para>
    /// The path is delimited by the first <c>.exe</c>: what follows are arguments, and
    /// a space in the arguments does not make the service vulnerable. Neither does a
    /// path already quoted, or one without a <c>.exe</c> executable (a driver, an
    /// unusual form).
    /// </para>
    /// </summary>
    internal static bool IsUnquotedWithSpace(string pathName)
    {
        var trimmed = pathName.Trim();

        if (trimmed.Length == 0 || trimmed[0] == '"')
        {
            return false;
        }

        var exe = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe < 0)
        {
            return false;
        }

        return trimmed[..(exe + 4)].Contains(' ');
    }
}
