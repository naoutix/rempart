using Rempart.Core.Providers;

namespace Rempart.Core.Rules;

/// <summary>
/// Raw result of reading a check, before any judgment.
/// </summary>
/// <param name="Found">Value actually present, or null if absent.</param>
/// <param name="Effective">
/// Value that governs the behavior: <paramref name="Found"/> or, failing that, the
/// Windows default declared by the rule.
/// </param>
/// <param name="Denied">Access was denied: neither compliant nor non-compliant.</param>
public sealed record CheckReading(string? Found, string? Effective, bool Denied)
{
    /// <summary>What the report displays, mentioning the Windows default when relevant.</summary>
    public string? Describe(CheckSpec check)
    {
        if (Denied)
        {
            // Set when an internal failure was diagnosed; null for a legitimate access
            // denial, where there is nothing to explain.
            return Found;
        }

        if (Found is not null)
        {
            return Found;
        }

        return check.WindowsDefault is { } fallback
            ? $"absent (défaut Windows : {fallback})"
            : "absent";
    }
}

/// <summary>
/// The only place in the project that translates a <see cref="CheckSpec"/> into provider
/// calls.
///
/// Evaluation and capture each used to have their own version of this translation, to be
/// kept in sync with nothing guaranteeing it. The next check type forgotten on the
/// capture side would have produced silently incomplete snapshots, and a replay failure
/// much later, with a message unrelated to the cause.
/// </summary>
public static class CheckReader
{
    public static CheckReading Read(CheckSpec check, ProviderSet providers) => check.Kind switch
    {
        CheckKind.Service => ReadService(check, providers.Services),
        CheckKind.Policy => ReadPolicy(check, providers.Policy),
        CheckKind.Wmi => ReadWmi(check, providers.Wmi),
        _ => Read(check, providers.Registry),
    };

    /// <summary>
    /// A fact missing from the dictionary is not a non-compliance: the API could not
    /// establish it. Returning "not verifiable" rather than a verdict avoids blaming a
    /// machine for what the tool could not read.
    ///
    /// <para>
    /// And the reason travels, as it does for a service and for WMI below. Policy facts come
    /// from four independent netapi32 surfaces filling one dictionary, so what a rule needs is
    /// why <em>its</em> fact is absent, not why some other one is: a lockout policy nobody
    /// could read must not describe the password policy that answered. Null where the read
    /// recorded nothing — every capture written before that channel existed — and the verdict
    /// is then exactly what it was: <c>Unknown</c>, out of the score, with nothing to explain.
    /// </para>
    /// </summary>
    private static CheckReading ReadPolicy(CheckSpec check, ISecurityPolicyProvider policy)
    {
        var facts = policy.Read();

        if (facts.Denied || facts.Find(check.Path) is not { } value)
        {
            return new CheckReading(facts.WhyMissing(check.Path), null, Denied: true);
        }

        return new CheckReading(value, value, Denied: false);
    }

    /// <summary>
    /// A missing service is not an access denial: there is nothing to read, and the
    /// comparison will run against "absent". Distinguishing the two avoids concluding
    /// non-compliance where the scan simply could not look.
    ///
    /// <para>
    /// And a failure is not a denial either, which is the distinction that had no channel:
    /// the provider answered <c>AccessDenied</c> on any Win32 code it did not recognise, so
    /// an unreachable service control manager put every <c>type: service</c> rule under
    /// « accès refusé » at once. The verdict is deliberately unchanged — <c>Unknown</c>,
    /// out of the score, never <c>Fail</c> — because what the scan could not establish says
    /// nothing about the machine. What travels now is the reason.
    /// </para>
    /// </summary>
    private static CheckReading ReadService(CheckSpec check, IServiceStateProvider services)
    {
        var read = services.Read(check.Path);

        // Both holes, and the second one arrived under this branch rather than beside it:
        // ServiceRead.Failed carried AccessDenied until #177, so widening the read's
        // vocabulary without widening this test would have let an unopenable service control
        // manager fall through to « absent » below — compared against the rule, and answered
        // Fail on a machine nobody managed to read. Unknown is never Fail.
        if (read.Status is ReadStatus.AccessDenied or ReadStatus.Failed)
        {
            // The reason for an internal failure travels with the verdict, exactly as it
            // does for WMI below: without it, an SCM that would not open looks like missing
            // privileges. Null for a genuine refusal, where there is nothing to explain.
            return new CheckReading(read.Diagnostic, null, Denied: true);
        }

        if (read.Info is not { } info)
        {
            return new CheckReading(null, "absent", Denied: false);
        }

        var observed = check.ValueName?.ToLowerInvariant() switch
        {
            "state" => info.State.ToString().ToLowerInvariant(),
            _ => info.StartMode.ToString().ToLowerInvariant(),
        };

        return new CheckReading(observed, observed, Denied: false);
    }

    /// <summary>
    /// A WMI check covers all returned instances: every volume, every adapter. It only
    /// passes if all of them pass — a single unencrypted disk is enough to expose the
    /// data it holds.
    ///
    /// When instances diverge, the observed value lists them and the comparison fails
    /// by itself: no single value can match several.
    /// </summary>
    private static CheckReading ReadWmi(CheckSpec check, IWmiProvider wmi)
    {
        var separator = check.Path.IndexOf(':');
        if (separator < 0 || check.ValueName is null)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var read = wmi.Query(
            check.Path[..separator], check.Path[(separator + 1)..], [check.ValueName]);

        // No instances: nothing to judge. BitLocker missing on a Home edition is not a
        // non-compliance, there is simply nothing to evaluate.
        //
        // And the one consumer of a truncated enumeration that must not keep what it read,
        // which is a decision rather than an oversight: the question this method asks is
        // « do *all* the instances conform », and « all » cannot be established from a walk
        // that stopped early. Two conforming volumes out of an unknown number would answer
        // Pass, and the volume the walk never reached is precisely the one that would have
        // said otherwise. Unknown leaves the check out of the score instead — never Fail,
        // never Pass — and the diagnostic travels with it so the report names the class.
        if (read.Status != ReadStatus.Found || read.Instances.Count == 0)
        {
            // The reason for an internal failure travels with the verdict: without it,
            // a provider bug looks like missing privileges.
            return new CheckReading(read.Diagnostic, null, Denied: true);
        }

        var values = read.Instances
            .Select(i => i.Find(check.ValueName))
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (values.Count == 0)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var observed = values.Count == 1 ? values[0] : string.Join(", ", values);
        return new CheckReading(observed, observed, Denied: false);
    }

    public static CheckReading Read(CheckSpec check, IRegistryProvider registry)
    {
        if (check.Kind == CheckKind.RegistryKey)
        {
            var status = registry.KeyExists(check.Path);

            return status == ReadStatus.AccessDenied
                ? new CheckReading(null, null, Denied: true)
                : new CheckReading(
                    Found: status == ReadStatus.Found ? "present" : null,
                    Effective: status == ReadStatus.Found ? "present" : null,
                    Denied: false);
        }

        var read = registry.ReadValue(check.Path, check.ValueName!);

        if (read.Status == ReadStatus.AccessDenied)
        {
            return new CheckReading(null, null, Denied: true);
        }

        var found = read.Status == ReadStatus.Found ? read.Value?.ToString() : null;

        // Absent key: the effective behavior is the Windows default declared by the
        // rule. The verdict is therefore about what the machine actually does, not
        // about the presence of a registry entry.
        return new CheckReading(found, found ?? check.WindowsDefault, Denied: false);
    }

    /// <summary>
    /// Performs the read without using the result, so a recording provider can log it.
    /// Goes through <see cref="Read"/>: that is what guarantees capture and evaluation
    /// touch exactly the same keys.
    /// </summary>
    public static void Touch(CheckSpec check, ProviderSet providers) =>
        _ = Read(check, providers);
}
