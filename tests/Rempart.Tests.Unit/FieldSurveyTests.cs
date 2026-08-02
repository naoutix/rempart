using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Survey;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// What one value is worth across the machines that have been seen.
///
/// <para>
/// `diff` compares two reports, `index` aggregates machines, `drift` aggregates dates. None
/// of them answers the question every deferred rule turns on: <b>does this key hold the same
/// value on every machine, and does it depend on the Windows build?</b> That question is
/// `DET-WINDEFAULT` — some sixty defaults validated on a single machine — and it is what
/// stands between the TLS and IPv6 rules and being shipped.
/// </para>
/// </summary>
public sealed class FieldSurveyTests
{
    [Fact]
    public void One_value_seen_everywhere_is_said_to_agree()
    {
        var survey = FieldSurvey.Of("tls.1_2.client.enabled",
        [
            Report("POSTE-01", "26100", ("tls.1_2.client.enabled", "1")),
            Report("POSTE-02", "26200", ("tls.1_2.client.enabled", "1")),
        ]);

        Assert.True(survey.Agrees);
        Assert.Equal(2, survey.Machines);
    }

    /// <summary>
    /// The finding this command exists to produce: the same key, two values, and the split
    /// falls on the build. A default guessed from either machine would be wrong on the other.
    /// </summary>
    [Fact]
    public void A_value_that_depends_on_the_build_is_shown_split_by_build()
    {
        var survey = FieldSurvey.Of("tls.1_0.client.enabled",
        [
            Report("POSTE-01", "22631", ("tls.1_0.client.enabled", "absent")),
            Report("POSTE-02", "26200", ("tls.1_0.client.enabled", "0")),
        ]);

        Assert.False(survey.Agrees);
        Assert.Equal(["22631", "26200"], survey.Builds.Select(b => b.Build));
        Assert.Equal("absent", Assert.Single(survey.Builds[0].Values).Value);
        Assert.Equal("0", Assert.Single(survey.Builds[1].Values).Value);
    }

    /// <summary>
    /// Absence is counted as a value and never as a missing observation. On the registry it
    /// is the ordinary state and it carries the meaning the whole exercise is after — "the
    /// default of this build applies". Dropping it would leave a survey that agrees with
    /// itself on the two machines that happened to have the key.
    /// </summary>
    [Fact]
    public void Absence_is_a_value_and_not_a_gap()
    {
        var survey = FieldSurvey.Of("tls.1_3.server.enabled",
        [
            Report("POSTE-01", "26200", ("tls.1_3.server.enabled", "absent")),
            Report("POSTE-02", "26200", ("tls.1_3.server.enabled", "1")),
        ]);

        Assert.False(survey.Agrees);
        Assert.Equal(2, Assert.Single(survey.Builds).Values.Count);
    }

    /// <summary>
    /// A machine counts once however often it was scanned, and it is its most recent report
    /// that speaks. A folder holding a weekly series of one machine and a single report of
    /// nine others would otherwise let the first outvote the rest ten to one — and the
    /// question asked here is "how many machines", never "how many files".
    /// </summary>
    [Fact]
    public void A_machine_scanned_ten_times_still_counts_once()
    {
        var survey = FieldSurvey.Of("os.name",
        [
            Report("POSTE-01", "26200", ("os.name", "Windows 11 Pro"), at: "2026-01-01T09:00:00Z"),
            Report("POSTE-01", "26200", ("os.name", "Windows 11 Pro"), at: "2026-02-01T09:00:00Z"),
            Report("POSTE-01", "26200", ("os.name", "Windows 11 Entreprise"), at: "2026-03-01T09:00:00Z"),
        ]);

        Assert.Equal(1, survey.Machines);
        Assert.Equal(3, survey.Reports);

        // The latest report is the one that answers: an edition upgraded in March is what
        // this machine is now, not what it was in January.
        Assert.Equal("Windows 11 Entreprise", Assert.Single(Assert.Single(survey.Builds).Values).Value);
    }

    /// <summary>
    /// A rule identifier surveys the value the rule observed, which is where the sixty
    /// windowsDefault of DET-WINDEFAULT actually live — a report carries every verdict's
    /// observed value. Told apart from a collector field by the dot: rule identifiers never
    /// carry one, field names always do.
    /// </summary>
    [Fact]
    public void A_rule_identifier_surveys_what_the_rule_observed()
    {
        var survey = FieldSurvey.Of("WIN-LEG-003",
        [
            Verdicts("POSTE-01", "26200", ("WIN-LEG-003", "absent")),
            Verdicts("POSTE-02", "22631", ("WIN-LEG-003", "1")),
        ]);

        Assert.True(survey.IsRule);
        Assert.False(survey.Agrees);
    }

    /// <summary>
    /// A name nobody records is answered with an empty survey rather than with a survey that
    /// agrees. "Every machine says the same thing" and "no machine was asked" must not print
    /// the same sentence — that is the silence this repository has closed five times.
    /// </summary>
    [Fact]
    public void A_name_no_report_carries_is_not_a_survey_that_agrees()
    {
        var survey = FieldSurvey.Of("tls.9_9.client.enabled",
            [Report("POSTE-01", "26200", ("os.name", "Windows 11 Pro"))]);

        Assert.Equal(0, survey.Machines);
        Assert.Empty(survey.Builds);
        Assert.False(survey.Agrees);
    }

    /// <summary>
    /// A machine whose build could not be read is surveyed under a build of its own rather
    /// than folded into another: attributing an observation to the wrong build is exactly the
    /// error the whole command exists to prevent.
    /// </summary>
    [Fact]
    public void A_machine_with_no_readable_build_is_not_folded_into_another()
    {
        var survey = FieldSurvey.Of("tls.1_2.client.enabled",
        [
            Report("POSTE-01", "26200", ("tls.1_2.client.enabled", "1")),
            Report("POSTE-02", null, ("tls.1_2.client.enabled", "1")),
        ]);

        Assert.Equal(2, survey.Builds.Count);
        Assert.Contains(survey.Builds, b => b.Build == "build inconnue");
    }

    /// <summary>
    /// A survey of one machine agrees with itself, and printing that as agreement would hand
    /// back exactly the reassurance this command exists to remove: DET-WINDEFAULT <em>is</em>
    /// sixty values that looked unanimous on a single machine. Found by running the command
    /// on this workstation's own reports, where every survey came back « une seule valeur sur
    /// toutes les machines vues » — true, and the most misleading sentence it could print.
    /// </summary>
    [Fact]
    public void One_machine_is_not_a_consensus()
    {
        var survey = FieldSurvey.Of("tls.1_2.client.enabled",
            [Report("POSTE-01", "26200", ("tls.1_2.client.enabled", "1"))]);

        var console = Rempart.Core.Reports.ConsoleReport.Survey(survey, "reports");

        Assert.Contains("défaut supposé", console, StringComparison.Ordinal);
        Assert.DoesNotContain("Une seule valeur sur", console, StringComparison.Ordinal);
    }

    /// <summary>
    /// Build 26100 is both Windows 11 24H2 and Windows Server 2025, and SCHANNEL defaults
    /// genuinely differ between client and server editions — measured, not feared: the CI
    /// runner on 26100 Server disables TLS 1.0 and 1.1 explicitly where a Windows 11
    /// workstation on 26200 leaves both absent. Grouping on the build alone would fold two
    /// machines that answer differently under one heading, which is the false consensus this
    /// whole command exists to prevent.
    /// </summary>
    [Fact]
    public void One_build_number_shared_by_two_editions_is_two_groups()
    {
        var survey = FieldSurvey.Of("tls.1_0.client.enabled",
        [
            Edition("POSTE-01", "26100", "Windows 11 Pro", "absent"),
            Edition("SRV-01", "26100", "Windows Server 2025 Datacenter", "0"),
        ]);

        Assert.Equal(2, survey.Builds.Count);
        Assert.False(survey.Agrees);
        Assert.All(survey.Builds, build => Assert.Contains("26100", build.Build, StringComparison.Ordinal));
    }

    private static ScanResult Edition(string machine, string build, string edition, string value) =>
        Blank("2026-08-02T09:15:00Z") with
        {
            Collectors =
            [
                new("inventory", CollectorStatus.Ok, new Dictionary<string, string?>
                {
                    ["machine.name"] = machine,
                    ["os.build"] = build,
                    ["os.registryProductName"] = edition,
                }, []),
                new("tls", CollectorStatus.Ok,
                    new Dictionary<string, string?> { ["tls.1_0.client.enabled"] = value }, []),
            ],
        };

    // ---- helpers -----------------------------------------------------------

    private static ScanResult Report(
        string machine, string? build, (string Field, string Value) field,
        string at = "2026-08-02T09:15:00Z")
    {
        var inventory = new Dictionary<string, string?>
        {
            ["machine.name"] = machine,
            ["os.build"] = build,
        };

        var collectors = new List<CollectorResult>
        {
            new("inventory", CollectorStatus.Ok, inventory, []),
        };

        if (field.Field.StartsWith("os.", StringComparison.Ordinal))
        {
            inventory[field.Field] = field.Value;
        }
        else
        {
            collectors.Add(new CollectorResult(
                "tls", CollectorStatus.Ok,
                new Dictionary<string, string?> { [field.Field] = field.Value }, []));
        }

        return Blank(at) with { Collectors = collectors };
    }

    private static ScanResult Verdicts(
        string machine, string build, (string RuleId, string Observed) verdict) =>
        Report(machine, build, ("os.name", "Windows 11 Pro")) with
        {
            Collectors =
            [
                new("inventory", CollectorStatus.Ok,
                    new Dictionary<string, string?>
                    {
                        ["machine.name"] = machine,
                        ["os.build"] = build,
                    }, []),
            ],
            Verdicts =
            [
                new(verdict.RuleId, "Contrôle", Severity.High, "réseau",
                    VerdictStatus.Fail, verdict.Observed, "0"),
            ],
        };

    private static ScanResult Blank(string at) => new(
        ToolVersion: "1.2.0",
        StartedAtUtc: at,
        Collectors: [],
        Verdicts: [],
        Findings: [],
        Score: null,
        RulesFingerprint: "82:aaa",
        DataAge: new DataAge("2026-07-01T00:00:00Z", 23, false, false, 180));
}
