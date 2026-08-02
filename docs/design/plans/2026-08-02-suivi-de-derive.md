# Suivi de dérive — plan d'implémentation

> **Pour un exécutant :** ce plan s'exécute tâche par tâche. Chaque tâche finit par un
> livrable testable seul et une PR. Les cases `- [ ]` servent au suivi.

**Objectif.** Rendre lisible la dérive d'une machine sur une **série** de rapports, là où
`diff` ne compare que deux points — d'après la spec
[2026-08-02-suivi-de-derive-design.md](../specs/2026-08-02-suivi-de-derive-design.md),
qui répond à #99.

**Architecture.** Un moteur **pur** dans `Rempart.Core/Drift/` ; une commande
`rempart drift` mince sur le modèle d'`IndexCommand` ; un contrat de sortie dans
`ExitCodes`, sans code nouveau. Rien n'est écrit hors de la page produite, rien n'est
supprimé.

**Où `ScanDiff` est appelé, et où il ne suffit pas.** La comparaison de deux points n'est
jamais réécrite : `ScanDiff.Compare` sur chaque paire consécutive produit les mouvements
que la page liste. Mais **la régression ouverte et l'instabilité ne se calculent pas en
enchaînant des paires**, et c'est la thèse de la spec plutôt qu'une entorse : un contrôle
qui passe, devient illisible, puis échoue ne produit *aucune* paire classée `Regression` —
`Pass → Unknown` est `VisibilityLost`, `Unknown → Fail` est `VisibilityGained`, et les deux
sont justes à leur échelle. La chute n'existe qu'à l'échelle de la série. Ces deux calculs
lisent donc la **suite des états connus** d'une règle, `Unknown` et `NotApplicable`
retirés. La frontière : *comparer deux points* reste chez `ScanDiff`, *lire une suite* est
ce que ce moteur ajoute.

**Périmètre.** Les trois issues restantes du jalon : #102 (contrat de sortie, tâche 1),
#100 (`rempart baseline`, tâche 2), #101 (tâche planifiée fournie, tâche 3). #99 est
close par la spec.

## Contraintes globales

- **AOT sans réflexion** : aucun type de ce lot n'est sérialisé, donc `RempartJsonContext`
  n'est pas touché. Si cela change, tout type sérialisé y passe (ADR-001, D1).
- **Pas de `System.IO.Path` sur du chemin Windows dans Core** : le rejeu tourne sur le job
  Linux. Le découpage de chemins reste dans `Rempart.Cli`.
- **Aucune horloge dans Core** : `DriftSeries.Build` reçoit l'instant courant en paramètre.
  Un moteur qui lit `DateTimeOffset.UtcNow` n'est pas testable sur une série figée.
- **Une capture ancienne doit se relire** : aucun champ n'est ajouté à un type sérialisé.
- **Langue** : identifiants et commentaires de code en anglais, sortie CLI en français.
- **`scripts/verify.ps1` avant chaque PR**, et `CommandSurfaceTests`,
  `BuildChainParityTests`, `UsageTests` doivent rester verts — ajouter une commande les
  touche tous les trois.

---

## Structure des fichiers

| Fichier | Responsabilité |
|---|---|
| `src/Rempart.Core/Drift/DriftPoint.cs` | *créé* — un rapport réduit à ce qu'une série lit |
| `src/Rempart.Core/Drift/DriftSeries.cs` | *créé* — le calcul : segments, régressions ouvertes, instabilité, fraîcheur |
| `src/Rempart.Core/Diff/ScanDiff.cs` | *modifié* — `MachineName` passe `public` |
| `src/Rempart.Core/Cli/ExitCodes.cs` | *modifié* — `ForDrift` |
| `src/Rempart.Core/Reports/DriftPage.cs` | *créé* — la page HTML autonome |
| `src/Rempart.Core/Reports/ConsoleReport.cs` | *modifié* — `Drift(...)` |
| `src/Rempart.Core/Cli/CommandSurface.cs` | *modifié* — lignes `drift` et `baseline` |
| `src/Rempart.Cli/Commands/DriftCommand.cs` | *créé* — découverte, groupement, rendu, code de sortie |
| `src/Rempart.Cli/Commands/BaselineCommand.cs` | *créé* — promotion validée |
| `src/Rempart.Cli/CommandTable.cs` | *modifié* — deux lignes de dispatch |
| `tools/scheduled-task/rempart-derive.xml` | *créé* — la définition versionnée, jamais importée par l'outil |
| `tests/Rempart.Tests.Unit/DriftSeriesTests.cs` | *créé* — le moteur |
| `tests/Rempart.Tests.Unit/DriftPageTests.cs` | *créé* — rendu et échappement |
| `tests/Rempart.Tests.Unit/BaselinePromotionTests.cs` | *créé* — les refus |
| `tests/Rempart.Tests.Unit/ScheduledTaskDefinitionTests.cs` | *créé* — le garde XML ↔ `CommandSurface` |
| `tests/Rempart.Tests.Unit/ExitCodeTests.cs` | *modifié* — table `ForDrift` |

---

## Tâche 1 — Le moteur de série, la commande, le contrat de sortie

Ferme #102. C'est la tâche qui porte le lot ; les deux suivantes sont petites.

**Files:**
- Create: `src/Rempart.Core/Drift/DriftPoint.cs`, `src/Rempart.Core/Drift/DriftSeries.cs`,
  `src/Rempart.Core/Reports/DriftPage.cs`, `src/Rempart.Cli/Commands/DriftCommand.cs`
- Modify: `src/Rempart.Core/Diff/ScanDiff.cs:163`, `src/Rempart.Core/Cli/ExitCodes.cs`,
  `src/Rempart.Core/Cli/CommandSurface.cs`, `src/Rempart.Core/Reports/ConsoleReport.cs`,
  `src/Rempart.Cli/CommandTable.cs`
- Test: `tests/Rempart.Tests.Unit/DriftSeriesTests.cs`,
  `tests/Rempart.Tests.Unit/DriftPageTests.cs`, `tests/Rempart.Tests.Unit/ExitCodeTests.cs`

**Interfaces produites** (ce sur quoi les tâches 2 et 3 s'appuient) :

```csharp
namespace Rempart.Core.Drift;

public sealed record DriftPoint(
    string Machine, DateTimeOffset At, string RulesFingerprint, ScanResult Result)
{
    public static DriftPoint? From(ScanResult result);
}

public sealed record ScorePoint(DateTimeOffset At, int? Overall, IReadOnlyDictionary<string, int> Domains);
public sealed record DriftSegment(string RulesFingerprint, IReadOnlyList<ScorePoint> Trajectory);
public sealed record OpenRegression(
    string RuleId, string Title, string Domain, Severity Severity,
    DateTimeOffset Since, int DaysObserved);
public sealed record UnstableControl(
    string RuleId, string Title, int Regressions, IReadOnlyList<DateTimeOffset> At);
public sealed record SeriesFreshness(
    DateTimeOffset Last, int DaysSinceLast, double? CadenceDays, bool Stale);

public sealed record DriftReport(
    string Machine, int Points, DateTimeOffset First, DateTimeOffset Last,
    IReadOnlyList<DriftSegment> Segments,
    IReadOnlyList<OpenRegression> OpenRegressions,
    IReadOnlyList<UnstableControl> Unstable,
    SeriesFreshness Freshness,
    bool LastPointPartial);

public static class DriftSeries
{
    public const double StaleFactor = 3.0;
    public static IReadOnlyList<DriftReport> Build(IEnumerable<DriftPoint> points, DateTimeOffset now);
}

// Rempart.Core.Cli
public static ExitCode ForDrift(IReadOnlyList<DriftReport> reports);

// Rempart.Core.Reports
public static class DriftPage { public const string FileName = "derive.html"; public static string Render(IReadOnlyList<DriftReport> reports); }
public static string ConsoleReport.Drift(IReadOnlyList<DriftReport> reports, string outPath, int unreadable);
```

### Étape 1.1 — La clé de série est celle du diff, pas une seconde

- [ ] **Rendre `ScanDiff.MachineName` publique** (`ScanDiff.cs:163`), avec la phrase qui
      dit pourquoi : la série et le `SameMachine` du diff doivent désigner la même chose
      par construction, pas par ressemblance.

```csharp
/// <summary>
/// The machine a report is about. Public because the drift series keys on it: two
/// notions of "same machine", one here and one over there, would eventually disagree
/// about which reports belong to the same curve.
/// </summary>
public static string MachineName(ScanResult result) =>
    result.Collectors
        .FirstOrDefault(c => c.Name == "inventory")
        ?.Fields.GetValueOrDefault("machine.name")
    ?? "machine inconnue";
```

- [ ] **Test d'abord** — la clé reste stable sur une capture anonymisée. Ce test existe
      pour qu'un sel ajouté un jour à `Anonymiser.Hash` casse ici, et pas silencieusement
      en découpant chaque série en points isolés.

```csharp
[Fact]
public void An_anonymised_machine_keeps_one_key_across_captures()
{
    Assert.Equal(Anonymiser.Hash("POSTE-01"), Anonymiser.Hash("POSTE-01"));
    Assert.StartsWith(Anonymiser.Hash("POSTE-01"), Anonymiser.Hash(Anonymiser.Hash("POSTE-01")));
}
```

- [ ] Lancer `dotnet test tests/Rempart.Tests.Unit --filter DriftSeriesTests` → échoue
      (le fichier de test n'existe pas encore ; le créer avec ce seul test d'abord).
- [ ] Commit : `test: pin the series key to the diff's notion of a machine`.

### Étape 1.2 — `DriftPoint.From`, et ce qui n'est pas un rapport

- [ ] **Test d'abord** : un rapport sans date, ou dont la date ne se lit pas, n'entre pas
      dans une série — `index` compte déjà ce cas comme illisible plutôt que de l'ignorer.

```csharp
[Theory]
[InlineData("")]
[InlineData("pas une date")]
public void A_report_without_a_readable_date_is_not_a_series_point(string started)
{
    Assert.Null(DriftPoint.From(Scan() with { StartedAtUtc = started }));
}

[Fact]
public void A_series_point_carries_the_machine_the_date_and_the_catalog()
{
    var point = DriftPoint.From(Scan());

    Assert.NotNull(point);
    Assert.Equal("POSTE-01", point.Machine);
    Assert.Equal("82:c3e6e3029b12", point.RulesFingerprint);
    Assert.Equal(new DateTimeOffset(2026, 7, 24, 9, 15, 0, TimeSpan.Zero), point.At);
}
```

- [ ] Lancer → échoue (`DriftPoint` n'existe pas).
- [ ] **Implémenter** :

```csharp
public static DriftPoint? From(ScanResult result) =>
    DateTimeOffset.TryParse(
        result.StartedAtUtc, CultureInfo.InvariantCulture,
        DateTimeStyles.RoundtripKind, out var at)
        ? new DriftPoint(ScanDiff.MachineName(result), at, result.RulesFingerprint, result)
        : null;
```

- [ ] Lancer → passe. Commit : `feat: a report reduced to what a series reads`.

### Étape 1.3 — La trajectoire, segmentée par catalogue

**Les helpers du fichier de test**, écrits une fois en tête et utilisés par toutes les
étapes qui suivent. `Scan()` est repris de `ScanDiffTests` (`ScanDiffTests.cs:705`) :

```csharp
private static DateTimeOffset At(string day) =>
    DateTimeOffset.Parse(day + "T09:15:00Z", CultureInfo.InvariantCulture,
        DateTimeStyles.RoundtripKind);

private static DriftPoint Point(
    string day,
    int? score = null,
    string catalog = "82:aaa",
    string machine = "POSTE-01",
    params (string Id, VerdictStatus Status)[] rules) =>
    DriftPoint.From(Scan() with
    {
        StartedAtUtc = day + "T09:15:00Z",
        RulesFingerprint = catalog,
        Collectors = [Inventory(machine)],
        Verdicts = [.. rules.Select(r => Rule(r.Id, r.Status))],
        Score = score is { } s ? Card(s, ("réseau", s)) : null,
    })!;

private static DriftReport Single(IReadOnlyList<DriftReport> reports) => Assert.Single(reports);
```

- [ ] **Test d'abord** :

```csharp
/// <summary>
/// Two fingerprints in one series cut the slope. A percentage produced by one catalog
/// and a percentage produced by another are not on the same scale, and subtracting them
/// would draw a climb or a fall nothing lived through.
/// </summary>
[Fact]
public void A_catalog_change_cuts_the_slope_and_keeps_the_points()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", score: 60, catalog: "82:aaa"),
        Point("2026-02-01", score: 64, catalog: "82:aaa"),
        Point("2026-03-01", score: 90, catalog: "91:bbb"),
    ], At("2026-03-02")));

    Assert.Equal(2, report.Segments.Count);
    Assert.Equal(["82:aaa", "91:bbb"], report.Segments.Select(s => s.RulesFingerprint));
    Assert.Equal(2, report.Segments[0].Trajectory.Count);
    Assert.Equal(3, report.Points);
}

/// <summary>
/// Two machines in one folder are two series. Nothing in a fleet folder says the reports
/// belong to the same machine, and drawing one curve through both would invent a posture
/// no machine ever had.
/// </summary>
[Fact]
public void Two_machines_are_two_series()
{
    var reports = DriftSeries.Build(
    [
        Point("2026-01-01", machine: "POSTE-01"),
        Point("2026-01-02", machine: "POSTE-02"),
    ], At("2026-01-03"));

    Assert.Equal(2, reports.Count);
    Assert.Equal(["POSTE-01", "POSTE-02"], reports.Select(r => r.Machine));
}
```

- [ ] Lancer → échoue.
- [ ] **Implémenter** le groupement : par `Machine` (`StringComparer.Ordinal`), tri par
      `At`, puis découpage en segments sur changement de `RulesFingerprint` d'un point au
      suivant. `ScorePoint.Domains` vient de `Result.Score?.Domains`, dictionnaire
      `Domain → Score` ; `Overall` est `Result.Score?.Overall`, donc `null` pour une
      machine qu'on n'a pas pu noter.
- [ ] Lancer → passe. Commit : `feat: a score slope that never crosses two catalogs`.

### Étape 1.4 — Régressions ouvertes et âge

**Définition, reprise de la spec §2** : une régression est *ouverte* quand un contrôle qui
a passé plus tôt dans la série échoue **au dernier point**. `Since` est la date du premier
point de la suite d'échecs courante ; `DaysObserved` sépare `Since` du dernier point — la
durée **observée**, jamais une durée déduite jusqu'à aujourd'hui, dont la série ne sait
rien.

- [ ] **Test d'abord** :

```csharp
[Fact]
public void A_control_that_failed_and_was_fixed_is_not_an_open_regression()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
    ], At("2026-03-02")));

    Assert.Empty(report.OpenRegressions);
}

[Fact]
public void An_open_regression_is_dated_from_the_point_it_started_failing()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
    ], At("2026-03-02")));

    var open = Assert.Single(report.OpenRegressions);
    Assert.Equal("WIN-X-001", open.RuleId);
    Assert.Equal(At("2026-02-01"), open.Since);
    Assert.Equal(28, open.DaysObserved);
}

/// <summary>
/// A control that was never seen passing is not a regression: it is a control that has
/// always failed, and calling it a regression would date a fall that never happened.
/// </summary>
[Fact]
public void A_control_failing_since_the_first_point_is_not_a_regression()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
    ], At("2026-02-02")));

    Assert.Empty(report.OpenRegressions);
}

/// <summary>
/// Unknown is visibility, not posture. A control read at the first point, unreadable at
/// the second and failing at the third has fallen once, not twice — and the unreadable
/// point neither dates the fall nor interrupts it.
/// </summary>
[Fact]
public void An_unreadable_point_does_not_date_a_fall()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Unknown)]),
        Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
    ], At("2026-03-02")));

    Assert.Equal(At("2026-03-01"), Assert.Single(report.OpenRegressions).Since);
}
```

- [ ] Lancer → échoue.
- [ ] **Implémenter** : pour chaque identifiant de règle, la suite des `(At, Status)` des
      points où la règle est évaluée, **`Unknown` et `NotApplicable` retirés**. Ouverte si
      le dernier état retenu est `Fail` **et** qu'un `Pass` le précède. `Since` = date du
      premier `Fail` de la suite finale d'échecs.
- [ ] Lancer → passe. Commit : `feat: an open regression carries the date it started`.

### Étape 1.5 — L'instabilité

**Définition** : le nombre de transitions `Pass → Fail` sur la série. À partir de **deux**,
le contrôle est instable — la seconde chute est ce qui fait le motif, et ce n'est pas un
seuil choisi au doigt mouillé : une chute puis une correction est un cycle de réparation
ordinaire, deux chutes disent que la correction ne tient pas.

- [ ] **Test d'abord** :

```csharp
[Fact]
public void A_control_that_falls_twice_is_named_unstable_once()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
        Point("2026-03-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        Point("2026-04-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
    ], At("2026-04-02")));

    var unstable = Assert.Single(report.Unstable);
    Assert.Equal(2, unstable.Regressions);
    Assert.Equal([At("2026-02-01"), At("2026-04-01")], unstable.At);
}

[Fact]
public void One_fall_is_not_instability()
{
    var report = Single(DriftSeries.Build(
    [
        Point("2026-01-01", rules: [("WIN-X-001", VerdictStatus.Pass)]),
        Point("2026-02-01", rules: [("WIN-X-001", VerdictStatus.Fail)]),
    ], At("2026-02-02")));

    Assert.Empty(report.Unstable);
}
```

- [ ] Lancer → échoue, implémenter, relancer → passe.
- [ ] Commit : `feat: a control that keeps falling back is said once`.

### Étape 1.6 — La fraîcheur, et le facteur trois

- [ ] **Test d'abord** :

```csharp
/// <summary>
/// Below three points no cadence is observable, so nothing is claimed — a series of two
/// scans a year apart is not a stale series, it is a series nobody can read a rhythm in.
/// </summary>
[Fact]
public void Under_three_points_no_cadence_is_claimed()
{
    var report = Single(DriftSeries.Build(
        [Point("2026-01-01"), Point("2026-02-01")], At("2026-12-01")));

    Assert.Null(report.Freshness.CadenceDays);
    Assert.False(report.Freshness.Stale);
}

[Fact]
public void A_series_that_stopped_at_three_times_its_own_cadence_is_stale()
{
    var weekly = new[] { Point("2026-01-01"), Point("2026-01-08"), Point("2026-01-15") };

    Assert.False(Single(DriftSeries.Build(weekly, At("2026-02-01"))).Freshness.Stale);
    Assert.True(Single(DriftSeries.Build(weekly, At("2026-02-20"))).Freshness.Stale);
}
```

> `2026-02-01` est à 17 jours du dernier point pour une cadence de 7 : sous le seuil de 21.
> `2026-02-20` est à 36 jours : au-dessus. Les deux bornes sont choisies pour que le test
> échoue si le facteur passe de 3 à 2 ou à 4.

- [ ] Lancer → échoue.
- [ ] **Implémenter** : intervalles en jours entre points consécutifs, médiane
      (moyenne des deux du milieu si le compte est pair) ; `Stale` vrai quand
      `DaysSinceLast > CadenceDays * StaleFactor`, et seulement à partir de trois points.
- [ ] Lancer → passe. Commit : `feat: a series says when it stopped being fed`.

### Étape 1.7 — Le contrat de sortie

- [ ] **Test d'abord**, dans `ExitCodeTests.cs`, sur le modèle de la table qui y tient
      déjà `ForScan`. Les quatre fabriques sont écrites en tête du fichier, chacune ne
      posant **que** le fait qu'elle nomme, pour qu'aucun test ne passe par accident :

```csharp
private static DriftReport Clean() => new(
    Machine: "POSTE-01", Points: 3, First: At("2026-01-01"), Last: At("2026-01-15"),
    Segments: [], OpenRegressions: [], Unstable: [],
    Freshness: new SeriesFreshness(At("2026-01-15"), 1, 7, Stale: false),
    LastPointPartial: false);

private static DriftReport WithOpenRegression() => Clean() with
{
    OpenRegressions = [new("WIN-X-001", "Contrôle", "réseau", Severity.High, At("2026-01-08"), 7)],
};

private static DriftReport Stale() => Clean() with
{
    Freshness = new SeriesFreshness(At("2026-01-15"), 97, 7, Stale: true),
};

private static DriftReport LastPointPartial() => Clean() with { LastPointPartial = true };
```

```csharp
[Fact]
public void An_open_regression_is_what_a_drift_run_answers()
{
    Assert.Equal(ExitCode.Regression, ExitCodes.ForDrift([WithOpenRegression()]));
}

[Fact]
public void A_stale_series_answers_partial_and_not_success()
{
    Assert.Equal(ExitCode.Partial, ExitCodes.ForDrift([Stale()]));
}

[Fact]
public void An_unevaluable_last_point_answers_partial()
{
    Assert.Equal(ExitCode.Partial, ExitCodes.ForDrift([LastPointPartial()]));
}

[Fact]
public void Nothing_readable_is_a_failure_and_not_a_clean_run()
{
    Assert.Equal(ExitCode.Failure, ExitCodes.ForDrift([]));
}

/// <summary>
/// Several machines: the worst answer wins, in the same order the scan precedence uses —
/// what the caller can do about it. A fleet where one machine regressed does not exit 0
/// because the other nine are clean.
/// </summary>
[Fact]
public void The_worst_machine_decides_the_code()
{
    Assert.Equal(ExitCode.Regression, ExitCodes.ForDrift([Clean(), WithOpenRegression(), Stale()]));
}
```

- [ ] Lancer → échoue.
- [ ] **Implémenter**, avec le paragraphe de documentation que la spec §6 impose — l'argument
      pour `5` sur une série périmée, et l'argument contraire, écrits là où le code est :

```csharp
public static ExitCode ForDrift(IReadOnlyList<DriftReport> reports) =>
    reports.Count == 0 ? ExitCode.Failure
    : reports.Any(r => r.OpenRegressions.Count > 0) ? ExitCode.Regression
    : reports.Any(r => r.LastPointPartial || r.Freshness.Stale) ? ExitCode.Partial
    : ExitCode.Success;
```

- [ ] Lancer → passe. Commit : `feat: what a periodic drift run answers a scheduler`.

### Étape 1.8 — Les deux rendus

- [ ] **Test d'abord** dans `DriftPageTests.cs` — l'échappement, règle de M6 sans changement :

```csharp
/// <summary>
/// The page is built from strings the audited machine chose. This is the one place in the
/// project where a formatting mistake becomes a vulnerability.
/// </summary>
[Fact]
public void Everything_the_machine_chose_is_escaped()
{
    var html = DriftPage.Render([ReportFor("<script>alert(1)</script>")]);

    Assert.DoesNotContain("<script>alert(1)</script>", html);
    Assert.Contains("&lt;script&gt;", html);
}

/// <summary>
/// A stale series opens on what limits it, before any figure — the rule M6 set for a
/// non-elevated scan, for the same reason: a number read without its caveat is worse than
/// no number.
/// </summary>
[Fact]
public void A_stale_series_says_so_before_any_figure()
{
    var html = DriftPage.Render([Stale()]);
    Assert.True(html.IndexOf("dernière capture", StringComparison.Ordinal)
              < html.IndexOf("<table", StringComparison.Ordinal));
}

/// <summary>
/// Nobody prunes, so the page owes the reader the cost of that choice: how far back the
/// series goes, how many reports it read, and what they weigh. Spec §4 — the sentence is
/// what replaces an automatic deletion.
/// </summary>
[Fact]
public void The_window_the_count_and_the_disk_cost_are_said()
{
    var console = ConsoleReport.Drift([Clean()], outPath: "derive.html", unreadable: 0, bytesOnDisk: 4_194_304);

    Assert.Contains("3 rapports", console);
    Assert.Contains("2026-01-01", console);
    Assert.Contains("4", console);          // 4 Mio, formatés par le helper de taille existant
}
```

> `Clean()`, `Stale()` et `ReportFor(machine)` sont les fabriques de l'étape 1.7,
> déplacées dans un helper partagé par les deux fichiers de test plutôt que recopiées —
> deux copies d'une fabrique divergent, et c'est `DET-RECPROV` en miniature.

- [ ] Lancer → échoue.
- [ ] **Implémenter** `DriftPage.Render` par `HtmlReport.OpenDocument` (page autonome,
      CSS et script en ligne, thème clair/sombre, aucune ressource externe) et
      `ConsoleReport.Drift`, dont la signature porte `bytesOnDisk` : la rétention est une
      **phrase**, et c'est tout ce que ce jalon livre à ce sujet. Le script en ligne ne
      reçoit **aucune donnée** du scan : il filtre des nœuds déjà présents.
- [ ] Lancer → passe. Commit : `feat: a trajectory a reader can take in at a glance`.

### Étape 1.9 — La commande

- [ ] Ajouter la ligne `drift` à `CommandSurface.All` :
      `new("drift", [new("--out", OptionArity.Value)], Positionals: 1)`, et
      `"drift" => DriftCommand.Run` à `CommandTable.Dispatch`. `CommandSurfaceTests` et
      `UsageTests` refusent l'un sans l'autre — c'est le garde, le laisser travailler.
- [ ] Écrire `DriftCommand.Run` sur le patron d'`IndexCommand` (`IndexCommand.cs:17`) :
      énumération de `ReportBundle.JsonName` en `AllDirectories`, désérialisation par
      `RempartJson.DeserialiseScanResult`, `DriftPoint.From` sur chacun, les `null` comptés
      comme illisibles et **dits**, jamais tus ; `DriftSeries.Build(points,
      DateTimeOffset.UtcNow)` ; écriture de `--out` ou `<dossier>/derive.html` ;
      `Console.Write(ConsoleReport.Drift(...))` ; `return (int)ExitCodes.ForDrift(reports)`.
- [ ] Ajouter `drift` au texte d'aide (`HelpCommand`) et à la liste des commandes de
      `README.md` et `docs/ARCHITECTURE.md` — la passe de doc du 2026-07-29 a montré que
      c'est l'endroit exact où le dépôt prend un commit de retard.
- [ ] `pwsh scripts/verify.ps1` → vert.
- [ ] Commit puis **PR**, titre en anglais, `Closes #102`.

---

## Tâche 2 — `rempart baseline`, qui refuse plutôt qu'installe

Ferme #100.

**Files:**
- Create: `src/Rempart.Cli/Commands/BaselineCommand.cs`,
  `src/Rempart.Core/Reports/BaselinePromotion.cs`
- Modify: `src/Rempart.Core/Cli/CommandSurface.cs`, `src/Rempart.Cli/CommandTable.cs`
- Test: `tests/Rempart.Tests.Unit/BaselinePromotionTests.cs`

**Le jugement est pur, l'écriture est mince.** `BaselinePromotion.Judge` décide et rend une
phrase ; la commande lit deux fichiers, appelle, écrit ou non. C'est la frontière d'ADR-007
D25, appliquée ici parce qu'elle rend les quatre refus testables sans disque.

```csharp
namespace Rempart.Core.Reports;

public enum PromotionVerdict { Accepted, NotAReport, OtherMachine, OtherCatalog }

public sealed record PromotionDecision(PromotionVerdict Verdict, string Sentence)
{
    public bool Writes => Verdict == PromotionVerdict.Accepted;
}

public static class BaselinePromotion
{
    /// <param name="current">The baseline in place, or null when there is none yet.</param>
    public static PromotionDecision Judge(ScanResult candidate, ScanResult? current, bool force);
}
```

- [ ] **Test d'abord** — les quatre refus de l'issue, et ce que la phrase doit contenir :

```csharp
[Fact]
public void A_file_that_is_not_a_report_is_refused()
{
    var decision = BaselinePromotion.Judge(Scan() with { StartedAtUtc = "" }, current: null, force: false);

    Assert.Equal(PromotionVerdict.NotAReport, decision.Verdict);
    Assert.False(decision.Writes);
}

/// <summary>
/// Overwriting a reference is a loss, not an update: the sentence names the date of what
/// it replaces, so nobody discovers afterwards which posture was traded away.
/// </summary>
[Fact]
public void Replacing_a_reference_says_the_date_of_the_one_it_replaces()
{
    var decision = BaselinePromotion.Judge(
        Scan("2026-08-02T10:00:00Z"), Scan("2026-05-01T10:00:00Z"), force: false);

    Assert.True(decision.Writes);
    Assert.Contains("2026-05-01", decision.Sentence);
}

[Fact]
public void A_report_of_another_machine_is_refused_and_both_names_are_said()
{
    var decision = BaselinePromotion.Judge(
        ScanOf("POSTE-02"), ScanOf("POSTE-01"), force: false);

    Assert.Equal(PromotionVerdict.OtherMachine, decision.Verdict);
    Assert.Contains("POSTE-01", decision.Sentence);
    Assert.Contains("POSTE-02", decision.Sentence);
}

/// <summary>
/// Both fingerprints are said whatever is decided — that is what the issue asks for, and
/// a refusal that does not name what disagreed cannot be acted on.
/// </summary>
[Fact]
public void A_report_of_another_catalog_is_refused_and_both_fingerprints_are_said()
{
    var decision = BaselinePromotion.Judge(
        Scan() with { RulesFingerprint = "91:bbb" },
        Scan() with { RulesFingerprint = "82:aaa" },
        force: false);

    Assert.Equal(PromotionVerdict.OtherCatalog, decision.Verdict);
    Assert.Contains("82:aaa", decision.Sentence);
    Assert.Contains("91:bbb", decision.Sentence);
}

[Fact]
public void Force_passes_a_disagreement_but_never_a_file_that_is_not_a_report()
{
    Assert.True(BaselinePromotion.Judge(ScanOf("POSTE-02"), ScanOf("POSTE-01"), force: true).Writes);
    Assert.False(BaselinePromotion.Judge(
        Scan() with { StartedAtUtc = "" }, current: null, force: true).Writes);
}
```

- [ ] Lancer → échoue. Implémenter. Relancer → passe.
- [ ] **La commande**, et le point que l'issue vise : `File.WriteAllText` sur un fichier
      tronqué à mi-écriture laisserait une référence muette. Écrire dans
      `baseline.json.tmp` puis `File.Move(tmp, path, overwrite: true)` — un déplacement
      sur le même volume est atomique, et une coupure laisse l'ancienne référence
      intacte plutôt qu'une moitié de la nouvelle.
- [ ] **Test du fichier tronqué**, celui que l'issue exige nommément — dans
      `BaselinePromotionTests`, sur disque temporaire : écrire un JSON coupé au milieu,
      appeler la commande, vérifier le code ≠ 0 **et** que `baseline.json` d'avant est
      inchangé, octet pour octet.
- [ ] Ligne `baseline` dans `CommandSurface.All` :
      `new("baseline", [new("--baseline", OptionArity.Value), new("--force", OptionArity.Flag)], Positionals: 1)`,
      dispatch, aide, README, ARCHITECTURE.
- [ ] `pwsh scripts/verify.ps1` → vert. PR, `Closes #100`.

---

## Tâche 3 — La tâche planifiée, fournie et jamais créée

Ferme #101.

**Files:**
- Create: `tools/scheduled-task/rempart-derive.xml`, `tools/scheduled-task/README.md`
- Test: `tests/Rempart.Tests.Unit/ScheduledTaskDefinitionTests.cs`

- [ ] **Écrire la définition** au format Task Scheduler (XML), déclencheur hebdomadaire,
      action `rempart.exe` avec `scan --report`, dossier de travail celui de la clé.
      Aucune élévation exigée dans le fichier : un scan non élevé est le cas ordinaire.
- [ ] **Le garde d'abord** — la doc ne peut pas dériver du binaire :

```csharp
/// <summary>
/// The command line inside the shipped task definition is read off the file and checked
/// against the surface the binary actually accepts. A definition naming an option that no
/// longer exists would fail on a user's machine, weeks later, with nothing to connect it
/// to the commit that renamed the option — the same class of drift BuildChainParityTests
/// closes for the workflows.
/// </summary>
[Fact]
public void The_shipped_task_runs_a_line_the_binary_accepts()
{
    var xml = RepositoryFiles.Read("tools/scheduled-task/rempart-derive.xml");
    var arguments = XDocument.Parse(xml).Descendants()
        .Single(e => e.Name.LocalName == "Arguments").Value
        .Split(' ', StringSplitOptions.RemoveEmptyEntries);

    // Usage.Check answers null when the line is one the binary honours, and a FailureExit
    // (code 6) otherwise — the same door a mistyped word goes through since #188.
    Assert.Null(Usage.Check(arguments[0], arguments));
}
```

- [ ] Lancer → échoue si la ligne est fautive, passe sinon.
- [ ] **Le README de `tools/scheduled-task/`** dit, dans cet ordre : la commande d'import
      (`schtasks /Create /XML …`), le compte sous lequel la tâche tourne, où atterrissent
      les rapports, comment lire la dérive ensuite (`rempart drift`), et **qu'un scan non
      élevé rend `5`, cas ordinaire et non panne**. Il dit aussi que l'outil n'importe
      jamais cette tâche lui-même, et pourquoi — v1 promet de ne pas modifier la
      configuration du système.
- [ ] Ajouter le renvoi depuis `README.md`.
- [ ] `pwsh scripts/verify.ps1` → vert. PR, `Closes #101`.

---

## Après les trois tâches

- [ ] **ROADMAP** : cocher « Suivi de dérive » dans « Le flux qui reste », avec ce que le
      lot a réellement livré et ce qu'il a laissé — le facteur trois non recalé, aucune
      série réelle. La feuille de route garde surtout ce qui a été reporté et pourquoi.
- [ ] **DEBT** : ouvrir l'entrée qui manque au registre — le seuil de péremption est un
      choix non mesuré, de la même famille que le seuil de fraîcheur des données
      d'ADR-002. L'inscrire coûte une ligne et la taire coûterait un audit.
- [ ] **CHANGELOG** : une entrée 1.2.0 en préparation.
