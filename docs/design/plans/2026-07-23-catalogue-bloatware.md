# Catalogue bloatware (M5b) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconnaître les logiciels indésirables (bloatware) dans l'inventaire M5a et escalader leur constat, via un catalogue socle-embarqué + enrichissement signé — calque du patron LOLDrivers.

**Architecture:** Un catalogue pur (`BloatwareCatalog`, Core) apparie chaque `InstalledSoftware` par identifiant exact (PFN Appx, clé Uninstall) ou motif nom/éditeur, et rend une entrée portant risque + note d'impact. Le collecteur `software` escalade le constat bénin sans se réécrire, exactement comme `LoadedDriversCollector` avec la liste de pilotes. Le socle embarqué fusionne avec un catalogue signé arrivé par le canal ADR-002.

**Tech Stack:** C# / .NET 10, Native-AOT (pas de réflexion — JSON par source-gen), xUnit.

## Global Constraints

- **AOT sans réflexion** : toute (dé)sérialisation JSON passe par `RempartJsonContext` / `CompactJsonContext` (source-gen). Ajouter un type sérialisé = l'ajouter au contexte.
- **Aucun accès Windows direct hors `Rempart.Windows`** : le catalogue et le collecteur vivent dans `Rempart.Core`, testables sans machine (ADR-001, D5).
- **Ne rien inventer** : aucun identifiant (PFN) inscrit « de mémoire » — le contenu du socle est vérifié sur machine réelle (Task 8). Le mécanisme se teste sans machine ; la matière se valide sur le réel.
- **Plancher honnête (D12)** : le socle embarqué ne contient que des identifiants stables et vérifiés ; une donnée illisible lève plutôt que de charger un catalogue tronqué (D13/D17).
- **`Unknown`/absence n'aggrave jamais à tort** : un logiciel non reconnu reste bénin ; le catalogue ne peut qu'escalader.
- Commit à chaque tâche verte. Tests : `dotnet test tests/Rempart.Tests.Unit` (portable) et `dotnet test tests/Rempart.Tests.Windows` (Windows).

---

## File Structure

**Créés :**
- `src/Rempart.Core/Updates/BloatwareCatalog.cs` — modèle, `Parse`, `Match`, `Merge`, `Empty`, `Embedded`.
- `src/Rempart.Core/data/bloatware-baseline.json` — socle embarqué (ressource compilée).
- `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs` — matcher/parse/merge/embedded.

**Modifiés :**
- `src/Rempart.Core/Providers/ISoftwareInventoryProvider.cs` — champ `Identifier`.
- `src/Rempart.Core/Software/AppxPackageName.cs` — `FamilyName`.
- `src/Rempart.Core/Findings/SoftwareInventoryCollector.cs` — injection catalogue + escalade.
- `src/Rempart.Core/Json/RempartJson.cs` — `BloatwareCatalogFile` au contexte + `SerialiseCompact`.
- `src/Rempart.Core/Updates/Manifest.cs` — `DatasetKind.Bloatware`.
- `src/Rempart.Core/Updates/UpdateStore.cs` — routage + `CatalogResolution.Catalog` + fusion.
- `src/Rempart.Core/Engine/ScanEngine.cs` — `DefaultFindingCollectors` prend le catalogue.
- `src/Rempart.Core/Rempart.Core.csproj` — `EmbeddedResource` du socle.
- `src/Rempart.Windows/LiveSoftwareInventoryProvider.cs` — renseigne `Identifier`.
- `src/Rempart.Cli/Program.cs` — threading de `resolution.Catalog`, note d'en-tête.
- `tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs`, `UpdateStoreTests.cs` — cas ajoutés.

---

## Task 1 : Champ `Identifier` sur `InstalledSoftware` + `AppxPackageName.FamilyName`

**Files:**
- Modify: `src/Rempart.Core/Providers/ISoftwareInventoryProvider.cs:29-35`
- Modify: `src/Rempart.Core/Software/AppxPackageName.cs`
- Test: `tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs`

**Interfaces:**
- Produces: `InstalledSoftware(..., string? Identifier = null)` (dernier paramètre, défaut `null`, rétrocompatible) ; `AppxPackageName.FamilyName(string fullName) -> string`.

- [ ] **Step 1 : Test d'échec — round-trip du nouveau champ + `FamilyName`**

Ajouter dans `tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs`, dans `AppxPackageNameTests` :

```csharp
    [Fact]
    public void Derives_the_package_family_name_from_a_full_name()
    {
        Assert.Equal(
            "AdobeNotificationClient_enpm4xejd91yc",
            AppxPackageName.FamilyName("AdobeNotificationClient_7.0.2.14_x64__enpm4xejd91yc"));
    }

    [Fact]
    public void A_name_without_separators_is_its_own_family_name()
    {
        Assert.Equal("SansSeparateur", AppxPackageName.FamilyName("SansSeparateur"));
    }
```

Et modifier le test de round-trip existant `Recording_then_replaying_round_trips_the_inventory` pour porter un `Identifier` (dernier argument) :

```csharp
        var entry = new InstalledSoftware(
            "7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall, false, true, "7-Zip");
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~AppxPackageNameTests"`
Expected: FAIL — `FamilyName` n'existe pas (erreur de compilation).

- [ ] **Step 3 : Ajouter le champ `Identifier`**

Dans `ISoftwareInventoryProvider.cs`, remplacer le record :

```csharp
public sealed record InstalledSoftware(
    string Name,
    string? Version,
    string? Publisher,
    SoftwareSource Source,
    bool Provisioned,
    bool SurvivesFeatureUpdate,
    /// <summary>
    /// Identifiant stable pour l'appariement exact du catalogue (M5b) : le
    /// <b>Package Family Name</b> pour un Appx, le <b>nom de clé Uninstall</b> pour une
    /// désinstallation classique. <c>null</c> ailleurs (App Paths, Chocolatey), qui ne
    /// s'apparient alors que par motif de nom/éditeur. Une capture d'avant M5b se relit
    /// avec <c>null</c> — l'exact ne matche pas, le motif reste.
    /// </summary>
    string? Identifier = null);
```

- [ ] **Step 4 : Ajouter `FamilyName`**

Dans `AppxPackageName.cs`, ajouter la méthode publique (à côté de `Parse`) :

```csharp
    /// <summary>
    /// Dérive le Package Family Name (<c>Nom_HashÉditeur</c>) d'un nom complet
    /// <c>Nom_Version_Arch__HashÉditeur</c> : le nom (avant le premier <c>_</c>) et le
    /// hash d'éditeur (après le dernier <c>_</c>). Un nom sans séparateur est rendu tel
    /// quel — c'est déjà un identifiant.
    /// </summary>
    public static string FamilyName(string fullName)
    {
        var first = fullName.IndexOf('_');
        var last = fullName.LastIndexOf('_');
        return first < 0 || first == last
            ? fullName
            : string.Concat(fullName.AsSpan(0, first), "_", fullName.AsSpan(last + 1));
    }
```

- [ ] **Step 5 : Lancer, vérifier le succès**

Run: `dotnet test tests/Rempart.Tests.Unit`
Expected: PASS (tout le projet, y compris le round-trip modifié).

- [ ] **Step 6 : Commit**

```bash
git add src/Rempart.Core/Providers/ISoftwareInventoryProvider.cs src/Rempart.Core/Software/AppxPackageName.cs tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs
git commit -m "Porter un identifiant stable sur InstalledSoftware (M5b)"
```

---

## Task 2 : `BloatwareCatalog` — modèle, `Parse`, `Match`, `Merge`

**Files:**
- Create: `src/Rempart.Core/Updates/BloatwareCatalog.cs`
- Modify: `src/Rempart.Core/Json/RempartJson.cs`
- Test: `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs`

**Interfaces:**
- Consumes: `InstalledSoftware` (avec `Identifier`, Task 1), `SoftwareSource`.
- Produces:
  - `enum BloatwareRisk { Unwanted, SecurityRelevant }`
  - `enum BloatwareMatch { Pfn, Uninstall, Name, Publisher }`
  - `record BloatwareEntry(string Id, BloatwareMatch Match, string Value, string Category, BloatwareRisk Risk, string Impact)`
  - `record BloatwareCatalogFile(string AsOfUtc, string? Source, List<BloatwareEntry> Entries)`
  - `class BloatwareCatalog` : `static Empty`, `int Count`, `string AsOfUtc`, `BloatwareEntry? Match(InstalledSoftware sw)`, `static BloatwareCatalog Parse(string json)`, `static BloatwareCatalog Merge(BloatwareCatalog @base, BloatwareCatalog incoming)`.

- [ ] **Step 1 : Écrire les tests d'échec**

Create `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs` :

```csharp
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class BloatwareCatalogTests
{
    private static InstalledSoftware Appx(string pfn, string name = "X") =>
        new(name, null, null, SoftwareSource.Appx, false, false, pfn);

    private static InstalledSoftware Uninstall(string key, string name = "X", string? publisher = null) =>
        new(name, null, publisher, SoftwareSource.Uninstall, false, true, key);

    private static BloatwareCatalog Catalog(params BloatwareEntry[] entries) =>
        BloatwareCatalog.Parse(RempartJson.SerialiseCompact(
            new BloatwareCatalogFile("2026-07-23T00:00:00Z", "test", [.. entries])));

    private static BloatwareEntry Entry(
        string id, BloatwareMatch match, string value,
        BloatwareRisk risk = BloatwareRisk.Unwanted) =>
        new(id, match, value, "test-cat", risk, "Impact non vide.");

    [Fact]
    public void An_empty_catalog_matches_nothing() =>
        Assert.Null(BloatwareCatalog.Empty.Match(Appx("Anything_hash")));

    [Fact]
    public void A_pfn_entry_matches_an_appx_by_exact_identifier()
    {
        var hit = Catalog(Entry("B1", BloatwareMatch.Pfn, "king.CandyCrush_kgqvny"))
            .Match(Appx("king.CandyCrush_kgqvny"));

        Assert.Equal("B1", hit?.Id);
    }

    [Fact]
    public void A_pfn_entry_does_not_match_a_uninstall_entry_of_the_same_string()
    {
        // Source-gated : un PFN ne s'apparie qu'à un Appx.
        Assert.Null(Catalog(Entry("B1", BloatwareMatch.Pfn, "shared-id"))
            .Match(Uninstall("shared-id")));
    }

    [Fact]
    public void A_uninstall_entry_matches_by_exact_key()
    {
        Assert.Equal("B2", Catalog(Entry("B2", BloatwareMatch.Uninstall, "{GUID-123}"))
            .Match(Uninstall("{GUID-123}"))?.Id);
    }

    [Fact]
    public void A_name_entry_matches_a_case_insensitive_substring()
    {
        Assert.Equal("B3", Catalog(Entry("B3", BloatwareMatch.Name, "mcafee"))
            .Match(Uninstall("k", name: "McAfee LiveSafe"))?.Id);
    }

    [Fact]
    public void A_publisher_entry_matches_a_case_insensitive_substring()
    {
        Assert.Equal("B4", Catalog(Entry("B4", BloatwareMatch.Publisher, "acme oem"))
            .Match(Uninstall("k", name: "Whatever", publisher: "ACME OEM Inc."))?.Id);
    }

    [Fact]
    public void When_several_entries_match_the_highest_risk_wins()
    {
        var hit = Catalog(
            Entry("LOW", BloatwareMatch.Name, "vendor", BloatwareRisk.Unwanted),
            Entry("HIGH", BloatwareMatch.Publisher, "vendor", BloatwareRisk.SecurityRelevant))
            .Match(Uninstall("k", name: "Vendor Tool", publisher: "Vendor"));

        Assert.Equal("HIGH", hit?.Id);
        Assert.Equal(BloatwareRisk.SecurityRelevant, hit?.Risk);
    }

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_impact() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"B","match":"Name","value":"v","category":"c","risk":"Unwanted","impact":""}]}"""));

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_id() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"","match":"Name","value":"v","category":"c","risk":"Unwanted","impact":"i"}]}"""));

    [Fact]
    public void An_unreadable_catalog_throws_rather_than_loading_partially() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse("pas du json"));

    [Fact]
    public void Merge_lets_an_incoming_entry_override_the_base_by_id()
    {
        var merged = BloatwareCatalog.Merge(
            Catalog(Entry("B1", BloatwareMatch.Name, "old")),
            Catalog(Entry("B1", BloatwareMatch.Name, "new"), Entry("B2", BloatwareMatch.Name, "extra")));

        Assert.Equal("B1", merged.Match(Uninstall("k", name: "new tool"))?.Id);   // surchargé
        Assert.Null(merged.Match(Uninstall("k", name: "old tool")));               // ancien motif parti
        Assert.Equal("B2", merged.Match(Uninstall("k", name: "extra tool"))?.Id);  // ajout
    }
}
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~BloatwareCatalogTests"`
Expected: FAIL — `BloatwareCatalog` / `SerialiseCompact(BloatwareCatalogFile)` n'existent pas.

- [ ] **Step 3 : Créer `BloatwareCatalog.cs`**

Create `src/Rempart.Core/Updates/BloatwareCatalog.cs` :

```csharp
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Providers;

namespace Rempart.Core.Updates;

/// <summary>Risque porté par une entrée du catalogue — mappé en gravité par le collecteur.</summary>
public enum BloatwareRisk { Unwanted, SecurityRelevant }

/// <summary>Comment une entrée reconnaît un logiciel installé.</summary>
public enum BloatwareMatch { Pfn, Uninstall, Name, Publisher }

/// <summary>
/// Une entrée du catalogue : comment reconnaître un logiciel, et ce qu'il coûte.
/// <see cref="Impact"/> est obligatoire — une entrée sans note d'impact n'entre pas.
/// </summary>
public sealed record BloatwareEntry(
    string Id,
    BloatwareMatch Match,
    string Value,
    string Category,
    BloatwareRisk Risk,
    string Impact);

/// <summary>Le fichier de catalogue tel qu'il est sérialisé et signé.</summary>
public sealed record BloatwareCatalogFile(string AsOfUtc, string? Source, List<BloatwareEntry> Entries);

/// <summary>
/// Le catalogue bloatware, interrogeable par logiciel installé.
///
/// <para>
/// Transposition du patron <see cref="DriverBlocklist"/> du hash de fichier à l'identité
/// logicielle : un logiciel n'a pas d'empreinte stable, d'où l'appariement hybride —
/// identifiant exact (PFN Appx, clé Uninstall) quand il existe, motif de nom/éditeur
/// curaté en repli.
/// </para>
///
/// <para>
/// Le catalogue ne juge pas la gravité : il rend une entrée porteuse d'un
/// <see cref="BloatwareRisk"/>, que le collecteur mappe. Ne rien inventer : une entrée
/// sans impact ou sans identifiant lève au chargement, un fichier illisible aussi.
/// </para>
/// </summary>
public sealed class BloatwareCatalog
{
    private readonly IReadOnlyList<BloatwareEntry> entries;

    public string AsOfUtc { get; }

    public int Count => entries.Count;

    private BloatwareCatalog(string asOfUtc, IReadOnlyList<BloatwareEntry> entries)
    {
        AsOfUtc = asOfUtc;
        this.entries = entries;
    }

    public static readonly BloatwareCatalog Empty = new("", []);

    /// <summary>
    /// Cherche l'entrée qui reconnaît ce logiciel. Plusieurs correspondances possibles
    /// (un motif nom et un motif éditeur) : le <b>risque le plus élevé</b> gagne,
    /// départage stable par <see cref="BloatwareEntry.Id"/> pour une sortie déterministe.
    /// <c>null</c> si rien ne correspond — le logiciel reste bénin.
    /// </summary>
    public BloatwareEntry? Match(InstalledSoftware software) =>
        entries
            .Where(e => Matches(e, software))
            .OrderByDescending(e => e.Risk)
            .ThenBy(e => e.Id, StringComparer.Ordinal)
            .FirstOrDefault();

    private static bool Matches(BloatwareEntry entry, InstalledSoftware sw) => entry.Match switch
    {
        // Exact et borné à la bonne source : un PFN ne s'apparie qu'à un Appx, une clé
        // Uninstall qu'à une désinstallation — sans quoi une même chaîne collerait à tort.
        BloatwareMatch.Pfn =>
            sw.Source == SoftwareSource.Appx && string.Equals(sw.Identifier, entry.Value, StringComparison.OrdinalIgnoreCase),
        BloatwareMatch.Uninstall =>
            sw.Source == SoftwareSource.Uninstall && string.Equals(sw.Identifier, entry.Value, StringComparison.OrdinalIgnoreCase),
        BloatwareMatch.Name =>
            sw.Name.Contains(entry.Value, StringComparison.OrdinalIgnoreCase),
        BloatwareMatch.Publisher =>
            sw.Publisher is { } p && p.Contains(entry.Value, StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    /// <summary>
    /// Fusionne un catalogue entrant dans un socle : une entrée de même
    /// <see cref="BloatwareEntry.Id"/> remplace celle du socle, une entrée inédite
    /// s'ajoute, aucune entrée du socle ne disparaît (D12). Calque de la fusion des règles.
    /// </summary>
    public static BloatwareCatalog Merge(BloatwareCatalog @base, BloatwareCatalog incoming)
    {
        var overrides = incoming.entries.ToDictionary(e => e.Id, e => e, StringComparer.OrdinalIgnoreCase);
        var result = new List<BloatwareEntry>(@base.entries.Count);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in @base.entries)
        {
            if (overrides.TryGetValue(entry.Id, out var replacement))
            {
                result.Add(replacement);
                used.Add(entry.Id);
            }
            else
            {
                result.Add(entry);
            }
        }

        foreach (var entry in incoming.entries)
        {
            if (!used.Contains(entry.Id))
            {
                result.Add(entry);
            }
        }

        var asOf = string.CompareOrdinal(incoming.AsOfUtc, @base.AsOfUtc) > 0 ? incoming.AsOfUtc : @base.AsOfUtc;
        return new BloatwareCatalog(asOf, result);
    }

    public static BloatwareCatalog Parse(string json)
    {
        var file = JsonSerializer.Deserialize(json, RempartJsonContext.Default.BloatwareCatalogFile)
            ?? throw new JsonException("Catalogue bloatware illisible.");

        var entries = file.Entries ?? [];

        // Une entrée sans identifiant ou sans note d'impact n'a aucune valeur d'audit :
        // lever plutôt que charger un catalogue tronqué (la note d'impact est obligatoire).
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Id) || string.IsNullOrWhiteSpace(entry.Impact))
            {
                throw new JsonException(
                    $"Entrée de catalogue invalide ({entry.Id}) : identifiant et note d'impact obligatoires.");
            }
        }

        return new BloatwareCatalog(file.AsOfUtc ?? "", entries);
    }
}
```

- [ ] **Step 4 : Enregistrer `BloatwareCatalogFile` au contexte JSON**

Dans `src/Rempart.Core/Json/RempartJson.cs` :

Ajouter la ligne d'attribut après `[JsonSerializable(typeof(DriverBlocklistFile))]` (ligne 24) :

```csharp
[JsonSerializable(typeof(BloatwareCatalogFile))]
```

Ajouter la même ligne dans `CompactJsonContext` après sa ligne 37 :

```csharp
[JsonSerializable(typeof(BloatwareCatalogFile))]
```

Ajouter la méthode de sérialisation compacte dans la classe `RempartJson`, après `SerialiseCompact(DriverBlocklistFile)` (ligne 53) :

```csharp
    /// <summary>Sérialise un catalogue bloatware sans indentation — artefact à transporter et signer.</summary>
    public static string SerialiseCompact(BloatwareCatalogFile catalog) =>
        JsonSerializer.Serialize(catalog, CompactJsonContext.Default.BloatwareCatalogFile);
```

- [ ] **Step 5 : Lancer, vérifier le succès**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~BloatwareCatalogTests"`
Expected: PASS (11 tests).

- [ ] **Step 6 : Commit**

```bash
git add src/Rempart.Core/Updates/BloatwareCatalog.cs src/Rempart.Core/Json/RempartJson.cs tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs
git commit -m "Catalogue bloatware : modèle, appariement hybride, fusion (M5b)"
```

---

## Task 3 : Escalade dans `SoftwareInventoryCollector`

**Files:**
- Modify: `src/Rempart.Core/Findings/SoftwareInventoryCollector.cs`
- Test: `tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs`

**Interfaces:**
- Consumes: `BloatwareCatalog` (Task 2), `InstalledSoftware.Identifier` (Task 1).
- Produces: `SoftwareInventoryCollector(BloatwareCatalog? catalog = null)` — défaut `Empty`, comportement M5a inchangé sans catalogue.

- [ ] **Step 1 : Écrire les tests d'échec**

Ajouter dans `SoftwareInventoryCollectorTests` (`tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs`). D'abord un helper qui prend un catalogue :

```csharp
    private static Finding CollectWith(BloatwareCatalog catalog, InstalledSoftware software) =>
        Assert.Single(new SoftwareInventoryCollector(catalog).Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider(software))));

    private static BloatwareCatalog OneEntry(BloatwareEntry entry) =>
        BloatwareCatalog.Parse(RempartJson.SerialiseCompact(
            new BloatwareCatalogFile("2026-07-23T00:00:00Z", "test", [entry])));

    [Fact]
    public void An_unwanted_match_escalates_a_benign_finding_to_notable()
    {
        var finding = CollectWith(
            OneEntry(new BloatwareEntry("BLOAT-GAME", BloatwareMatch.Name, "candy crush",
                "game", BloatwareRisk.Unwanted, "Jeu préinstallé, désinstallable sans impact.")),
            new InstalledSoftware("Candy Crush Saga", null, null, SoftwareSource.Appx, true, true, "king.CandyCrush_x"));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Equal("game", finding.Details["bloatware"]);
        Assert.Equal("BLOAT-GAME", finding.Details["catalogue"]);
        Assert.Contains("désinstallable", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void A_security_relevant_match_escalates_to_suspicious()
    {
        var finding = CollectWith(
            OneEntry(new BloatwareEntry("BLOAT-UPD", BloatwareMatch.Publisher, "acme",
                "security-relevant", BloatwareRisk.SecurityRelevant, "Updater OEM vulnérable connu.")),
            new InstalledSoftware("Acme Update", "1.0", "ACME Corp", SoftwareSource.Uninstall, false, true, "{acme}"));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    [Fact]
    public void An_unmatched_entry_stays_benign()
    {
        var finding = CollectWith(
            OneEntry(new BloatwareEntry("BLOAT-X", BloatwareMatch.Name, "zzz-absent",
                "game", BloatwareRisk.Unwanted, "impact")),
            new InstalledSoftware("7-Zip", "23.01", "Igor Pavlov", SoftwareSource.Uninstall, false, true, "7-Zip"));

        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.False(finding.Details.ContainsKey("bloatware"));
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~SoftwareInventoryCollectorTests"`
Expected: FAIL — `SoftwareInventoryCollector` n'a pas de constructeur prenant un catalogue.

- [ ] **Step 3 : Injecter le catalogue et escalader**

Remplacer le corps de `src/Rempart.Core/Findings/SoftwareInventoryCollector.cs` par :

```csharp
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Core.Findings;

/// <summary>
/// Inventaire des logiciels installés — un constat par entrée, bénin par défaut, escaladé
/// si le catalogue bloatware (M5b) reconnaît l'entrée.
///
/// <para>
/// L'inventaire seul énumère. Le catalogue vient par-dessus, sans réécrire ce collecteur :
/// il ne peut qu'aggraver un constat, jamais l'inventer. Un logiciel non reconnu reste
/// bénin. Calque de <see cref="LoadedDriversCollector"/> avec la liste de pilotes.
/// </para>
/// </summary>
public sealed class SoftwareInventoryCollector(BloatwareCatalog? catalog = null) : IFindingCollector
{
    private readonly BloatwareCatalog catalog = catalog ?? BloatwareCatalog.Empty;

    public string Name => "software";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var software in providers.SoftwareInventory.Read())
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

            // Le catalogue ne peut qu'aggraver : un logiciel reconnu monte à Notable
            // (indésirable) ou Suspicious (risque de sécurité). Le risque est mappé ici,
            // dans le code — la donnée ne porte pas de gravité en dur.
            if (this.catalog.Match(software) is { } hit)
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
```

- [ ] **Step 4 : Lancer, vérifier le succès**

Run: `dotnet test tests/Rempart.Tests.Unit`
Expected: PASS (tout le projet — les tests M5a existants passent toujours, `catalog` par défaut = `Empty`).

- [ ] **Step 5 : Commit**

```bash
git add src/Rempart.Core/Findings/SoftwareInventoryCollector.cs tests/Rempart.Tests.Unit/SoftwareInventoryTests.cs
git commit -m "Escalader le constat software au croisement du catalogue bloatware (M5b)"
```

---

## Task 4 : Socle embarqué — `bloatware-baseline.json` + `BloatwareCatalog.Embedded`

**Files:**
- Create: `src/Rempart.Core/data/bloatware-baseline.json`
- Modify: `src/Rempart.Core/Rempart.Core.csproj:16-19`
- Modify: `src/Rempart.Core/Updates/BloatwareCatalog.cs`
- Test: `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs`

**Interfaces:**
- Produces: `BloatwareCatalog.Embedded` (propriété statique mise en cache), `BloatwareCatalog.EmbeddedAsOfUtc`.

> **Note sur le contenu** : les entrées PFN ci-dessous sont un point de départ **à vérifier sur machine réelle** (Task 8). Le hash d'éditeur `8wekyb3d8bbwe` est celui, public et stable, des paquets Microsoft. Les entrées tierces passent par motif de nom (pas de PFN inventé). La forme est figée ici ; les valeurs se valident sur le réel.

- [ ] **Step 1 : Écrire le test d'échec**

Ajouter dans `BloatwareCatalogTests` :

```csharp
    [Fact]
    public void The_embedded_baseline_parses_and_is_non_empty()
    {
        Assert.True(BloatwareCatalog.Embedded.Count > 0);
    }

    [Fact]
    public void The_embedded_baseline_matches_a_known_provisioned_appx()
    {
        // Xbox Game Bar : Appx Microsoft provisionné, cas type de bloatware qui revient.
        var hit = BloatwareCatalog.Embedded.Match(new InstalledSoftware(
            "Xbox Game Bar", null, null, SoftwareSource.Appx, true, true,
            "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe"));

        Assert.NotNull(hit);
        Assert.False(string.IsNullOrWhiteSpace(hit!.Impact));
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~The_embedded"`
Expected: FAIL — `BloatwareCatalog.Embedded` n'existe pas.

- [ ] **Step 3 : Créer le fichier socle**

Create `src/Rempart.Core/data/bloatware-baseline.json` :

```json
{
  "asOfUtc": "2026-07-23T00:00:00Z",
  "source": "socle Rempart — identifiants Appx stables, vérifiés sur machine réelle",
  "entries": [
    { "id": "BLOAT-XBOX-OVERLAY", "match": "Pfn", "value": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe", "category": "game", "risk": "Unwanted", "impact": "Superposition de jeu Xbox. Désinstallable ; revient à la mise à jour de fonctionnalité si provisionné." },
    { "id": "BLOAT-XBOX-APP", "match": "Pfn", "value": "Microsoft.GamingApp_8wekyb3d8bbwe", "category": "game", "risk": "Unwanted", "impact": "Application Xbox. Inutile hors usage jeu ; désinstallable sans impact système." },
    { "id": "BLOAT-BING-WEATHER", "match": "Pfn", "value": "Microsoft.BingWeather_8wekyb3d8bbwe", "category": "oem-preinstall", "risk": "Unwanted", "impact": "Widget météo préinstallé. Désinstallable sans dépendance." },
    { "id": "BLOAT-ZUNE-MUSIC", "match": "Pfn", "value": "Microsoft.ZuneMusic_8wekyb3d8bbwe", "category": "oem-preinstall", "risk": "Unwanted", "impact": "Groove Musique. Redondant avec un lecteur tiers ; désinstallable." },
    { "id": "BLOAT-CLIPCHAMP", "match": "Pfn", "value": "Clipchamp.Clipchamp_yxz26nhyzhsrt", "category": "oem-preinstall", "risk": "Unwanted", "impact": "Éditeur vidéo préinstallé. Désinstallable sans impact." }
  ]
}
```

- [ ] **Step 4 : Embarquer la ressource**

Dans `src/Rempart.Core/Rempart.Core.csproj`, dans le `ItemGroup` des ressources (celui qui inclut les YAML, lignes 16-19), ajouter :

```xml
    <!-- Socle bloatware embarqué : identifiants Appx stables, complété par un catalogue signé. -->
    <EmbeddedResource Include="data\bloatware-baseline.json" LinkBase="data" />
```

- [ ] **Step 5 : Ajouter `Embedded` / `EmbeddedAsOfUtc` à `BloatwareCatalog`**

Dans `src/Rempart.Core/Updates/BloatwareCatalog.cs`, ajouter en tête de fichier :

```csharp
using System.Reflection;
```

Et dans la classe `BloatwareCatalog`, après le champ `Empty` :

```csharp
    private static BloatwareCatalog? cachedEmbedded;

    /// <summary>
    /// Le socle embarqué : le plancher bloatware livré dans le binaire (D12), complété par
    /// un catalogue signé quand il est présent. Chargé une fois depuis les ressources.
    /// </summary>
    public static BloatwareCatalog Embedded
    {
        get
        {
            if (cachedEmbedded is not null)
            {
                return cachedEmbedded;
            }

            var assembly = typeof(BloatwareCatalog).Assembly;
            var name = assembly.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("bloatware-baseline.json", StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException(
                    "Socle bloatware embarqué introuvable. Vérifier l'inclusion de data/bloatware-baseline.json en ressource.");

            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            return cachedEmbedded = Parse(reader.ReadToEnd());
        }
    }

    /// <summary>Date de référence du socle embarqué — à avancer à chaque révision.</summary>
    public static string EmbeddedAsOfUtc => Embedded.AsOfUtc;
```

- [ ] **Step 6 : Lancer, vérifier le succès**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~BloatwareCatalogTests"`
Expected: PASS.

- [ ] **Step 7 : Commit**

```bash
git add src/Rempart.Core/data/bloatware-baseline.json src/Rempart.Core/Rempart.Core.csproj src/Rempart.Core/Updates/BloatwareCatalog.cs tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs
git commit -m "Socle bloatware embarqué, chargé des ressources (M5b)"
```

---

## Task 5 : Canal signé — `DatasetKind.Bloatware`, routage `UpdateStore`, `CatalogResolution.Catalog`

**Files:**
- Modify: `src/Rempart.Core/Updates/Manifest.cs:4-22`
- Modify: `src/Rempart.Core/Updates/UpdateStore.cs`
- Modify: `src/Rempart.Core/Engine/ScanEngine.cs:48-66,128-131`
- Modify: `src/Rempart.Cli/Program.cs:115-123`
- Test: `tests/Rempart.Tests.Unit/UpdateStoreTests.cs`

**Interfaces:**
- Consumes: `BloatwareCatalog` (Tasks 2, 4).
- Produces:
  - `DatasetKind.Bloatware = "bloatware"`.
  - `CatalogResolution(..., BloatwareCatalog Catalog)` — nouveau champ, après `Blocklist`.
  - `ScanEngine.DefaultFindingCollectors(DriverBlocklist blocklist, BloatwareCatalog catalog)`.

- [ ] **Step 1 : Étendre le helper `Publish` avec un type de dataset**

Le helper `Publish` de `UpdateStoreTests.cs` fixe le fichier en type « rules » (il ne passe pas de `Kind` à `ManifestEntry`). Lui ajouter un paramètre `kind` optionnel. Remplacer sa signature et la construction de l'entrée :

```csharp
    private (string ManifestPath, ManifestVerifier Verifier) Publish(
        TestPublisher publisher, string datasetName, string content,
        string publishedAt = "2026-08-01T00:00:00Z", string? kind = null)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        File.WriteAllBytes(Path.Combine(Source, datasetName), bytes);

        var entry = new ManifestEntry(
            datasetName, "2.0.0",
            Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length,
            kind ?? DatasetKind.Infer(datasetName));
```

(Le reste du corps de `Publish` est inchangé. Le renommage `yaml` → `content` n'affecte pas les appelants existants, qui passent l'argument positionnellement.)

- [ ] **Step 2 : Écrire les tests d'échec**

Ajouter en tête de `UpdateStoreTests.cs` l'import des providers (pour `InstalledSoftware`) :

```csharp
using Rempart.Core.Providers;
```

Puis, dans la classe, deux tests calqués sur `An_applied_update_adds_rules_and_dates_from_the_manifest` :

```csharp
    [Fact]
    public void An_applied_bloatware_dataset_resolves_into_the_catalog()
    {
        using var publisher = new TestPublisher();

        var catalogJson = RempartJson.SerialiseCompact(new BloatwareCatalogFile(
            "2026-08-01T00:00:00Z", "test",
            [new BloatwareEntry("BLOAT-SIGNED", BloatwareMatch.Name, "signedware",
                "oem-preinstall", BloatwareRisk.Unwanted, "Ajouté par catalogue signé.")]));

        var (manifestPath, verifier) = Publish(publisher, "bloatware.json", catalogJson, kind: DatasetKind.Bloatware);
        UpdateStore.Apply(manifestPath, Store, ["bloatware.json"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        // Le socle embarqué tient, l'entrée signée s'y ajoute.
        Assert.True(resolution.Catalog.Count > BloatwareCatalog.Embedded.Count);
        Assert.Equal("BLOAT-SIGNED", resolution.Catalog.Match(new InstalledSoftware(
            "SignedWare Pro", null, null, SoftwareSource.Uninstall, false, true, "{s}"))?.Id);
    }

    [Fact]
    public void Without_a_store_the_catalog_is_the_embedded_baseline()
    {
        using var publisher = new TestPublisher();
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(BloatwareCatalog.Embedded.Count, resolution.Catalog.Count);
    }
```

- [ ] **Step 3 : Lancer, vérifier l'échec**

Run: `dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~UpdateStoreTests"`
Expected: FAIL — `DatasetKind.Bloatware` et `CatalogResolution.Catalog` n'existent pas.

- [ ] **Step 4 : Ajouter le type de dataset**

Dans `src/Rempart.Core/Updates/Manifest.cs`, dans `DatasetKind`, après la constante `Drivers` (ligne 10) :

```csharp
    /// <summary>Catalogue bloatware (M5b), en JSON. Type imposé à la signature (--kind bloatware) :
    /// l'inférence par extension ne distingue pas ce JSON de la liste de pilotes.</summary>
    public const string Bloatware = "bloatware";
```

- [ ] **Step 5 : Étendre `CatalogResolution` et le routage `Resolve`**

Dans `src/Rempart.Core/Updates/UpdateStore.cs` :

Ajouter le champ au record `CatalogResolution` (après `DriverBlocklist Blocklist,`) :

```csharp
    IReadOnlyList<Rule> Rules,
    DriverBlocklist Blocklist,
    BloatwareCatalog Catalog,
    string AsOfUtc,
    string? UpdateNote);
```

Dans `Resolve`, cas « pas de manifeste » (le `return` après `if (!File.Exists(manifestPath))`) — passer le socle embarqué :

```csharp
            return new CatalogResolution(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);
```

Initialiser un catalogue local à côté de `var blocklist = DriverBlocklist.Empty;` :

```csharp
        var catalog = BloatwareCatalog.Embedded;
```

Dans le `switch (entry.Kind)`, ajouter un cas avant le `default` :

```csharp
                    case DatasetKind.Bloatware:
                        catalog = BloatwareCatalog.Merge(BloatwareCatalog.Embedded, BloatwareCatalog.Parse(text));
                        break;
```

Élargir le `catch` du bloc `try` de lecture des datasets pour inclure les erreurs du catalogue (déjà `JsonException`, donc couvert — `BloatwareCatalog.Parse` lève `JsonException`).

Mettre à jour le `return` final (mise à jour appliquée) pour porter le catalogue et compléter la note :

```csharp
        var driverNote = blocklist.Count > 0 ? $", {blocklist.Count} pilotes surveillés" : "";
        var bloatNote = catalog.Count > BloatwareCatalog.Embedded.Count
            ? $", {catalog.Count} entrées bloatware" : "";

        return new CatalogResolution(merged, blocklist, catalog, verdict.Payload.PublishedAtUtc,
            $"Mise à jour appliquée, publiée le {verdict.Payload.PublishedAtUtc} : " +
            $"{merged.Count} contrôles ({baseRules.Count} au socle){driverNote}{bloatNote}.");
```

Mettre à jour le helper `Refused` pour porter le socle embarqué :

```csharp
    private static CatalogResolution Refused(IReadOnlyList<Rule> baseRules, string note) =>
        new(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, note);
```

- [ ] **Step 6 : Câbler le catalogue au collecteur**

Dans `src/Rempart.Core/Engine/ScanEngine.cs`, changer la signature de `DefaultFindingCollectors` (ligne 48) :

```csharp
    public static IReadOnlyList<IFindingCollector> DefaultFindingCollectors(
        Updates.DriverBlocklist blocklist, Updates.BloatwareCatalog catalog) =>
```

et sa dernière entrée (ligne 65) :

```csharp
        new SoftwareInventoryCollector(catalog),
```

Dans `Run`, le défaut interne (ligne 130) :

```csharp
        foreach (var collector in findingCollectors
            ?? DefaultFindingCollectors(Updates.DriverBlocklist.Empty, Updates.BloatwareCatalog.Empty))
```

- [ ] **Step 7 : Threading dans `Program.cs`**

Dans `src/Rempart.Cli/Program.cs`, le chemin sans magasin (lignes 115-118) — ajouter le socle embarqué :

```csharp
        : new CatalogResolution(RuleCatalog.Load(OptionValue(args, "--rules")),
            DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);
```

L'appel à `DefaultFindingCollectors` (ligne 122) :

```csharp
            ScanEngine.DefaultFindingCollectors(resolution.Blocklist, resolution.Catalog));
```

- [ ] **Step 8 : Lancer, vérifier le succès**

Run: `dotnet test tests/Rempart.Tests.Unit`
Expected: PASS. Si un site de construction de `CatalogResolution` a été oublié, le compilateur le signale — ajouter `BloatwareCatalog.Embedded` (ou `.Empty` en test neutre) à ce site.

- [ ] **Step 9 : Commit**

```bash
git add src/Rempart.Core/Updates/Manifest.cs src/Rempart.Core/Updates/UpdateStore.cs src/Rempart.Core/Engine/ScanEngine.cs src/Rempart.Cli/Program.cs tests/Rempart.Tests.Unit/UpdateStoreTests.cs
git commit -m "Router le catalogue bloatware par le canal signé, fusionné au socle (M5b)"
```

---

## Task 6 : `LiveSoftwareInventoryProvider` renseigne `Identifier` (Windows)

**Files:**
- Modify: `src/Rempart.Windows/LiveSoftwareInventoryProvider.cs:60-111`
- Test: `tests/Rempart.Tests.Windows/LiveSoftwareInventoryProviderTests.cs`

**Interfaces:**
- Consumes: `AppxPackageName.FamilyName` (Task 1), `InstalledSoftware.Identifier` (Task 1).

- [ ] **Step 1 : Écrire le test d'échec (Windows)**

Ouvrir `tests/Rempart.Tests.Windows/LiveSoftwareInventoryProviderTests.cs`, repérer le test qui lit la machine réelle, et ajouter :

```csharp
    [Fact]
    public void Appx_entries_carry_a_package_family_name_as_identifier()
    {
        var software = new LiveSoftwareInventoryProvider().Read();
        var appx = software.Where(s => s.Source == SoftwareSource.Appx).ToList();

        // Sur toute machine Windows moderne il y a des paquets Appx, et chacun a un PFN.
        Assert.NotEmpty(appx);
        Assert.All(appx, s => Assert.False(string.IsNullOrWhiteSpace(s.Identifier)));
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `dotnet test tests/Rempart.Tests.Windows --filter "FullyQualifiedName~Appx_entries_carry"`
Expected: FAIL — `Identifier` est `null` pour les Appx.

- [ ] **Step 3 : Renseigner `Identifier` par source**

Dans `src/Rempart.Windows/LiveSoftwareInventoryProvider.cs` :

`ReadUninstall` — la clé de désinstallation comme identifiant (dernier argument) :

```csharp
                software.Add(new InstalledSoftware(
                    name, Text(path, "DisplayVersion"), Text(path, "Publisher"),
                    SoftwareSource.Uninstall, Provisioned: false, SurvivesFeatureUpdate: true,
                    Identifier: key));
```

`ReadAppx` — le PFN dérivé du nom complet :

```csharp
            software.Add(new InstalledSoftware(
                name, version, Publisher: null, SoftwareSource.Appx,
                Provisioned: isProvisioned,
                SurvivesFeatureUpdate: isProvisioned,
                Identifier: AppxPackageName.FamilyName(fullName)));
```

(`ReadAppPaths` et `ReadChocolatey` restent sans identifiant — `null` par défaut, ils ne s'apparient que par motif.)

- [ ] **Step 4 : Lancer, vérifier le succès**

Run: `dotnet test tests/Rempart.Tests.Windows --filter "FullyQualifiedName~LiveSoftwareInventoryProvider"`
Expected: PASS (sur machine Windows).

- [ ] **Step 5 : Commit**

```bash
git add src/Rempart.Windows/LiveSoftwareInventoryProvider.cs tests/Rempart.Tests.Windows/LiveSoftwareInventoryProviderTests.cs
git commit -m "Renseigner l'identifiant Appx (PFN) et Uninstall du live provider (M5b)"
```

---

## Task 7 : Note d'en-tête du catalogue dans le rapport

**Files:**
- Modify: `src/Rempart.Cli/Program.cs` (fonction de rendu de l'en-tête / des constats, autour de la ligne 1000)

**Interfaces:**
- Consumes: `resolution.Catalog.Count` (Task 5).

- [ ] **Step 1 : Repérer le rendu de l'en-tête**

Lire `src/Rempart.Cli/Program.cs` autour de la ligne 1000 (`[constats] {byKind} …`) et l'endroit où l'âge/la fraîcheur des données est affiché (recherche `DataAge`, `pilotes surveillés`, `UpdateNote`). L'`UpdateNote` de `CatalogResolution` porte déjà « N entrées bloatware » (Task 5) et s'affiche via le canal existant — **aucune ligne de rendu nouvelle n'est requise si l'`UpdateNote` est déjà affiché**.

- [ ] **Step 2 : Vérifier que la note s'affiche**

Run (sur Windows, après avoir appliqué un catalogue signé — voir Task 8) :
`dotnet run --project src/Rempart.Cli -- scan`
Expected: l'en-tête mentionne « … N entrées bloatware » quand un catalogue signé est appliqué.

Si l'`UpdateNote` n'est pas rendu à l'utilisateur (le rechercher dans `Program.cs` ; il l'est déjà pour la note pilotes), ajouter son affichage à côté de la ligne `[constats]`. Sinon, cette tâche est un simple point de vérification, sans changement de code.

- [ ] **Step 3 : Commit (si changement)**

```bash
git add src/Rempart.Cli/Program.cs
git commit -m "Afficher le nombre d'entrées bloatware dans l'en-tête du scan (M5b)"
```

> Si aucun changement n'est nécessaire (note déjà rendue), passer cette tâche sans commit.

---

## Task 8 : Validation sur machine réelle + catalogue signé + doc (critère de sortie)

**Files:**
- Modify: `src/Rempart.Core/data/bloatware-baseline.json` (correction des PFN si nécessaire)
- Modify: `docs/ROADMAP.md` (case M5b), `README.md` (compteurs), `docs/DEBT.md` (si dette relevée)

**Ce n'est pas du TDD** : c'est la vérification bout-en-bout exigée par le critère de sortie (« validé sur machine OEM réelle, pas sur VM »).

- [ ] **Step 1 : Vérifier les PFN du socle sur la machine réelle**

Run (PowerShell) :

```powershell
Get-AppxPackage | Select-Object -ExpandProperty PackageFamilyName | Sort-Object
```

Pour chaque entrée `Pfn` du socle (`bloatware-baseline.json`), confirmer que le `value` figure dans cette liste **si le paquet est installé**. Corriger tout PFN erroné (hash d'éditeur, casse). Une entrée dont le paquet n'est pas sur cette machine reste dans le socle — elle vaut pour d'autres machines.

- [ ] **Step 2 : Scanner et vérifier l'escalade du socle**

Run:

```powershell
dotnet run --project src/Rempart.Cli -- scan
```

Expected: au moins une entrée du socle installée sur la machine ressort en **Notable** (ou Suspicious) avec sa note d'impact, `details["bloatware"]` et `details["catalogue"]` renseignés. Les logiciels non catalogués restent bénins (comptés, non détaillés). Zéro faux positif sur un logiciel légitime.

- [ ] **Step 3 : Signer un catalogue d'enrichissement et l'appliquer**

Créer un petit catalogue d'enrichissement `catalogue-test/bloatware.json` (une entrée `Name` visant un logiciel présent sur la machine, note d'impact remplie), puis :

```powershell
# clé de dev déjà générée (rempart keygen) ; sinon la générer
rempart sign --key <clé privée> --data catalogue-test --kind bloatware
rempart update --from catalogue-test\manifest.json --apply
rempart scan
```

Expected: l'en-tête indique « … N entrées bloatware » ; l'entrée d'enrichissement escalade son logiciel cible **en plus** de celles du socle (fusion effective).

- [ ] **Step 4 : Vérifier le refus d'un catalogue altéré**

Modifier un octet de `bloatware.json` dans le magasin après `--apply`, relancer `rempart scan`.
Expected: la mise à jour est **refusée visiblement** (note d'en-tête), le socle embarqué tient — jamais un chargement silencieux.

- [ ] **Step 5 : Suite complète + publication AOT**

Run:

```powershell
./scripts/verify.ps1
```

Expected: workflows, `dotnet test` (Unit + Windows), publication AOT et exécution du binaire isolé — tout au vert. Le binaire publié embarque `bloatware-baseline.json`.

- [ ] **Step 6 : Mettre à jour la documentation**

- `docs/ROADMAP.md` : cocher `- [ ] **M5b — catalogue bloatware**` → `- [x]`, avec une ligne « Vérifié sur machine réelle : N entrées de socle, escalade du catalogue signé confirmée ».
- `README.md` : mettre à jour l'état (M5b terminé) et, le cas échéant, le nombre de constats/contrôles si l'intro les chiffre.
- `docs/DEBT.md` : si la validation a révélé une limite (ex. couverture du socle, PFN tiers non vérifiables), l'y consigner.

- [ ] **Step 7 : Commit**

```bash
git add src/Rempart.Core/data/bloatware-baseline.json docs/ROADMAP.md README.md docs/DEBT.md
git commit -m "Valider le catalogue bloatware sur machine réelle et acter M5b (M5b)"
```

---

## Self-Review — couverture de la spec

| Section spec | Tâche |
|---|---|
| Appariement hybride (PFN/Uninstall exact + Name/Publisher motif) | Task 2 (`Match`), Task 1 (`Identifier`, `FamilyName`) |
| Sévérité par risque (Unwanted→Notable, SecurityRelevant→Suspicious), mapping dans le code | Task 3 |
| `Impact` obligatoire, `Parse` lève | Task 2 |
| Risque-le-plus-élevé-gagne, départage stable | Task 2 |
| Socle embarqué + fusion `Merge` par `Id` | Task 4 (embedded), Task 2 (Merge), Task 5 (résolution) |
| `DatasetKind.Bloatware`, type imposé à la signature | Task 5 |
| Routage `UpdateStore.Resolve` + `CatalogResolution.Catalog` + note | Task 5 |
| Extension M5a (`Identifier`), round-trip snapshot, rétrocompat | Task 1 |
| Live provider renseigne `Identifier` | Task 6 |
| Câblage `ScanEngine` → collecteur | Task 5 |
| Pas de `fetch-bloatware` | (absence assumée — aucune tâche) |
| Pas d'anonymiseur | (inchangé — aucune tâche) |
| Fixtures synthétiques inchangées (pas de section software) | (vérifié par Task 5 : suite unit verte) |
| Critère de sortie : validé sur machine réelle | Task 8 |
