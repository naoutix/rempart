# Import du catalogue bloatware — plan d'implémentation

> **Pour un exécutant :** ce plan s'exécute tâche par tâche. Chaque tâche finit par un
> livrable testable seul et un commit. Les cases `- [ ]` servent au suivi.

**Objectif.** Faire passer le catalogue bloatware de 5 à 141 entrées en important les
identifiants de [Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat), le jugement
restant écrit ici — [ADR-006](../../adr/ADR-006-catalogue-bloatware-importe.md), décisions
D18 à D21.

**Architecture.** L'amont fournit des faits (identifiant, méthode, recommandation), le dépôt
fournit `Category`, `Risk` et `Impact` dans un fichier de jugement versionné, et
`fetch-bloatware` joint les deux pour produire le `BloatwareCatalogFile` que l'éditeur signe.
La transformation est **pure et vit dans Core**, donc testée sur le job Linux ; la commande CLI
n'est qu'une enveloppe, sur le patron de `fetch-loldrivers`.

**Périmètre.** Ce plan couvre les actions **1, 2, 3, 4 et 6** de l'ADR. L'action 5 (rédiger les
141 notes) est de la rédaction et fait son propre lot ; l'action 7 (source secondaire ASUS,
Acer, MSI, Razer) est une extension qui attend que ce pipeline tourne.

## Contraintes globales

- **AOT sans réflexion** : tout type sérialisé passe par `RempartJsonContext`
  ([ADR-001](../../adr/ADR-001-stack-et-perimetre.md), D1). Un `JsonSerializable` oublié ne
  casse qu'à l'exécution du binaire publié.
- **Pas de `System.IO.Path` sur du chemin Windows dans Core** : le rejeu de fixtures tourne sur
  le job Linux, découper `\` et `/` à la main.
- **Une capture ancienne doit se relire** : tout champ ajouté à un type sérialisé est
  optionnel, avec un défaut qui préserve le sens de l'ancien fichier.
- **Langue** : identifiants et commentaires de code en anglais, messages de la CLI en français.
- **`scripts/verify.ps1` avant chaque PR**, et les gardes de `BuildChainParityTests` et
  `CommandSurfaceTests` doivent rester verts.

---

## Structure des fichiers

| Fichier | Responsabilité |
|---|---|
| `src/Rempart.Core/Updates/BloatwareCatalog.cs` | *modifié* — mode d'appariement `PackageName`, provenance de la note |
| `src/Rempart.Core/Updates/Win11DebloatImport.cs` | *créé* — transformation pure amont + jugement → catalogue |
| `data/bloatware-judgement.json` | *créé* — le jugement versionné, indexé par identifiant amont |
| `src/Rempart.Cli/Commands/FetchBloatwareCommand.cs` | *créé* — enveloppe CLI : téléchargement, jointure, écriture |
| `src/Rempart.Cli/CommandTable.cs` | *modifié* — une ligne |
| `src/Rempart.Core/Cli/CommandSurface.cs` | *modifié* — déclaration des options |
| `src/Rempart.Core/Json/RempartJson.cs` | *modifié* — types sérialisables |
| `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs` | *modifié* — appariement et forme des valeurs |
| `tests/Rempart.Tests.Unit/Win11DebloatImportTests.cs` | *créé* — transformation, pièges 1/2/3 |

---

### Tâche 1 : appariement par nom de paquet, et le garde qui interdit la confusion

Le piège 3 de l'ADR : `BloatwareMatch.Pfn` compare par égalité exacte contre un PFN complet
(`Microsoft.XboxGamingOverlay_8wekyb3d8bbwe`), l'amont ne livre qu'un nom de paquet
(`AD2F1837.HPSupportAssistant`). Importer tel quel donne 141 entrées et zéro appariement.

**Fichiers**
- Modifier : `src/Rempart.Core/Updates/BloatwareCatalog.cs`
- Tester : `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs`

**Interfaces**
- Produit : `BloatwareMatch.PackageName`, consommé par la tâche 3.

- [ ] **Étape 1 — écrire les tests qui échouent**

```csharp
[Fact]
public void A_package_name_entry_matches_the_family_name_that_carries_the_publisher_hash()
{
    // Upstream ships bare package names; an installed Appx carries the full PFN. Comparing
    // the two by equality is what would have loaded 141 entries and matched nothing.
    var catalog = BloatwareCatalog.Parse("""
        { "asOfUtc": "2026-07-28T00:00:00Z", "entries": [
          { "id": "BLOAT-HP-SUPPORT", "match": "PackageName", "value": "AD2F1837.HPSupportAssistant",
            "category": "oem", "risk": "Unwanted", "impact": "Assistance HP." } ] }
        """);

    var installed = new InstalledSoftware("HP Support Assistant", "1.0", "HP", SoftwareSource.Appx,
        Provisioned: true, SurvivesFeatureUpdate: true,
        Identifier: "AD2F1837.HPSupportAssistant_v10z8vjag6ke6");

    Assert.Equal("BLOAT-HP-SUPPORT", catalog.Match(installed)?.Id);
}

[Fact]
public void A_package_name_entry_does_not_match_a_longer_name_sharing_its_prefix()
{
    // Equality on the name segment, never a prefix test: "Microsoft.Xbox" must not claim
    // "Microsoft.XboxGamingOverlay".
    var catalog = BloatwareCatalog.Parse("""
        { "asOfUtc": "2026-07-28T00:00:00Z", "entries": [
          { "id": "BLOAT-XBOX", "match": "PackageName", "value": "Microsoft.Xbox",
            "category": "game", "risk": "Unwanted", "impact": "Xbox." } ] }
        """);

    var installed = new InstalledSoftware("Xbox Game Bar", "1.0", "Microsoft", SoftwareSource.Appx,
        Provisioned: true, SurvivesFeatureUpdate: true,
        Identifier: "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe");

    Assert.Null(catalog.Match(installed));
}

[Fact]
public void A_package_name_entry_ignores_software_that_is_not_an_Appx()
{
    var catalog = BloatwareCatalog.Parse("""
        { "asOfUtc": "2026-07-28T00:00:00Z", "entries": [
          { "id": "BLOAT-X", "match": "PackageName", "value": "Some.Package",
            "category": "oem", "risk": "Unwanted", "impact": "X." } ] }
        """);

    var installed = new InstalledSoftware("Some Package", "1.0", "Vendor", SoftwareSource.Uninstall,
        Provisioned: false, SurvivesFeatureUpdate: false, Identifier: "Some.Package");

    Assert.Null(catalog.Match(installed));
}

[Fact]
public void Every_embedded_entry_states_its_identifier_in_the_form_its_match_mode_expects()
{
    // The shape guard for the confusion above: a Pfn value carries the publisher hash, a
    // PackageName value does not. Nothing else relates the two, and getting it wrong is
    // silent -- the catalogue loads, announces its count, and matches nothing.
    foreach (var entry in BloatwareCatalog.Embedded.Entries)
    {
        if (entry.Match == BloatwareMatch.Pfn)
        {
            Assert.True(entry.Value.Contains('_'),
                $"{entry.Id} apparie en Pfn mais « {entry.Value} » n'a pas de condensat "
                + "d'éditeur : aucun paquet installé ne portera cette valeur.");
        }

        if (entry.Match == BloatwareMatch.PackageName)
        {
            Assert.False(entry.Value.Contains('_'),
                $"{entry.Id} apparie en PackageName mais « {entry.Value} » porte un condensat "
                + "d'éditeur : le segment comparé n'en a jamais.");
        }
    }
}
```

- [ ] **Étape 2 — vérifier que ça échoue**

`dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~BloatwareCatalogTests"`
Attendu : erreurs de compilation — `BloatwareMatch.PackageName` et `BloatwareCatalog.Entries`
n'existent pas.

- [ ] **Étape 3 — implémenter**

Dans `BloatwareCatalog.cs`, étendre l'énumération et exposer les entrées :

```csharp
/// <summary>How an entry recognizes an installed piece of software.</summary>
public enum BloatwareMatch { Pfn, Uninstall, Name, Publisher, PackageName }
```

```csharp
/// <summary>The entries, for guards that check their shape rather than their effect.</summary>
public IReadOnlyList<BloatwareEntry> Entries => entries;
```

Et l'arm d'appariement, dans `Matches` :

```csharp
        // The name segment of a Package Family Name, which is "<Name>_<PublisherId>". Split
        // on the LAST underscore: a package name cannot contain one, so first and last agree
        // today, and the last one stays right if that ever changes. Equality, never a prefix
        // test -- "Microsoft.Xbox" must not claim "Microsoft.XboxGamingOverlay".
        BloatwareMatch.PackageName =>
            sw.Source == SoftwareSource.Appx
            && sw.Identifier is { } pfn
            && string.Equals(NameSegmentOf(pfn), entry.Value, StringComparison.OrdinalIgnoreCase),
```

```csharp
    /// <summary>
    /// The name part of a Package Family Name. Returns the whole string when there is no
    /// publisher hash, so a capture that stored a bare name still compares sensibly.
    /// </summary>
    private static string NameSegmentOf(string packageFamilyName)
    {
        var separator = packageFamilyName.LastIndexOf('_');
        return separator < 0 ? packageFamilyName : packageFamilyName[..separator];
    }
```

- [ ] **Étape 4 — vérifier que ça passe**

`dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~BloatwareCatalogTests"`
Attendu : tous verts.

- [ ] **Étape 5 — vérifier par mutation**

Remplacer `string.Equals(...)` par `NameSegmentOf(pfn).StartsWith(entry.Value, ...)` :
`A_package_name_entry_does_not_match_a_longer_name_sharing_its_prefix` doit rougir. Remettre.

- [ ] **Étape 6 — commit**

```bash
git add src/Rempart.Core/Updates/BloatwareCatalog.cs tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs
git commit -m "Match a bloatware entry on the package name, not only on the full family name"
```

---

### Tâche 2 : la provenance de la note d'impact

D20 : une note décrite en amont n'est pas une note vérifiée ici, et le rapport doit pouvoir le
dire. Champ **optionnel avec défaut**, pour qu'un catalogue signé antérieur se relise.

**Fichiers**
- Modifier : `src/Rempart.Core/Updates/BloatwareCatalog.cs`, `src/Rempart.Core/Json/RempartJson.cs`
- Tester : `tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs`

**Interfaces**
- Produit : `ImpactProvenance { Upstream, Verified }` et `BloatwareEntry.ImpactSource`,
  consommés par la tâche 3.

- [ ] **Étape 1 — écrire les tests qui échouent**

```csharp
[Fact]
public void An_entry_without_a_stated_provenance_reads_back_as_described_upstream()
{
    // The conservative default: a catalogue written before this field existed did not
    // verify anything on a machine, and must not come back claiming it did.
    var catalog = BloatwareCatalog.Parse("""
        { "asOfUtc": "2026-07-28T00:00:00Z", "entries": [
          { "id": "BLOAT-A", "match": "PackageName", "value": "Some.Package",
            "category": "oem", "risk": "Unwanted", "impact": "Note." } ] }
        """);

    Assert.Equal(ImpactProvenance.Upstream, catalog.Entries[0].ImpactSource);
}

[Fact]
public void A_verified_provenance_survives_a_serialisation_round_trip()
{
    var file = new BloatwareCatalogFile("2026-07-28T00:00:00Z", "test",
    [
        new BloatwareEntry("BLOAT-A", BloatwareMatch.PackageName, "Some.Package", "oem",
            BloatwareRisk.Unwanted, "Note.", ImpactProvenance.Verified),
    ]);

    var again = BloatwareCatalog.Parse(RempartJson.Serialise(file));

    Assert.Equal(ImpactProvenance.Verified, again.Entries[0].ImpactSource);
}
```

- [ ] **Étape 2 — vérifier que ça échoue**

Attendu : `ImpactProvenance` n'existe pas.

- [ ] **Étape 3 — implémenter**

```csharp
/// <summary>
/// Where an impact note comes from. The default is deliberate: a note nobody has checked
/// against a running machine says so, rather than borrowing the authority of one that has
/// (ADR-006, D20).
/// </summary>
public enum ImpactProvenance { Upstream, Verified }
```

```csharp
public sealed record BloatwareEntry(
    string Id,
    BloatwareMatch Match,
    string Value,
    string Category,
    BloatwareRisk Risk,
    string Impact,
    ImpactProvenance ImpactSource = ImpactProvenance.Upstream);
```

Aucun changement de `RempartJson.cs` n'est attendu — `BloatwareCatalogFile` y est déjà
déclaré et l'énumération suit le type. **Le vérifier** plutôt que le supposer : si la
sérialisation d'une énumération nouvelle échoue au binaire publié, c'est ici que ça se voit.

- [ ] **Étape 4 — vérifier que ça passe**

`dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~BloatwareCatalogTests"`

- [ ] **Étape 5 — commit**

```bash
git add src/Rempart.Core/Updates/BloatwareCatalog.cs tests/Rempart.Tests.Unit/BloatwareCatalogTests.cs
git commit -m "An impact note states whether it was described upstream or verified here"
```

---

### Tâche 3 : la transformation pure, et les trois pièges

**Fichiers**
- Créer : `src/Rempart.Core/Updates/Win11DebloatImport.cs`
- Créer : `tests/Rempart.Tests.Unit/Win11DebloatImportTests.cs`

**Interfaces**
- Consomme : `BloatwareMatch.PackageName` (tâche 1), `ImpactProvenance` (tâche 2).
- Produit : `Win11DebloatImport.Transform(string rawJson, string judgementJson, string asOfUtc)`
  → `BloatwareCatalogFile` ; `Win11DebloatImport.SourceUrl` ; `UnjudgedEntriesException`.

- [ ] **Étape 1 — écrire les tests qui échouent**

```csharp
public sealed class Win11DebloatImportTests
{
    private const string Judgement = """
        { "entries": [
          { "appId": "AD2F1837.HPSupportAssistant", "category": "oem", "risk": "Unwanted",
            "impact": "Assistance et mises à jour HP. Sa suppression prive des correctifs de firmware.",
            "impactSource": "Upstream" },
          { "appId": "Microsoft.Edge", "category": "browser", "risk": "SecurityRelevant",
            "impact": "Navigateur par défaut. Sa suppression retire le seul navigateur du bac à sable.",
            "impactSource": "Upstream" },
          { "appId": "XPFFTQ037JWMHS", "category": "browser", "risk": "SecurityRelevant",
            "impact": "Même navigateur, identifiant Store.", "impactSource": "Upstream" } ] }
        """;

    [Fact]
    public void An_upstream_entry_becomes_a_package_name_match_carrying_the_local_judgement()
    {
        var upstream = """
            { "Version": "1.1", "Apps": [
              { "FriendlyName": "HP Support Assistant", "AppId": "AD2F1837.HPSupportAssistant",
                "Description": "HP OEM software", "SelectedByDefault": true,
                "Recommendation": "optional", "RemovalMethod": "Appx" } ] }
            """;

        var file = Win11DebloatImport.Transform(upstream, Judgement, "2026-07-28T00:00:00Z");

        var entry = Assert.Single(file.Entries);
        Assert.Equal(BloatwareMatch.PackageName, entry.Match);
        Assert.Equal("AD2F1837.HPSupportAssistant", entry.Value);
        Assert.Equal("oem", entry.Category);
        Assert.Equal(BloatwareRisk.Unwanted, entry.Risk);
        Assert.Contains("firmware", entry.Impact);
    }

    [Fact]
    public void The_upstream_recommendation_never_decides_the_risk()
    {
        // Piège 1 : les deux axes sont orthogonaux. « unsafe » dit ce que casse la
        // suppression ; Risk dit pourquoi l'entrée est au catalogue. Le Store est unsafe à
        // retirer et n'est pas security-relevant.
        var upstream = """
            { "Version": "1.1", "Apps": [
              { "FriendlyName": "Microsoft Edge", "AppId": "Microsoft.Edge",
                "Description": "Default browser", "SelectedByDefault": false,
                "Recommendation": "unsafe", "RemovalMethod": "Appx" } ] }
            """;

        var file = Win11DebloatImport.Transform(upstream, Judgement, "2026-07-28T00:00:00Z");

        // SecurityRelevant vient du jugement local, pas du « unsafe » d'amont.
        Assert.Equal(BloatwareRisk.SecurityRelevant, file.Entries[0].Risk);
    }

    [Fact]
    public void An_upstream_entry_carrying_several_identifiers_produces_one_entry_per_namespace()
    {
        // Piège 2 : Microsoft Edge porte un AppId tableau, et les deux valeurs ne sont pas du
        // même espace de noms -- un nom de paquet et un identifiant produit du Store.
        var upstream = """
            { "Version": "1.1", "Apps": [
              { "FriendlyName": "Microsoft Edge", "AppId": ["Microsoft.Edge", "XPFFTQ037JWMHS"],
                "Description": "Default browser", "SelectedByDefault": false,
                "Recommendation": "unsafe", "RemovalMethod": "Appx" } ] }
            """;

        var file = Win11DebloatImport.Transform(upstream, Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(2, file.Entries.Count);
        Assert.Contains(file.Entries, e => e.Value == "Microsoft.Edge");
        Assert.Contains(file.Entries, e => e.Value == "XPFFTQ037JWMHS");
        Assert.All(file.Entries, e => Assert.NotEqual("", e.Id));
    }

    [Fact]
    public void An_entry_nobody_has_judged_fails_the_import_and_is_named()
    {
        // D19 : ni livrée sans note, ni disparue en silence.
        var upstream = """
            { "Version": "1.1", "Apps": [
              { "FriendlyName": "Brand New App", "AppId": "Vendor.BrandNewApp",
                "Description": "Added upstream last week", "SelectedByDefault": true,
                "Recommendation": "safe", "RemovalMethod": "Appx" } ] }
            """;

        var thrown = Assert.Throws<UnjudgedEntriesException>(
            () => Win11DebloatImport.Transform(upstream, Judgement, "2026-07-28T00:00:00Z"));

        Assert.Contains("Vendor.BrandNewApp", thrown.Message);
    }

    [Fact]
    public void The_source_field_credits_the_upstream_list()
    {
        // MIT exige l'attribution, et BloatwareCatalogFile porte déjà le champ.
        var upstream = """
            { "Version": "1.1", "Apps": [
              { "FriendlyName": "HP Support Assistant", "AppId": "AD2F1837.HPSupportAssistant",
                "Description": "HP OEM software", "SelectedByDefault": true,
                "Recommendation": "optional", "RemovalMethod": "Appx" } ] }
            """;

        var file = Win11DebloatImport.Transform(upstream, Judgement, "2026-07-28T00:00:00Z");

        Assert.Contains("Win11Debloat", file.Source);
        Assert.Contains("MIT", file.Source);
    }
}
```

- [ ] **Étape 2 — vérifier que ça échoue**

`dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~Win11DebloatImportTests"`
Attendu : `Win11DebloatImport` n'existe pas.

- [ ] **Étape 3 — implémenter**

Créer `src/Rempart.Core/Updates/Win11DebloatImport.cs`, lu au `JsonDocument` comme
`LolDriversImport` — le schéma d'amont ne nous appartient pas, et un champ qui bouge ailleurs
ne doit rien casser :

```csharp
using System.Text.Json;

namespace Rempart.Core.Updates;

/// <summary>Raised when upstream carries an identifier the repository has not judged.</summary>
public sealed class UnjudgedEntriesException(IReadOnlyList<string> appIds) : Exception(
    $"{appIds.Count} identifiant(s) sans jugement : {string.Join(", ", appIds)}. "
    + "Une entrée sans note d'impact n'entre pas au catalogue (ADR-006, D19) : "
    + "compléter data/bloatware-judgement.json.")
{
    public IReadOnlyList<string> AppIds { get; } = appIds;
}
```

`Transform` fait, dans cet ordre : lire le jugement en dictionnaire indexé par `appId` ;
parcourir `Apps` ; **normaliser `AppId` en liste** (chaîne ou tableau — piège 2) ; pour chaque
identifiant, chercher le jugement ; accumuler les manquants ; lever si la liste n'est pas vide ;
sinon produire une entrée par identifiant.

Deux règles à ne pas relâcher :

- `Recommendation` **n'alimente jamais** `Risk`. Elle peut être reprise dans le texte de la
  note lors de la rédaction, jamais convertie en jugement (piège 1).
- Le mode d'appariement est `PackageName` pour un identifiant sans `_`, et `Pfn` s'il en porte
  un — la règle est la forme de la valeur, pas la méthode de suppression annoncée en amont.

`Id` de l'entrée : `"BLOAT-" + identifiant en majuscules, points et espaces remplacés par des
tirets`, tronqué à 60 — déterministe, donc deux imports du même amont donnent le même fichier.

`Source` : `"Raphire/Win11Debloat (MIT) — <SourceUrl>"`.

- [ ] **Étape 4 — vérifier que ça passe**

`dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~Win11DebloatImportTests"`

- [ ] **Étape 5 — vérifier par mutation**

Faire dériver `Risk` de `Recommendation` : `The_upstream_recommendation_never_decides_the_risk`
doit rougir. Traiter `AppId` comme une chaîne seulement :
`An_upstream_entry_carrying_several_identifiers…` doit rougir. Remettre les deux.

- [ ] **Étape 6 — commit**

```bash
git add src/Rempart.Core/Updates/Win11DebloatImport.cs tests/Rempart.Tests.Unit/Win11DebloatImportTests.cs
git commit -m "Transform the upstream bloatware list into a catalogue, joined with the local judgement"
```

---

### Tâche 4 : le fichier de jugement et la commande `fetch-bloatware`

**Fichiers**
- Créer : `data/bloatware-judgement.json`
- Créer : `src/Rempart.Cli/Commands/FetchBloatwareCommand.cs`
- Modifier : `src/Rempart.Cli/CommandTable.cs`, `src/Rempart.Core/Cli/CommandSurface.cs`

**Interfaces**
- Consomme : `Win11DebloatImport.Transform` (tâche 3).

- [ ] **Étape 1 — écrire le fichier de jugement, amorcé sur les 5 entrées existantes**

Reprendre les 5 entrées de `src/Rempart.Core/data/bloatware-baseline.json` dans le format
`{ "entries": [ { "appId", "category", "risk", "impact", "impactSource" } ] }`, en gardant
leurs notes actuelles et en leur mettant `"impactSource": "Verified"` — elles **ont** été
confrontées à `Get-AppxPackage` sur une machine réelle (M5b).

- [ ] **Étape 2 — la commande, sur le patron de `FetchLoldriversCommand`**

Options : `--out` (défaut `bloatware.json`), `--judgement` (défaut `bloatware-judgement.json`).
L'URL est épinglée **par empreinte de commit** dans `Win11DebloatImport.SourceUrl`, jamais par
branche (D18) :

```
https://raw.githubusercontent.com/Raphire/Win11Debloat/<sha40>/Config/Apps.json
```

Sur `UnjudgedEntriesException`, écrire le message sur `stderr` et rendre **1** : la commande
échoue en nommant ce qui manque, elle n'émet pas un catalogue amputé.

- [ ] **Étape 3 — enregistrer la commande**

Une ligne dans `CommandTable.Dispatch` :

```csharp
        "fetch-bloatware" => FetchBloatwareCommand.Run,
```

Et la déclaration dans `CommandSurface`, à côté de `fetch-loldrivers` :

```csharp
        new("fetch-bloatware",
        [
            new("--out", OptionArity.Value),
            new("--judgement", OptionArity.Value),
        ], Positionals: 0),
```

- [ ] **Étape 4 — vérifier que les treize gardes de la table restent verts**

`dotnet test tests/Rempart.Tests.Unit --filter "FullyQualifiedName~CommandSurfaceTests"`
Ils comparent la table aux classes de commande **qui existent réellement** : une ligne sans
classe, ou l'inverse, rougit.

- [ ] **Étape 5 — éprouver sur le vrai amont**

```powershell
dotnet publish src/Rempart.Cli -c Release
$exe = "src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe"
& $exe fetch-bloatware --judgement data/bloatware-judgement.json --out bloatware.json
```

Attendu à ce stade : **échec nommant les ~136 identifiants non jugés**. C'est le succès de
l'étape, pas son échec — la tâche 5 les remplira.

- [ ] **Étape 6 — commit**

```bash
git add data/bloatware-judgement.json src/Rempart.Cli/Commands/FetchBloatwareCommand.cs src/Rempart.Cli/CommandTable.cs src/Rempart.Core/Cli/CommandSurface.cs
git commit -m "fetch-bloatware: pinned upstream, joined with the local judgement, fails on an unjudged entry"
```

---

### Tâche 5 : reprendre le socle embarqué depuis la même jointure

Action 6 de l'ADR. Le socle et le jeu de données signé doivent sortir de **la même chaîne de
production** — les dupliquer serait refaire DET-RECPROV.

**Fichiers**
- Modifier : `src/Rempart.Core/data/bloatware-baseline.json`
- Vérifier : les 4 fixtures et leurs 12 références

- [ ] **Étape 1 — régénérer le socle depuis la jointure**, une fois les notes écrites
- [ ] **Étape 2 — relire les références de fixtures**

`compromised-win11` porte des constats bloatware ; leur libellé peut bouger si une note change.
`scripts/regenerate-fixtures.ps1` régénère, **mais le diff se lit entrée par entrée** : une
référence qui bouge sans qu'on sache pourquoi est un défaut, pas une mise à jour.

- [ ] **Étape 3 — `scripts/verify.ps1` complet, puis commit**

---

## Auto-relecture du plan

**Couverture de la spec.** Actions 1 (tâche 1), 2 (tâche 4 étape 1), 3 (tâches 3 et 4),
4 (tâche 3), 6 (tâche 5). Actions 5 et 7 explicitement hors périmètre, dit en tête.

**Cohérence des types.** `BloatwareMatch.PackageName` (tâche 1) est consommé en tâche 3 ;
`ImpactProvenance` (tâche 2) l'est aussi ; `UnjudgedEntriesException` (tâche 3) est attrapée en
tâche 4. `BloatwareCatalog.Entries` est ajouté en tâche 1 et utilisé par les tests des tâches 1
et 2.

**Ce que le plan ne dit volontairement pas.** L'empreinte de commit exacte de l'amont : elle se
relève au moment de l'implémentation, et l'écrire ici la périmerait. Le libellé des 141 notes :
c'est le lot suivant.
