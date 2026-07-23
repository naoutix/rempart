# Design — Catalogue bloatware (M5b)

> État : design validé le 2026-07-23. Deuxième sous-lot de M5 (logiciels & bloatware).
> Escalade l'inventaire M5a ; M5c (extensions navigateur) reste indépendant.

## Contexte

M5a énumère les logiciels installés en constats **bénins** (un par entrée). M5b ajoute un
**catalogue bloatware** qui reconnaît les entrées indésirables et les **escalade**, sans
réécrire le collecteur — un enrichissement, exactement comme la liste LOLDrivers escalade
un pilote chargé.

Le précédent est direct : `DriverBlocklist` (donnée indexée, socle vide, `Match`) +
`LoadedDriversCollector` (sévérité de base, puis escalade si la liste reconnaît
l'empreinte). M5b transpose le même patron du **hash de fichier** à l'**identité
logicielle** — un logiciel n'a pas de hash stable, d'où un appariement différent.

## Décisions tranchées (brainstorming)

1. **Appariement hybride** : identifiant exact quand il existe (Package Family Name Appx,
   clé Uninstall / product code), motif de nom/éditeur curaté en repli.
2. **Sévérité par risque** : l'entrée porte un risque (`Unwanted`/`SecurityRelevant`) que
   le **code** mappe en gravité (`Notable`/`Suspicious`). Le jugement reste dans le code,
   la donnée ne porte qu'un risque — pas une gravité en dur.
3. **Socle embarqué + canal signé** : le binaire embarque un petit socle d'identifiants
   Appx stables et vérifiés ; le catalogue signé fusionne par-dessus. Un PFN est un
   identifiant documenté et vérifiable, pas une empreinte devinée qui périme — D12 vise la
   donnée périmée/inventée, pas les identifiants stables.

## Le catalogue (Core, pur, testable sans Windows)

```csharp
public enum BloatwareRisk { Unwanted, SecurityRelevant }   // → Notable / Suspicious
public enum BloatwareMatch { Pfn, Uninstall, Name, Publisher }

/// <summary>Une entrée du catalogue : comment reconnaître un logiciel, et ce qu'il coûte.</summary>
public sealed record BloatwareEntry(
    string Id,                 // stable, ex. "BLOAT-CANDYCRUSH"
    BloatwareMatch Match,
    string Value,              // PFN / clé exacte, ou sous-chaîne pour Name/Publisher
    string Category,           // oem-preinstall · game · trialware · adware-telemetry · security-relevant
    BloatwareRisk Risk,
    string Impact);            // OBLIGATOIRE — ce que c'est, pourquoi signalé, coût du retrait

public sealed record BloatwareCatalogFile(string AsOfUtc, string? Source, List<BloatwareEntry> Entries);
```

`BloatwareCatalog` (le catalogue interrogeable) :

- `Empty` — plancher honnête, ne matche rien.
- `Embedded` + `EmbeddedAsOfUtc` — le socle compilé dans le binaire (même mécanisme que le
  socle de règles `RuleCatalog`).
- `Match(InstalledSoftware) → BloatwareEntry?` :
  - `Pfn` / `Uninstall` : égalité exacte sur `InstalledSoftware.Identifier`, restreinte à la
    bonne source (PFN ↔ source Appx, clé ↔ source Uninstall).
  - `Name` / `Publisher` : sous-chaîne insensible à la casse sur `Name` / `Publisher`.
  - **Plusieurs correspondances → le risque le plus élevé gagne**, départage stable par
    `Id` ordinal (sortie de rapport déterministe).
- `Merge(base, incoming)` — l'entrée signée surcharge le socle **par `Id`** ; aucune entrée
  du socle ne disparaît (D12). Calque de `UpdateStore.Merge` pour les règles.
- `Parse(json)` — **lève** si une entrée a un `Id` ou un `Impact` vide (la note d'impact est
  obligatoire, ROADMAP). Un fichier illisible n'est pas un catalogue vide : lever plutôt que
  charger un catalogue de sécurité tronqué. Le store traduit en refus visible, comme
  `DriverBlocklist.Parse`.

## Mapping risque → gravité (dans le code)

| Risque de l'entrée | Gravité du constat | Cas |
|---|---|---|
| `Unwanted` | `Notable` | Jeux OEM, essais, applications consommateur préinstallées |
| `SecurityRelevant` | `Suspicious` | Updater OEM vulnérable connu, adware/télémétrie forcé |

Le palier `Suspicious` est **étroit et justifié** : un bloatware est d'abord indésirable, pas
malveillant. Sur-alarmer disqualifie l'outil (principe du projet).

## Extension M5a (nécessaire pour le volet exact)

`InstalledSoftware` gagne un champ :

```csharp
public sealed record InstalledSoftware(
    string Name, string? Version, string? Publisher, SoftwareSource Source,
    bool Provisioned, bool SurvivesFeatureUpdate,
    string? Identifier);       // NOUVEAU : PFN (Appx) · nom de clé Uninstall / product code · null ailleurs
```

- `LiveSoftwareInventoryProvider` renseigne `Identifier` par source (le PFN est déjà lu au
  registre `AppModel\Repository\Packages` ; la clé Uninstall est le nom de sous-clé).
- Snapshot / recording : round-trip du nouveau champ.
- Rétrocompat : une capture M5a sans `Identifier` se relit avec `Identifier = null` — l'exact
  ne matche alors pas, le motif nom/éditeur reste disponible.
- L'appariement par motif utilise `Name` / `Publisher`, déjà présents — aucune dépendance
  supplémentaire côté provider.

## Collecteur (escalade — calque de `LoadedDriversCollector`)

`SoftwareInventoryCollector(BloatwareCatalog catalog)` :

```csharp
var finding = /* constat bénin comme en M5a */;
if (catalog.Match(software) is { } hit)
{
    severity = hit.Risk == BloatwareRisk.SecurityRelevant
        ? FindingSeverity.Suspicious : FindingSeverity.Notable;
    reasons.Insert(0, hit.Impact);
    details["bloatware"] = hit.Category;
    details["catalogue"] = hit.Id;
}
```

Ne peut qu'aggraver — un logiciel non reconnu reste bénin. Le rapport humain compte les
bénins et détaille les escaladés (comme les autres constats).

## Canal signé & socle

- `DatasetKind.Bloatware = "bloatware"`. `Infer()` classe le JSON en `Drivers` par défaut :
  le type bloatware est donc **imposé à la signature** (`rempart sign --kind bloatware`, flag
  déjà supporté). Documenté ; pas de nouvelle option CLI.
- `UpdateStore.Resolve` : `CatalogResolution` porte un `BloatwareCatalog` ; `case
  DatasetKind.Bloatware → BloatwareCatalog.Parse(text)` ; fusion socle embarqué ⊕ signé ;
  note d'en-tête (nombre d'entrées surveillées, comme le compte de pilotes).
- **Pas de commande `fetch-bloatware`** : aucune source amont canonique (contrairement à
  loldrivers.io). Le catalogue signé est curaté à la main.
- `ScanEngine` passe le catalogue résolu au collecteur `software`.
- `RempartJson` : ajouter `BloatwareCatalogFile` / `BloatwareEntry` au contexte source-gen.
- `Program.cs` : l'en-tête du scan mentionne la fraîcheur du catalogue (comme le compte de
  pilotes surveillés).

## Erreurs & garanties (réutilise l'existant)

- Entrée invalide (Impact/Id vide, JSON illisible) → `Parse` lève → store **refuse
  visiblement**, socle conservé (D13/D17).
- Dataset altéré après `--apply` → rejeté à la re-vérification de chaque scan.
- Hors-ligne / pas de magasin → socle embarqué seul, pleinement utilisable (D12).
- **Pas d'anonymiseur** : noms, versions, éditeurs et PFN ne sont pas des identifiants de
  machine (décision M5a inchangée) ; la catégorie et l'impact ajoutés ne le sont pas non plus.

## Composants (patron A2)

| Fichier | Rôle |
|---|---|
| `Updates/BloatwareCatalog.cs` | *pur* : `BloatwareEntry`, enums, `BloatwareCatalogFile`, `BloatwareCatalog` (Empty/Embedded/Match/Merge/Parse) |
| socle embarqué `bloatware-baseline.json` | ressource compilée : identifiants Appx stables et **vérifiés** |
| `Providers/ISoftwareInventoryProvider.cs` | `InstalledSoftware` + champ `Identifier` |
| `Windows/LiveSoftwareInventoryProvider.cs` | renseigne `Identifier` par source |
| `Findings/SoftwareInventoryCollector.cs` | injection du catalogue + escalade |
| `Updates/Manifest.cs` | `DatasetKind.Bloatware` |
| `Updates/UpdateStore.cs` | routage `case Bloatware`, fusion, note ; `CatalogResolution` + catalogue |
| `Engine/ScanEngine.cs` + `ProviderSet` | câblage du catalogue au collecteur |
| snapshots (`RecordingProviders`, `MachineSnapshot`) | round-trip d'`Identifier` |
| `Json/RempartJson.cs` | types du contexte source-gen |
| `Program.cs` | note d'en-tête |

## Tests

- **Matcher pur** (unit) : hit PFN exact, hit Uninstall, sous-chaîne Name/Publisher, non-match,
  risque-le-plus-élevé-gagne, `Parse` lève si Impact/Id vide, catalogue vide ne matche rien,
  restriction PFN↔Appx / clé↔Uninstall.
- **Collecteur** (unit, `FakeSoftwareInventoryProvider` + catalogue) : entrée reconnue →
  sévérité + raison (l'impact) + détails ; non reconnue → bénin ; mapping risque→gravité.
- **Fusion** (unit) : entrée signée surcharge le socle par `Id` ; socle conservé sinon.
- **Store / round-trip** : dataset bloatware appliqué → catalogue résolu ; altéré → refusé ;
  round-trip du champ `Identifier` dans un snapshot.
- **Socle embarqué** (unit) : parse, tout `Id`/`Impact` non vide, risque valide.
- **Windows** : `LiveSoftwareInventoryProvider` renseigne `Identifier` (PFN non vide pour Appx).
- Références de rejeu synthétiques : inchangées (pas de section software, comme le réseau).

## Critère de sortie

Sur une machine OEM réelle, `rempart scan` signale le bloatware du socle en Notable/Suspicious
avec sa note d'impact, et un catalogue d'enrichissement signé appliqué via `update` escalade
des entrées supplémentaires. **Vérifié sur machine réelle, pas sur VM** (exigence ROADMAP).

Le **contenu exact du socle** (les PFN) est vérifié sur machine réelle pendant
l'implémentation — aucun identifiant inscrit « de mémoire ». Le mécanisme est livrable ; la
matière du socle se valide sur le réel.
