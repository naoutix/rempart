# Design — Inventaire logiciel (M5a)

> État : design validé le 2026-07-23. Premier sous-lot de M5 (logiciels & bloatware).
> M5b (catalogue bloatware) escaladera cet inventaire ; M5c (extensions) est indépendant.

## Contexte & décomposition

M5 est un lot, pas une PR. Découpe :
- **M5a — inventaire logiciel** *(ici)* : énumérer ce qui est installé, avec la distinction
  provisionné/utilisateur (D6) et `survives_feature_update` (D7). Constats bénins.
- **M5b — catalogue bloatware** : dataset signé (type `bloatware`, canal ADR-002, comme
  LOLDrivers) croisé avec l'inventaire — un **enrichissement** qui escalade les constats
  `software` correspondants, pas une réécriture.
- **M5c — extensions navigateur** : indépendant.

Le canal de rafraîchissement du catalogue n'est **pas** un point ouvert : ADR-001 le renvoie
à ADR-002 (canal signé). M5a n'a donc aucune décision de canal à prendre.

## Sources (vérifiées sur machine réelle)

| Source | Lecture | Sur cette machine |
|---|---|---|
| **Uninstall** | registre, 3 racines : `HKLM\…\Uninstall`, `HKLM\WOW6432Node\…\Uninstall`, `HKCU\…\Uninstall` | 98 + 112 + 5 |
| **Appx / MSIX** | registre : `HKCU\…\AppModel\Repository\Packages` (installés) croisé avec `HKLM\…\Appx\AppxAllUserStore\Applications` (provisionnés) | 148 installés, 51 provisionnés |
| **App Paths** | registre : `HKLM\…\App Paths` (exe autonomes enregistrés) | 35 |
| **Chocolatey** | système de fichiers : dossiers sous `C:\ProgramData\chocolatey\lib` | absent (dégrade à vide) |

**winget** n'a pas de registre propre : ses paquets apparaissent déjà dans Uninstall/Appx
— pas de source séparée. **Portables** purs (exe déposés au hasard) ne sont pas énumérables
de façon fiable ; App Paths couvre ceux qui s'enregistrent. Ces deux limites sont
documentées, pas contournées par une heuristique qui crierait au loup.

## Modèle

```csharp
public enum SoftwareSource { Uninstall, Appx, AppPath, Chocolatey }

public sealed record InstalledSoftware(
    string Name,
    string? Version,
    string? Publisher,
    SoftwareSource Source,
    bool Provisioned,             // Appx stagé pour tous les utilisateurs (D6)
    bool SurvivesFeatureUpdate);  // revient après une mise à jour de fonctionnalité (D7)

public interface ISoftwareInventoryProvider
{
    IReadOnlyList<InstalledSoftware> Read();
}
```

Sémantique des deux drapeaux :
- **Uninstall / AppPath / Chocolatey** : `Provisioned=false`, `SurvivesFeatureUpdate=true`
  (un logiciel classique n'est pas retiré par une mise à jour de fonctionnalité).
- **Appx utilisateur** : `Provisioned=false`, `SurvivesFeatureUpdate=false` (peut être retiré).
- **Appx provisionné** : `Provisioned=true`, `SurvivesFeatureUpdate=true` — le cas qui
  compte pour le bloatware : retiré par l'utilisateur, il **revient** à la mise à jour
  suivante tant que le provisionnement tient.

## Composants (patron A2, comme le proxy/DNS)

| Fichier | Rôle |
|---|---|
| `Providers/ISoftwareInventoryProvider.cs` | interface + `InstalledSoftware`/`SoftwareSource` |
| `Software/AppxPackageName.cs` | *pur* : `Parse("Nom_Version_Arch__Hash")` → nom, version (testable) |
| `Findings/SoftwareInventoryCollector.cs` | émet un constat `software` **bénin** par entrée |
| `Windows/LiveSoftwareInventoryProvider.cs` | agrège les 4 sources via `IRegistryProvider`/`IFileSystemProvider` |
| snapshot + `ProviderSet` + `ScanEngine` + `Program.cs` + `FixtureReplayTests` | câblage rejouable habituel |

Le collecteur émet un `Finding("software", <source>, <nom>, Benign, [], details)` par entrée
— détails : version, éditeur, source, provisionné, survives_feature_update. Tous bénins en
M5a (aucun catalogue encore) ; le rapport humain les compte sans les détailler (comme les
~60 constats de processus). **M5b escaladera** les entrées listées au catalogue.

Pas de champ `ScanResult` nouveau, pas d'anonymiseur (noms/versions/éditeurs ne sont pas des
identifiants ; aucun chemin de profil conservé). La provenance Appx est lue au registre via
`IRegistryProvider`, donc rejouable — le provider ne fait aucun accès direct.

## Tests

- `AppxPackageNameTests` (unit, pur) : parse un nom complet en nom + version ; un nom
  atypique (GUID, segments manquants) dégrade sans lever.
- `SoftwareInventoryCollectorTests` (unit, `FakeSoftwareInventoryProvider`) : un constat par
  entrée, bénin, avec les bons détails et drapeaux ; provisionné → `survives_feature_update`.
- Round-trip snapshot ; rétrocompat (capture sans section software → inventaire vide).
- `LiveSoftwareInventoryProviderTests` (Windows) : lit la machine sans lever, rend des
  entrées cohérentes (nom non vide), Uninstall non vide.
- Références de rejeu : les synthétiques ne portent pas d'inventaire logiciel (comme le
  réseau) → inchangées.

## Critère de sortie

Sur une machine réelle, `rempart scan` inventorie les logiciels des quatre sources, avec la
distinction provisionné/utilisateur et `survives_feature_update` justes, prêt à être croisé
au catalogue en M5b. Vérifié sur machine réelle (≈400 entrées attendues).
