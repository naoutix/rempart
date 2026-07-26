# ADR-005 : Découpage de la couche CLI et généralisation des fournisseurs

**Statut :** Proposé
**Date :** 2026-07-27
**Décide :** l'éditeur du projet
**Dettes visées :** DET-PROGRAM, DET-RECPROV, DET-WINDOWS-TESTS (phase 3 du plan de [DEBT.md](../DEBT.md))

## Contexte

L'audit du 2026-07-26 a mesuré `Program.cs` à **1 881 lignes**, contre ~1 240 à son
inscription au registre : **+52 % en trois lots**. La trajectoire compte plus que la
taille, parce que chaque milestone y ajoute une commande et que M9 — la remédiation — y
ajoutera des fournisseurs en écriture, des confirmations individuelles et un journal de
rollback.

Le fichier mélange trois responsabilités :

| Responsabilité | Volume approximatif | Exemples |
|---|--:|---|
| Dispatch et 15 commandes | ~1 400 l. | `Scan`, `Diff`, `Index`, `Seal`, `Update`, `Explain`… |
| Rendu console | ~420 l. | `WriteHumanReadable`, `WritePosture`, `WriteFindings`, `WriteDiff`, `DescribeStatus` |
| Arguments et chemins | ~60 l. | `OptionValue`, `RulesDirectory`, `StoreDirectory`, `BaselinePath` |

**Le fait qui décide de tout le reste : cette couche n'a aucun test.** Les 534 tests
unitaires et 56 tests Windows n'en touchent pas une ligne. La CI se contente de vérifier
des codes de sortie (`rempart version`, `rempart scan`, `diagnose-wmi`, `diagnose-tasks`).
Un découpage de 1 400 lignes sans filet, dans un dépôt qui a déjà produit trois fois la
même régression silencieuse (D2, D2b, `componentStore`), est le scénario le plus risqué
que ce projet puisse s'offrir.

### Correction d'une affirmation antérieure

Il a été avancé que `DET-RECPROV` « réduirait la surface de `DET-PROGRAM` », et donc
devrait passer en premier. **C'est faux.** `RecordingProviders.cs` vit dans Core ;
`Program.cs` n'y touche que par la construction de `ProviderSet`, une cinquantaine de
lignes sur 1 881. Les deux dettes sont largement indépendantes, et l'ordre doit se décider
sur le risque, pas sur une dépendance qui n'existe pas.

### Contraintes non négociables

- **Native AOT, sans réflexion** (ADR-001). Tout registre de commandes est une table
  explicite ; aucune découverte par attribut ou par scan d'assembly.
- **Déterminisme du rejeu.** Rien de ce découpage ne doit toucher au chemin
  capture → instantané → rejeu, protégé depuis peu par le garde de `DET-REPLAY-CABLAGE`.
- **Le binaire reste unique**, sans dépendance ajoutée : la surface d'approvisionnement
  d'un outil de sécurité est un argument du projet (une seule dépendance de production).

## Décision

Découper en trois temps, dans cet ordre, **une PR par étape** :

1. **Extraire un rendu console pur**, `ScanResult → texte`, testable sans console.
2. **Découper les commandes** derrière une table explicite, une classe par commande.
3. **Généraliser les paires `Recording`/`Snapshot`** et outiller les tests Windows.

L'étape 1 est l'étape habilitante : elle crée le filet qui rend l'étape 2 vérifiable.

### Pourquoi le rendu d'abord — le projet l'a déjà fait

M6 a rendu les rapports HTML, Markdown et JSON **purs** : `ScanResult → texte`, donc
testables sans Windows ni système de fichiers. C'est ce qui a permis d'attraper les jauges
de score plafonnées à 70 % et l'échappement HTML, par des tests. Le rendu **console** n'a
jamais reçu ce traitement : il écrit directement sur `Console`, donc rien ne l'observe.

Appliquer à la sortie console le patron déjà éprouvé sur les rapports n'est pas une idée
neuve à valider — c'est l'extension d'une décision qui a fonctionné.

## Options considérées

### Option A — Ne rien faire, découper au moment de M9

| Dimension | Évaluation |
|---|---|
| Complexité | Nulle maintenant |
| Coût | Reporté, et croissant : +52 % en trois lots |
| Risque | Élevé — M9 écrit sur la machine |
| Réversibilité | Bonne |

**Pour :** aucun effort immédiat ; le fichier fonctionne et est couvert par des tests
d'intégration de fait (la CI lance un vrai scan).
**Contre :** M9 est le lot où une erreur modifie une machine réelle. Y arriver avec un
dispatch de 2 000+ lignes sans test, c'est choisir d'ajouter l'écriture au seul endroit
non couvert du projet.

### Option B — Une classe par commande, plus une couche de rendu pur *(retenue)*

| Dimension | Évaluation |
|---|---|
| Complexité | Moyenne, mécanique |
| Coût | 3 PR, échelonnables entre deux lots |
| Risque | Faible si le rendu passe en premier |
| Familiarité | Le patron est déjà celui des rapports (M6) |

```
src/Rempart.Cli/
  Program.cs              dispatch seul, ~80 l. : table nom → commande
  Commands/ScanCommand.cs …  une par commande, ~60-250 l. chacune
  Rendering/ConsoleReport.cs  ScanResult → string, pur, testable
  Options/CommandLine.cs      parsing et résolution de chemins
```

**Pour :** chaque commande devient lisible seule ; le rendu devient testable, donc les
régressions d'affichage cessent d'être invisibles ; M9 ajoute un fichier au lieu d'une
section.
**Contre :** ~15 fichiers nouveaux ; le dispatch reste une table à tenir à la main —
c'est le prix du sans-réflexion, et il est explicite.

### Option C — Un registre de commandes découvert automatiquement

| Dimension | Évaluation |
|---|---|
| Complexité | Faible à l'écriture, élevée à déboguer |
| Coût | Faible |
| Risque | **Rédhibitoire** |

**Contre :** exige de la réflexion ou un générateur de source. La réflexion est exclue par
ADR-001 et casserait l'AOT ; le générateur ajoute une dépendance d'outillage à un projet
qui en revendique une seule. Écartée sans hésitation.

### Option D — Une bibliothèque d'analyse d'arguments (`System.CommandLine`)

| Dimension | Évaluation |
|---|---|
| Complexité | Faible |
| Coût | Une dépendance de plus |
| Risque | Moyen — compatibilité AOT à vérifier |

**Contre :** ajouter une dépendance de production à un outil de sécurité dont l'argument
est d'en avoir **une seule** demande une justification plus forte que la commodité. Le
parsing actuel tient en 60 lignes et n'a jamais posé problème. Écartée, réexaminable si le
nombre d'options explose.

## Analyse des compromis

Le vrai arbitrage n'est pas « découper ou non » mais **dans quel ordre**, et il se joue
sur une question : qu'est-ce qui échoue bruyamment si on se trompe ?

- Déplacer une commande **sans** rendu testable : la sortie change, personne ne le voit.
  La CI vérifie un code de sortie, pas un texte.
- Extraire le rendu **d'abord** : chaque commande déplacée ensuite est comparée à une
  sortie de référence, exactement comme les fixtures comparent un rejeu.

C'est le même raisonnement que celui qui a fermé `DET-REPLAY-CABLAGE` : on n'ajoute pas de
la surface avant d'avoir posé le garde qui la surveille.

Second arbitrage, sur `DET-WINDOWS-TESTS` : les tests Windows n'ont **pas** de faux
registre — `FakeRegistryProvider` est `internal` à `Rempart.Tests.Unit`. Deux voies :
extraire les fakes dans un projet partagé, ou étendre le patron `diagnose-*` déjà utilisé
pour WMI et le planificateur. Le patron `diagnose-*` a l'avantage d'exercer **le binaire
AOT publié**, là où une erreur d'interop se manifeste réellement — c'est lui qui a attrapé
le WMI mort après publication. Retenu pour les fournisseurs d'interop ; le projet partagé
de fakes reste préférable pour `CatalogSignature`, qui est de la logique et non de
l'interop.

## Conséquences

**Ce qui devient plus facile**
- Ajouter une commande en M9 : un fichier, pas une section dans un fichier de 2 000 lignes.
- Voir une régression d'affichage : le rendu console rejoint les rapports du côté testé.
- Relire une commande : elle tient à l'écran.

**Ce qui devient plus difficile**
- Suivre un appel de bout en bout traverse maintenant deux fichiers de plus.
- La table de dispatch doit être tenue à jour à la main — un oubli y est silencieux.
  **À couvrir par un test** comparant la table aux classes de commandes présentes, sur le
  modèle exact du garde de `DET-REPLAY-CABLAGE`, qui existe parce que ce type d'oubli
  s'est produit trois fois.

**Ce qu'il faudra revisiter**
- Si le nombre d'options par commande grossit, l'option D redevient discutable.
- Si M9 introduit des commandes interactives, la couche de rendu devra distinguer
  « écrire » de « demander », ce que ce découpage ne traite pas.

## Actions

1. [ ] **PR 1 — rendu console pur.** Extraire `Write*`/`Describe*` vers
       `Rendering/ConsoleReport.cs`, signature `ScanResult → string`. Figer la sortie
       actuelle comme référence **avant** tout déplacement, pour que la PR prouve qu'elle
       ne change rien.
2. [ ] **PR 2 — découpage des commandes.** Une classe par commande, table explicite dans
       `Program.cs`, plus le test qui compare la table aux commandes existantes.
3. [ ] **PR 3 — fournisseurs.** `RecordingProvider<T>`/`SnapshotProvider<T>` génériques
       (`DET-RECPROV`), puis `diagnose-drivers`/`diagnose-processes` sur le modèle
       `diagnose-wmi`, et un projet de fakes partagé pour `CatalogSignature`
       (`DET-WINDOWS-TESTS`).
4. [ ] Mettre à jour [DEBT.md](../DEBT.md) à la fermeture de chaque dette.

**Faisable avant M9, pas pendant.** Aucune de ces trois PR ne devrait être ouverte en même
temps qu'un lot fonctionnel : elles touchent le point de passage de toutes les commandes.
