# ADR-005 : Découpage de la couche CLI et généralisation des fournisseurs

**Statut :** Accepté — **exécuté en entier le 2026-07-27** (étapes 1, 2 et 3). Deux des actions ont été menées autrement que prévu ici, et les deux écarts sont notés à leur place plutôt que corrigés dans le plan.
**Date :** 2026-07-27
**Décide :** l'éditeur du projet
**Dettes visées :** DET-PROGRAM, DET-RECPROV, DET-WINDOWS-TESTS (phase 3 du plan de [DEBT.md](../DEBT.md))

## Contexte

L'audit du 2026-07-26 a mesuré `Program.cs` à **1 881 lignes** — 1 610 depuis PR 1a et 1b, contre ~1 240 à son
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

> **État au 2026-07-27, l'étape 1 livrée.** Le constat ci-dessus est celui qui a motivé
> cet ADR ; il n'est plus vrai, et c'est le but. Le rendu des trois commandes qui écrivent
> sur la console est figé par des références, et les deux surfaces pures du CLI — le
> contrat de sortie et le parsing d'arguments — vivent dans Core avec 44 tests. Ce qui
> reste sans test, c'est le corps des commandes : la lecture de fichiers, l'écriture des
> rapports, l'enchaînement. C'est précisément l'objet de la PR 2.

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
                          + la résolution de chemins, qui reste côté hôte

src/Rempart.Core/Reports/
  ConsoleReport.cs        ScanResult → string, pur, testable
src/Rempart.Core/Cli/
  CommandLine.cs          parsing d'arguments, pur
  ExitCodes.cs            le contrat de sortie, pur
```

**Le rendu va dans Core, pas dans le CLI** — corrigé après coup, le premier jet le plaçait
sous `Rempart.Cli/Rendering/`. `Rempart.Cli` cible `net10.0-windows` : un test golden qui y
vivrait ne tournerait **jamais sur le job Linux**. Dans `Core/Reports/` il rejoint
`HtmlReport` et `MarkdownReport`, et tourne partout où ils tournent.

**Et la même correction s'applique au parsing**, que ce croquis plaçait d'abord sous
`src/Rempart.Cli/Options/`. Le raisonnement est identique et il a été refait deux fois :
tout ce qui doit être testé en CI vit dans Core. Ne restent dans le CLI que les fonctions
qui touchent réellement à l'hôte — `Path.Combine`, `AppContext.BaseDirectory`,
`Environment` — dont la place n'est pas dans une bibliothèque rejouée sur Linux.

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

1. [x] **PR 1a — rendu du scan.** Fait (#78) : `Rempart.Core/Reports/ConsoleReport.cs`,
       `ScanResult → string`, plus un test golden par fixture. Sortie figée avant
       déplacement puis rediffée : identique sur les trois fixtures.
2. [x] **PR 1b — rendu du diff.** Fait (#79) : `ConsoleReport.Diff`, même preuve
       avant/après.
3. [x] **PR 1c — finir le filet.** Fait : trois références golden pour `ConsoleReport.Diff`
       (`restricted-access` → `default-win11`, son miroir, et un auto-diff), plus
       `ConsoleReport.Fleet` extrait de `Index` avec son golden. Sortie de `index` figée
       avant déplacement puis rediffée : identique octet pour octet.

   > **Précondition découverte en livrant PR 1a, absente de la première rédaction de cet
   > ADR.** Le filet doit couvrir `scan`, `diff` **et** `index` avant que la moindre
   > commande ne bouge. À la fin de PR 1a il ne couvrait qu'un chemin sur trois, et
   > déplacer des commandes dans cet état serait exactement ce que la section « Analyse
   > des compromis » interdit. C'est la vraie porte d'entrée de PR 2.

   > **Angle mort assumé du golden, à ne pas croire couvert.** Aucune fixture versionnée
   > ne porte de constat `transitoire` ou `éphémère`, et les trois partagent la même
   > empreinte de catalogue : ni le bloc « mouvements attendus », ni la bannière des
   > catalogues divergents, ni les sections « contrôles apparus/disparus » ne sont
   > atteignables par une paire de fixtures. Ces quatre-là sont couverts par des tests
   > unitaires dans `DiffReportTests` et `ScanDiffTests`, pas par une référence.

4. [x] **PR 1c-bis — contrat de sortie et parsing extraits.** Fait :
       `Rempart.Core/Cli/ExitCodes.cs` (les 5 codes, dont l'aide dérive désormais son
       propre texte — elle omettait le code 4 depuis son introduction) et
       `Rempart.Core/Cli/CommandLine.cs` (les 6 primitives). Aucune commande déplacée.
       La couche CLI passe de 0 à 44 tests, et trois défauts réels sont **figés** plutôt
       que corrigés au passage : `DET-SORTIE-PARTIELLE`, `DET-ARITE-REPORT`,
       `DET-EXPLAIN-POSITIONNEL`.
5. [x] **PR 2 — découpage des commandes.** Fait : 17 classes sous `Commands/`, table
       explicite dans `CommandTable.cs`, `Program.cs` réduit à **29 lignes non vides**
       (1 543 avant, 1 881 à l'ouverture de DET-PROGRAM). `CommandSurface` porte les 47
       paires `commande → option` et remplace les deux listes `valueTaking` tenues à la
       main. Dix gardes, **tous vérifiés par mutation** et non seulement verts.

   > **Ce que la relecture a corrigé, et qui mérite d'être retenu.** Le premier jet
   > comparait la table de dispatch à `CommandSurface` — deux listes écrites de la même
   > main dans le même lot, donc un garde qui ne garde rien. Ce que cette section réclamait
   > était la table contre **les classes réellement présentes sur le disque**, et l'écart
   > n'est pas théorique : l'étape 3 ajoute `diagnose-drivers`, qui ne lit aucune option et
   > serait donc passée entre les mailles de tous les autres gardes. De même, la
   > vérification « toute option lue est déclarée » était **globale** : déplacer une
   > lecture d'une commande vers une autre la laissait verte, alors que c'est précisément
   > ce qui rend `ValueTaking` incomplète. Elle est désormais faite **par commande**.
   >
   > La leçon est celle de `DET-REPLAY-CABLAGE`, une fois de plus : un garde qui compare
   > deux artefacts écrits ensemble ne prouve rien. Il faut le confronter à ce qui existe
   > vraiment — le disque, pas une seconde liste.
6. [x] **PR 3 — fournisseurs.** `diagnose-drivers` et `diagnose-processes` faits, sur le
       modèle `diagnose-wmi`, avec leurs deux étapes contre le binaire AOT. `DET-RECPROV`
       est fermée — **en refusant ce que cette action prescrivait**, voir l'encadré suivant.

   > **La généralisation demandée ici est impossible, et le mesurer valait mieux que
   > l'appliquer.** `RecordingProvider<T>`/`SnapshotProvider<T>` exigerait de résoudre à
   > l'exécution ce qui varie entre deux paires : le *nom de méthode* de l'interface
   > (`Read`, `Enumerate`, `Verify`, `ListFiles`, `Query`) et le *champ* de
   > `MachineSnapshot`. Deux noms résolus à la compilation, donc pas de générique sans
   > réflexion — qu'ADR-001 exclut. Les trois formes candidates ont été écrites (délégués
   > get/set, classe de base abstraite, `static abstract` sur un slot) : toutes ajoutent
   > plus de lignes qu'elles n'en retirent, neuf des treize corps faisant une ligne.
   >
   > **La vraie duplication était ailleurs**, et c'est ce qui a été fait : quatre copies de
   > la liste des fournisseurs — câblage réel, enregistrement, rejeu, et *la copie du rejeu
   > dans le test*. Devenues trois fabriques nommées dans `Snapshots/ProviderSets.cs` et
   > `Rempart.Windows/LiveProviders.cs`. Conséquence directe :
   > `Every_provider_is_wired_into_the_replay` — le garde qui a déjà attrapé trois
   > régressions réelles — inspectait jusque-là **la liste du test** et non celle du
   > produit. Il inspecte désormais celle que la commande exécute.
   >
   > Ce que `StatusChannel` généralise, lui, l'est par `static abstract` sur l'interface :
   > l'appel se résout à la compilation par le paramètre de type, donc sans réflexion.

   > **Le projet de fakes partagé, proposé ici pour `CatalogSignature`, n'a pas été
   > construit — et ne devrait pas l'être.** Cette section l'avait envisagé avant d'avoir
   > ouvert le fichier. En le lisant, le jugement s'est révélé séparable de l'interop :
   > `AuthenticodeVerdict` est descendu dans Core, où il est testé **par le job Linux**,
   > sans nouveau projet ni fakes à maintenir. L'interop qui reste — acquisition de
   > contexte, hachage, `WinVerifyTrust` — est tenue par cinq tests Windows sondés.
   > Extraction prouvée neutre sur 459 fichiers réels de System32, sortie identique.
   >
   > La leçon rejoint celle de la phase 1 sur le registre de dette : une cotation faite en
   > lisant *autour* du code n'est pas une cotation faite en l'ouvrant.
7. [x] Mettre à jour [DEBT.md](../DEBT.md) à la fermeture de chaque dette. Onze fermées le
       2026-07-27 ; les cinq qui restent attendent des machines ou une décision, pas du code.

**Faisable avant M9, pas pendant.** Aucune de ces trois PR ne devrait être ouverte en même
temps qu'un lot fonctionnel : elles touchent le point de passage de toutes les commandes.
