# Registre de dette technique

Ce que le projet sait devoir améliorer, tenu à jour au fil des audits. La dette du code
vit surtout en commentaires ; ce registre la rassemble pour qu'elle soit lisible d'un coup
et priorisable, plutôt que dispersée. Dernier audit : **2026-07-26, post-v1.0.0-rc.1** —
audit complet, toutes catégories, mesures refaites plutôt que reprises.

Priorité indicative : `(Impact + Risque) × (6 − Effort)`.

## Mesures de l'audit du 2026-07-26

| | |
|---|---|
| Code de production | 14 941 lignes — Core 10 289 (100 fichiers), Windows 2 703 (28), CLI 1 949 (7) |
| Tests | 7 789 lignes — 513 unitaires, 56 Windows |
| Marqueurs `TODO`/`FIXME`/`HACK` | **aucun** dans tout le code |
| Dépendances de production | **une seule** — YamlDotNet 18.1.0 |
| `catch` vides | 3, tous `JsonException` dans les parseurs d'extensions (voir DET-EXT-MUET) |

**Ce qui est sain, et mérite d'être dit.** Aucun marqueur de dette laissé dans le code :
elle est écrite en prose là où elle se trouve, et rassemblée ici. Une seule dépendance de
production sur un outil de sécurité, ce qui réduit d'autant la surface d'attaque de chaîne
d'approvisionnement. Toutes les actions GitHub épinglées par SHA. 569 tests, dont un rejeu
de fixtures qui exerce le chemin complet du scan sans machine Windows.

## Corrigé

| Réf | Dette | Corrigé dans |
|---|---|---|
| D1 | `AutorunsCollector` résolvait les dossiers de démarrage par `Environment`/`Path` — cassait le déterminisme du rejeu Linux | Phase 1 dette (#45) — lecture via registre `Shell Folders` |
| D2 | Le rejeu bout-en-bout ne câblait que 8 providers snapshot ; les collecteurs réseau tournaient à vide | Phase 1 dette (#45) — 14 providers câblés, round-trip JSON exercé |
| D3 | `ProviderSet` (14 params) construit positionnellement en 3 sites — inversion silencieuse possible | Phase 1 dette (#45) — arguments nommés |
| D2b | Récidive de D2 : M5c a ajouté `IBrowserExtensionProvider` sans le câbler au rejeu de fixtures | M6 — fournisseur câblé |
| DET-DISM | Les libellés attendus par `ComponentStoreParser` venaient de la documentation, pas d'une exécution élevée réelle | 2026-07-26 — exécution en console admin : `Found`, les 7 libellés correspondent, aucune correction. Deux subtilités validées sur du réel : découpage au premier deux-points (la date porte les siens) et `0 bytes` à double espace |
| DET-APPX-FAUXPOS | Le collecteur Appx remontait les entrées-ressource orphelines (`..._split.scale-*`) comme des logiciels installés | Post-M7 (#67) — `AppxPackageName.IsResourcePackage`, jugement pur en Core. Mesuré : BingWeather 1→0, Clipchamp 2→0, GamingApp 2→1 |
| DET-WMI-FLAKY | `LiveWmiProviderTests` faisait échouer le build quand le runner partagé répondait zéro ligne — 5 fois en une journée, dont une sur une PR sans C# | 2026-07-26 (#70) — chaque test sonde d'abord si WMI répond ; les assertions sont inchangées quand il répond |

## Ouvert

Classé par priorité décroissante.

| Réf | Dette | Catégorie | I | R | E | Prio | Note |
|---|---|---|:-:|:-:|:-:|:-:|---|
| DET-DEPENDABOT | `dependabot.yml` ne surveille que `github-actions`. **Aucune surveillance de `nuget`** : ni YamlDotNet, seule dépendance de production, ni les paquets de test ne reçoivent d'alerte de mise à jour ou de vulnérabilité | Dépendance | 2 | 4 | 1 | **30** | Le fichier justifie lui-même sa raison d'être par « un pin figé rate les correctifs amont, sécurité compris » — le raisonnement s'applique mot pour mot à NuGet, qui n'est pas couvert. Un bloc de 5 lignes ferme le sujet |
| DET-WMI-VIDE | `LiveWmiProvider.cs:134` : une énumération **réussie rendant zéro ligne** devient `NotFound`, indistinguable d'une classe absente. Un WMI dégradé peut donc produire un verdict là où il faudrait « non vérifiable » | Code | 3 | 4 | 3 | **21** | Le principe est déjà écrit dans `IWmiProvider` : « un refus doit devenir non vérifiable, jamais une non-conformité ». Zéro ligne reste une réponse légitime pour certaines classes, donc pas de mappage global : distinguer à la source la classe inconnue de l'énumération vide |
| DET-SECURITY | Dépôt **public** d'un outil de sécurité, sans `SECURITY.md` ni voie de divulgation. Qui trouve une faille n'a pas d'endroit où l'adresser hors d'une issue publique | Documentation | 1 | 3 | 1 | **20** | Un fichier, une adresse, un délai de réponse annoncé |
| DET-EXT-MUET | Trois `catch (JsonException) { }` dans `ChromiumExtensions` et `FirefoxExtensions` : un manifeste illisible fait **disparaître l'extension de l'inventaire**, sans un mot | Code | 2 | 3 | 2 | **20** | Contredit frontalement la règle du projet — « un accès refusé est dit et non tu ». Une extension qu'on n'a pas su lire doit ressortir comme non lue, pas comme absente |
| DET-IPV6 | Ports en écoute IPv6 non collectés (`AF_INET` seul) — recoupe l'item M4 « IPv6 » | Code | 3 | 3 | 3 | 18 | Ajouter `AF_INET6` + formatage d'adresse ; le test Windows suppose IPv4 (`Split('.')`) et devra suivre |
| DET-REPLAY-CABLAGE | Rien ne vérifie que tout nouveau fournisseur est câblé au rejeu de fixtures — D2 puis D2b sont la même erreur deux fois | Test | 3 | 3 | 3 | 18 | Un test de réflexion comparant les propriétés de `ProviderSet` aux fournisseurs câblés fermerait la récidive. **Deux occurrences historiques : la troisième est une question de temps** |
| DET-SYSTEM32 | `C:\Windows\System32\` résolu en dur dans 3 collecteurs (COM, LSA, Logon) | Code | 2 | 2 | 2 | 16 | Helper `PathResolver.ResolveSystem32` |
| DET-TACHE-EXPIREE | La branche « tâche supprimée après expiration » n'a aucun cas positif sur machine réelle : 196 tâches sur le poste de test, aucune concernée. Couverte par fixture fabriquée seulement | Test | 2 | 2 | 2 | 16 | Se ferme sur la première capture d'une machine qui en porte une ; le zéro a été vérifié, pas supposé |
| DET-WINDEFAULT | ~60 `windowsDefault` validés sur **une seule machine** — la « dette n°4 » d'ADR-002 | Code | 2 | 3 | 3 | 15 | Se corrige à mesure des captures réelles |
| DET-CI-SHA | Toutes les actions GitHub sont épinglées par SHA (vérifié). Ce qui flotte encore : le tag Docker d'actionlint (`:1.7.12`) et la bande `dotnet-version: '10.0.x'` | Infrastructure | 1 | 2 | 1 | 15 | Épingler actionlint par digest ; un `global.json` fermerait le SDK en même temps que DET-SDK |
| DET-WINDOWS-TESTS | La couche P/Invoke — 2 703 lignes, celle dont l'échec est « une valeur plausible et fausse » — n'a que 826 lignes de tests, tous contre la machine réelle, sans faux registre. **Sept fournisseurs n'ont ni test dédié ni commande `diagnose`** : `CatalogSignature`, `LiveDriverProvider`, `LiveProcessProvider`, `LiveSecurityPolicyProvider`, `LiveDnsProvider`, `LiveHostsFileProvider`, `LiveFileSystemProvider` | Test | 3 | 4 | 4 | 14 | WMI et le planificateur sont couverts par `diagnose-wmi`/`diagnose-tasks` contre le binaire AOT — le modèle existe, il n'est pas étendu. `CatalogSignature` est le plus gênant : la vérification de signature par catalogue décide qu'un binaire est sain |
| DET-SDK | Pas de `global.json` (SDK non verrouillé) ni de Central Package Management | Infrastructure | 1 | 2 | 2 | 12 | Versions de test dupliquées dans 2 `.csproj` |
| DET-SCRIPTS | `verify.ps1` réimplémente la CI (actionlint, tests, publish, diagnose) sans être appelé par elle | Infrastructure | 2 | 2 | 3 | 12 | Divergence silencieuse possible ; confirmé structurellement à l'audit |
| DET-DIRTY | Aucune fixture « sale » **versionnée** : 4 fixtures existent (réelle anonymisée, défaut, durcie, accès restreint), aucune compromise. Les chemins de menace ne sont testés que par fakes | Test | 3 | 3 | 4 | 12 | Une capture réelle compromise, anonymisée, serait le banc de test le plus honnête |
| DET-TLS | Règles SCHANNEL/TLS non livrées : les défauts varient selon la build | Code | 3 | 3 | 4 | 12 | Demande une vérification sur plusieurs machines (ROADMAP M2b) |
| DET-RECPROV | 13 paires `Recording`/`Snapshot` quasi-identiques — `RecordingProviders.cs` fait 327 lignes | Code | 2 | 2 | 3 | 12 | Généraliser par `RecordingProvider<T>`/`SnapshotProvider<T>`. Lié à DET-REPLAY-CABLAGE : moins de répétition, moins d'occasions d'oublier un câblage |
| DET-PROGRAM | `Program.cs` monolithe. **Mesuré à 1 881 lignes le 2026-07-26, contre ~1 240 à l'inscription** : +52 % en trois lots, dispatch + 13 commandes + rendu + parsing d'args | Architecture | 3 | 2 | 4 | 10 | La trajectoire compte autant que la taille : chaque lot y ajoute une commande. Découper en commandes + couche de rendu **avant** M9, qui ajoutera l'écriture et ses confirmations |
| DET-APPX-VERSIONS | Un paquet Appx dont plusieurs versions restent enregistrées est remonté autant de fois (`ECApp` et `LockApp` 3 fois ; 113 PFN distincts pour 148 entrées) | Code | 1 | 1 | 2 | 8 | Pas un faux positif, une redondance. **Ne pas corriger par unicité du PFN** : les variantes d'architecture sont des paquets distincts et légitimes |
| DET-PLAGE-DYNAMIQUE | Le premier port de la plage dynamique (49152) est une constante, non lue de la machine | Code | 1 | 1 | 3 | 6 | Dégradation gracieuse, jamais une affirmation fausse |

## Plan de remédiation par phases

Pensé pour avancer **à côté du développement de fonctionnalités**, pas à sa place.

### Phase 1 — quatre correctifs courts, aucun risque de régression

`DET-DEPENDABOT` · `DET-SECURITY` · `DET-EXT-MUET` · `DET-SYSTEM32`

Priorités 30, 20, 20 et 16 pour un effort de 1 à 2 chacun. Les deux premiers sont des
fichiers de configuration et de la prose ; les deux suivants sont des changements locaux
et testables. Justification : `DET-DEPENDABOT` laisse aujourd'hui la seule dépendance de
production sans surveillance de vulnérabilité, sur un outil dont l'argument est la
sécurité — c'est le pire rapport risque/effort du registre.

### Phase 2 — ce qui touche la justesse de l'audit

`DET-WMI-VIDE` · `DET-REPLAY-CABLAGE` · `DET-APPX-VERSIONS`

Ces trois-là décident de ce que le rapport **dit**. `DET-WMI-VIDE` peut transformer une
machine non auditée en machine jugée ; `DET-REPLAY-CABLAGE` a déjà laissé passer deux fois
un collecteur tournant à vide derrière une référence figée à « rien trouvé ». À traiter
avant d'ajouter des collecteurs, chacun en étant une occasion de plus.

### Phase 3 — structure, avant M9

`DET-PROGRAM` · `DET-RECPROV` · `DET-WINDOWS-TESTS`

M9 (remédiation) ajoutera des providers en écriture, des confirmations individuelles et un
journal de rollback. Greffer ça sur un `Program.cs` de 1 881 lignes qui croît de moitié par
milestone, et sur une couche P/Invoke faiblement testée, coûtera plus cher que de préparer
le terrain. `DET-RECPROV` et `DET-REPLAY-CABLAGE` se répondent : la duplication est ce qui
rend l'oubli possible.

### Phase 4 — ce qui attend des machines, pas du code

`DET-TLS` · `DET-IPV6` (partie règles) · `DET-WINDEFAULT` · `DET-DIRTY` · `DET-TACHE-EXPIREE`

Aucun de ces points ne se ferme au clavier : ils demandent d'observer plusieurs builds de
Windows, une machine compromise, une machine portant une tâche expirante. Ils avancent au
rythme des captures réelles. La partie **code** de `DET-IPV6` (`AF_INET6`) fait exception
et peut rejoindre la phase 2.

## Limitations connues, assumées

Documentées dans le code, conservatrices par conception — à ne « corriger » que si un besoin
réel émerge :

- **Pare-feu** : mots-clés de port dynamiques (`RPC`) non résolus, règles d'app empaquetées
  (`PFN`) non rapprochées d'un chemin, expansion d'environnement figée à la main
  ([ADR-003](adr/ADR-003-pare-feu-par-registre.md)).
- **DNS** : liste de résolveurs publics « bien connus » non exhaustive — un résolveur
  légitime absent de la liste ressort en `Notable`.
- **Autoruns** : la cible d'un raccourci `.lnk` n'est pas résolue ; le raccourci est énuméré
  sans jugement de signature.
- **Chemins de service non guillemetés** : l'inscriptibilité du dossier intermédiaire
  (condition d'exploitabilité) n'est pas vérifiée.
- **Fraîcheur des données** : le seuil d'alerte de 180 jours est arbitraire tant que la
  cadence de publication réelle n'est pas observée ([ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md)).
- **Appx résiduel** : les entrées-ressource orphelines sont écartées (DET-APPX-FAUXPOS,
  corrigé). Le filtre porte sur le segment ressource commençant par `split.`, **pas** sur ce
  segment non vide : deux douzaines de paquets système réellement installés — le shell
  Windows compris — portent `neutral` à cette place, et les écarter rendrait l'audit muet
  sur du logiciel présent.
