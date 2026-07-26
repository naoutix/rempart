# Registre de dette technique

Ce que le projet sait devoir améliorer, tenu à jour au fil des audits. La dette du code
vit surtout en commentaires ; ce registre la rassemble pour qu'elle soit lisible d'un coup
et priorisable, plutôt que dispersée. Dernier audit : **2026-07-24, post-M6**.

Priorité indicative : `(Impact + Risque) × (6 − Effort)`.

## Corrigé

| Réf | Dette | Corrigé dans |
|---|---|---|
| D1 | `AutorunsCollector` résolvait les dossiers de démarrage par `Environment`/`Path` — cassait le déterminisme du rejeu Linux | Phase 1 dette (#45) — lecture via registre `Shell Folders` |
| D2 | Le rejeu bout-en-bout ne câblait que 8 providers snapshot ; les collecteurs réseau tournaient à vide | Phase 1 dette (#45) — 14 providers câblés, round-trip JSON exercé |
| D3 | `ProviderSet` (14 params) construit positionnellement en 3 sites — inversion silencieuse possible | Phase 1 dette (#45) — arguments nommés |
| D2b | Récidive de D2 : M5c a ajouté `IBrowserExtensionProvider` sans le câbler au rejeu de fixtures — le collecteur tournait à vide et la référence figeait « rien trouvé » | M6 — fournisseur câblé. Le commentaire du test affirmait « every replay provider is wired in » : une affirmation qu'aucun test ne vérifiait |

## Ouvert

| Réf | Dette | I | R | E | Prio | Note |
|---|---|:-:|:-:|:-:|:-:|---|
| DET-TLS | Règles SCHANNEL/TLS non livrées : les défauts varient selon la build de Windows, un `windowsDefault` deviné produirait de faux constats | 3 | 3 | 4 | 12 | Demande une vérification sur plusieurs machines (ROADMAP M2b) |
| DET-WINDEFAULT | ~60 `windowsDefault` validés sur **une seule machine** — la « dette n°4 » référencée dans [ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md) | 2 | 3 | 3 | 15 | Se corrige à mesure des captures réelles ; aucune liste ne la traçait avant ce registre |
| DET-IPV6 | Ports en écoute IPv6 non collectés (`AF_INET` seul) — recoupe l'item M4 « IPv6 » | 3 | 3 | 3 | 18 | Ajouter `AF_INET6` + formatage d'adresse ; le test Windows suppose IPv4 (`Split('.')`) et devra suivre |
| DET-SYSTEM32 | `C:\Windows\System32\` résolu en dur dans 3 collecteurs (COM, LSA, Logon) | 2 | 2 | 2 | 16 | Helper `PathResolver.ResolveSystem32` |
| DET-CI-SHA | Actions CI épinglées en tags mouvants (`@v4`, `actionlint:latest`, `10.0.x`) | 2 | 3 | 2 | 20 | Épingler par SHA (Phase 2 dette) |
| DET-SDK | Pas de `global.json` (SDK non verrouillé) ni de Central Package Management | 1 | 2 | 2 | 12 | Versions de test dupliquées dans 2 `.csproj` |
| DET-SCRIPTS | `verify.ps1` / `regenerate-fixtures.ps1` répliquent/alimentent la CI sans être appelés par elle | 2 | 2 | 3 | 12 | Peuvent diverger de `ci.yml` en silence |
| DET-DIRTY | Aucune fixture « sale » **versionnée** : les chemins de menace ne sont testés que par fakes + une capture locale hors dépôt | 3 | 3 | 4 | 12 | Une capture réelle compromise, anonymisée, serait le banc de test le plus honnête |
| DET-RECPROV | 13 paires `Recording`/`Snapshot` quasi-identiques (~250 l.) | 2 | 2 | 3 | 12 | Généraliser par `RecordingProvider<T>`/`SnapshotProvider<T>` |
| DET-PROGRAM | `Program.cs` monolithe (~1240 l. : dispatch + 10 commandes + rendu + parsing d'args) | 3 | 2 | 4 | 10 | Découper en commandes + couche de rendu, quand ça freinera |
| DET-DISM | Les libellés attendus par `ComponentStoreParser` viennent de la documentation, pas d'une exécution élevée réelle : le poste de développement refuse l'élévation (code 740, y compris sur `dism /?`). Le lecteur refuse proprement au lieu d'inventer des zéros, donc le risque est « la fonction ne marche pas », pas « la fonction ment » | 2 | 2 | 1 | 20 | Une seule exécution en console admin tranche : `rempart diagnose-store --raw`, puis corriger les libellés si besoin |
| DET-REPLAY-CABLAGE | Rien ne vérifie que tout nouveau fournisseur est câblé au rejeu de fixtures — D2 puis D2b sont la même erreur à deux reprises, et elle se voit uniquement en relisant un commentaire | 3 | 3 | 3 | 18 | Un test de réflexion comparant les propriétés de `ProviderSet` aux fournisseurs câblés dans `FixtureReplayTests` fermerait la récidive |
| DET-APPX-FAUXPOS | Le collecteur Appx lit directement `AppModel\Repository\Packages`, qui peut retenir une entrée-ressource orpheline (`..._split.scale-*`) d'un paquet désinstallé, sans l'entrée principale — `Get-AppxPackage` ne le liste alors plus. Constaté sur machine réelle (M5b) : 2 des 5 entrées du socle bloatware (météo Bing, Clipchamp) étaient dans ce cas et sont ressorties en `Notable`. Vu du consommateur de l'audit, c'est un faux positif en bonne et due forme : le rapport nomme un bloatware « à désinstaller » pour un logiciel qui n'est pas installé, il n'y a rien à retirer | 3 | 3 | 3 | 18 | Risque « crier au loup », pas hypothétique : faire distinguer au lecteur Appx une installation active d'une entrée-ressource orpheline avant d'escalader |

## Limitations connues, assumées

Documentées dans le code, conservatrices par conception — à ne « corriger » que si un besoin
réel émerge :

- **Pare-feu** : mots-clés de port dynamiques (`RPC`) non résolus, règles d'app empaquetées
  (`PFN`) non rapprochées d'un chemin, expansion d'environnement figée à la main
  ([ADR-003](adr/ADR-003-pare-feu-par-registre.md)).
- **DNS** : liste de résolveurs publics « bien connus » non exhaustive — un résolveur
  légitime absent de la liste ressort en `Notable`.
- **Autoruns** : la cible d'un raccourci `.lnk` n'est pas résolue (le format n'est pas lu) ;
  le raccourci est énuméré sans jugement de signature.
- **Chemins de service non guillemetés** : l'inscriptibilité du dossier intermédiaire
  (condition d'exploitabilité) n'est pas vérifiée.
- **Fraîcheur des données** : le seuil d'alerte de 180 jours est arbitraire tant que la
  cadence de publication réelle n'est pas observée ([ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md)).
- **Appx résiduel** : voir DET-APPX-FAUXPOS ci-dessus (registre « Ouvert ») — ce n'est pas
  une limitation assumée mais une dette à corriger.
