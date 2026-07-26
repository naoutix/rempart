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
| DET-DISM | Les libellés attendus par `ComponentStoreParser` venaient de la documentation, pas d'une exécution élevée réelle | 2026-07-26 — `rempart diagnose-store --raw` exécuté en console admin : `Found`, **les 7 libellés correspondent**, aucune correction nécessaire. Deux subtilités du code validées sur du réel : le découpage au premier deux-points (la date `2026-07-23 09:53:40` porte les siens) et `0 bytes` à double espace. Relevé : 16,45 Gio réels, 7,76 partagés, 8,68 de sauvegardes, 5 paquets récupérables, nettoyage recommandé |
| DET-APPX-FAUXPOS | Le collecteur Appx remontait les entrées-ressource orphelines (`..._split.scale-*`) comme des logiciels installés — le rapport nommait un bloatware « à désinstaller » pour un paquet absent | Post-M7 — `AppxPackageName.IsResourcePackage`, jugement pur en Core, filtre dans `ReadAppx`. Mesuré sur machine réelle : BingWeather 1→0, Clipchamp 2→0, GamingApp 2→1 (réellement installé, conservé) |

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
| DET-TACHE-EXPIREE | La branche « tâche supprimée par Windows après expiration » (`DeleteExpiredTaskAfter` + `EndBoundary`) n'a aucun cas positif sur machine réelle : 196 tâches sur le poste de test, aucune avec l'un ou l'autre réglage, recoupé par `Get-ScheduledTask`. Couvert par fixture fabriquée seulement | 2 | 2 | 2 | 16 | Se ferme sur la première capture d'une machine qui en porte une ; le zéro a été vérifié, pas supposé |
| DET-PLAGE-DYNAMIQUE | Le premier port de la plage dynamique (49152) est une constante, non lue depuis la configuration de la machine. Un poste ayant personnalisé sa plage obtient un diff plus bruyant | 1 | 1 | 3 | 6 | Dégradation gracieuse, jamais une affirmation fausse. À reprendre si le cas se présente |
| DET-REPLAY-CABLAGE | Rien ne vérifie que tout nouveau fournisseur est câblé au rejeu de fixtures — D2 puis D2b sont la même erreur à deux reprises, et elle se voit uniquement en relisant un commentaire | 3 | 3 | 3 | 18 | Un test de réflexion comparant les propriétés de `ProviderSet` aux fournisseurs câblés dans `FixtureReplayTests` fermerait la récidive |
| DET-APPX-VERSIONS | Un paquet Appx dont plusieurs versions restent enregistrées est remonté autant de fois : sur le poste de test, `Microsoft.ECApp` et `Microsoft.LockApp` sortent 3 fois chacun, et les variantes d'architecture (`x64` + `x86` du même `Microsoft.NET.Native.Framework`) 2 fois. 113 PFN distincts pour 148 entrées brutes. Contrairement à DET-APPX-FAUXPOS ce n'est pas un faux positif — le logiciel est bien installé — mais une redondance qui gonfle l'inventaire | 1 | 1 | 2 | 8 | Découvert en corrigeant DET-APPX-FAUXPOS. Ne pas « corriger » par unicité du PFN : les variantes d'architecture sont des paquets distincts et légitimes. Retenir la version la plus haute par PFN serait le geste juste |

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
- **Appx résiduel** : les entrées-ressource orphelines sont désormais écartées
  (DET-APPX-FAUXPOS, corrigé). Le filtre porte sur le segment ressource commençant par
  `split.`, **pas** sur ce segment non vide : deux douzaines de paquets système réellement
  installés — le shell Windows compris — portent `neutral` à cette place, et les écarter
  rendrait l'audit muet sur du logiciel présent.
