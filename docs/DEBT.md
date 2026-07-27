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

**Relevé au 2026-07-27**, après les phases 1 et 2 et l'étape 1 complète de la phase 3
(ADR-005 : rendus figés, contrat de sortie et parsing extraits). Lignes **non vides**,
convention retenue ici parce que c'est celle des relevés précédents de `Program.cs` :
Core 11 263, Windows 2 712, CLI 1 799 réparties sur 20 fichiers dont `Program.cs` qui n'en
porte plus que **29** — 1 881 → 29 depuis l'ouverture de DET-PROGRAM. **660 tests unitaires
en CI** et 62 Windows, soit 722 — 663 sur le poste de développement, qui porte une capture
réelle dans `tests/fixtures/local/` et exécute donc trois théories de plus
(DET-FIXTURE-LOCALE, dont c'est exactement le symptôme : le chiffre du poste et celui de
la CI ne sont pas le même chiffre, et le second est le seul reproductible). Le tableau
ci-dessus reste tel que mesuré le 2026-07-26 : c'est la photo qui a servi à prioriser, et
la réécrire effacerait le point de comparaison.

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
| DET-DEPENDABOT | Dependabot ne surveillait que `github-actions` : YamlDotNet, seule dépendance de production, n'avait aucune alerte de vulnérabilité | Phase 1 dette — écosystème `nuget` ajouté, outillage de test groupé en une seule PR |
| DET-SECURITY | Dépôt public d'un outil de sécurité sans voie de divulgation | Phase 1 dette — `SECURITY.md`, et **signalement privé de vulnérabilité activé** sur le dépôt : un rapport atteint le mainteneur sans passer par une issue publique, et sans publier d'adresse personnelle |
| DET-SYSTEM32 | `C:\Windows\System32\` et le paragraphe expliquant pourquoi il est en dur, recopiés dans 3 collecteurs | Phase 1 dette — `WindowsPaths`, qui garde le codage en dur (délibéré : pas de disque, pas de `System.IO.Path`, sinon une capture Windows rejouée sur Linux résoudrait autrement) et le dit une fois |
| DET-REPLAY-CABLAGE | Rien ne vérifiait qu'un fournisseur ajouté à `ProviderSet` était câblé au rejeu de fixtures — D2 puis D2b, la même erreur deux fois | Phase 2 dette — test de réflexion : chaque propriété de `ProviderSet` doit porter une implémentation `Snapshot*`. **Il a trouvé la troisième occurrence à sa première exécution** : `componentStore`, ajouté en M6, jamais câblé, sous un commentaire affirmant que tous l'étaient. Latente cette fois — le collecteur est opt-in — donc attrapée avant qu'elle ne fige « rien trouvé » |
| DET-WMI-MUET | `LiveDriverProvider` et `LiveProcessProvider` rendaient une liste vide sur lecture échouée, sans canal de statut : un WMI dégradé donnait zéro pilote et zéro processus, et le rapport ressemblait à une machine saine | Phase 2 dette — `DriverRead` et `ProcessRead` portent `Status` + `Diagnostic`, sur le modèle de `ScheduledTaskRead`. Les collecteurs remontent un constat `Notable` nommant l'échec. Le statut est **ajouté à côté** de la liste dans l'instantané, jamais en remplacement : changer `drivers` d'un tableau JSON en objet aurait rendu illisible toute capture existante, y compris les captures réelles hors dépôt |
| DET-EXT-MUET | Trois `catch (JsonException) { }` faisaient disparaître un profil de navigateur entier de l'inventaire, indistinguable de « ce profil n'a pas d'extension » | Phase 2 dette — les parseurs rendent `null` pour « illisible », distinct de la liste vide qui reste une réponse légitime. `BrowserExtensionRead.Partial` garde ce qui a été lu **et** nomme le profil qui ne l'a pas été. Asymétrie assumée avec les pilotes : zéro extension est un état de machine plausible, zéro pilote non |
| DET-IPV6 | Ports en écoute IPv6 non collectés : `LiveListeningPortProvider` n'interrogeait que `AF_INET`, donc un service exposé en IPv6 seul était **absent du rapport** | 2026-07-26 — tables `AF_INET6` lues avec leur propre forme de ligne (le scope id sépare l'adresse du port et décale tout ce qui suit : 56 octets en TCP6, 28 en UDP6). Adresse rendue sous forme compressée canonique par `IPAddress`, dont dépend le jugement Core. **Vérifié contre `netstat -ano`** : 18 triplets sur 19 identiques, l'unique écart étant un port de la plage dynamique — le transitoire `éphémère` déjà documenté en M7, pas un décalage. Le jugement Core acceptait `::` et `::1` depuis le début : il est désormais atteint, et testé |
| DET-FIXTURE-LOCALE | Le rejeu découvrait ses fixtures sur le disque et `tests/fixtures/local/` est gitignoré : le poste de dev exécutait 513 tests, la CI 511, sans que rien l'annonce | 2026-07-26 (#75) — le rejeu énonce son inventaire sur la sortie de test et dit franchement quand aucune capture réelle n'était présente. **Le registre, lui, n'a pas été mis à jour dans cette PR** : l'entrée est restée en « Ouvert » un jour de plus, le même écart entre le code et le registre que cet audit traquait ailleurs |
| DET-PROGRAM | `Program.cs` monolithe : **1 881 lignes** non vides à l'audit contre ~1 240 à l'inscription, +52 % en trois lots, dispatch et 16 commandes mêlés au rendu et au parsing | 2026-07-27, ADR-005 étapes 1 et 2 — il en porte **29** : l'encodage console, un appel à la table, le `try/catch` qui traduit une exception en code de sortie. Le reste est dans 17 classes de commande, une table explicite, un hôte pour les auxiliaires et deux surfaces pures dans Core. **Ce qui la fermait n'était pas la taille mais l'absence de filet** : rien ne surveillait 1 400 lignes qu'on s'apprêtait à déplacer. D'où l'ordre suivi — figer le rendu des trois commandes qui écrivent sur la console, extraire ce qui était pur, *puis* déplacer. Dix gardes surveillent la table, tous vérifiés par mutation ; deux d'entre eux ne sont nés que parce que la relecture a montré que les premiers comparaient deux listes écrites de la même main |
| DET-SORTIE-PARTIELLE | `rempart scan` rendait **0** quand les collecteurs avaient lu correctement mais que des règles étaient revenues `Unknown` : le code de sortie était décidé par le statut des collecteurs, jamais par les verdicts. Un scan non élevé dont des contrôles sont illisibles était, pour un appelant qui ne lit que le code — planificateur, script de parc —, indistinguable d'un scan complet | 2026-07-27 — code **5, « audit partiel »**, distinct du 3 : le 3 dit qu'un *collecteur* a été refusé, le 5 qu'une ou plusieurs *règles* n'ont pas pu être évaluées. Précédence 1 > 3 > 5 > 0, classée par ce que l'appelant peut en faire : une panne ne se répare pas en relançant élevé, un refus de collecteur si, une règle non évaluable est le plus faible des trois signaux sans être rien. `ForScan` prend désormais le `ScanResult` entier, comme `ForDiff` prend le `DiffResult` — deux paramètres de même forme auraient laissé passer les collecteurs d'un scan avec les verdicts d'un autre, sans que rien le signale. Le déclencheur est un verdict `Unknown`, lu à la source plutôt qu'à travers `Score`, qui est `null` précisément quand *rien* n'a pu être évalué. **Mesuré sur les quatre fixtures** : `restricted-access` — 100 % avec 4 contrôles non vérifiables, le cas qui motivait la dette — passe de 0 à **5** ; `hardened-win11` reste à **0** ; `default-win11` et `compromised-win11` passent à **5** (`WIN-ENC-001` illisible dans les deux). Un scan réel non élevé sur le poste rend 5, d'où l'élargissement de la garde CI de `{0, 3}` à `{0, 3, 5}` dans `ci.yml` **et** `release.yml` : acceptable sur un runner non élevé, qui ne peut pas tout vérifier, jamais pour un auditeur |
| DET-FIXTURE-MATERIEL | Les fixtures « synthétiques » ne sont pas fabriquées de rien : ce sont des captures réelles dont les champs identifiants sont lavés. Il restait, dans un dépôt public, **11 chemins de tâches planifiées** nommant des logiciels installés (`\Launch Adobe CCXProcess`, `\AMDRyzenMasterSDKTask`, `\NVIDIA App SelfUpdate_{GUID}`, `\StartCN`, `\StartDVR`, `\SoftLanding\…`), le **modèle de carte mère** (MS-7E80, PRO B850-S WIFI6E) et la **version et la date du BIOS** (2.A41, 03/17/2026). `Versioned_fixtures_are_anonymised` ne pouvait pas le voir : il ne vérifiait qu'un booléen et le préfixe du nom de machine | 2026-07-27 — **l'anonymiseur a été étendu plutôt que la phrase corrigée** : il sert aussi aux captures réelles qu'un utilisateur voudrait partager, et c'est son vrai métier. Trois changements, dans cet ordre parce que le troisième conditionne les deux autres. **(1)** L'identité matérielle — fabricant, modèle, famille, carte mère, version et date de BIOS — est hachée. Le périmètre est la **clé** `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, pas le nom de valeur : `ProductName` sous `CurrentVersion` vaut « Windows 11 Pro », la chaîne sur laquelle repose toute la dérivation de version d'OS, et un filtre par nom l'aurait emportée. **(2)** Le chemin et le nom des tâches **hors `\Microsoft\`** sont hachés. Le critère est le dossier et non l'auteur, délibérément : la fixture compromise plante une tâche **sous** `\Microsoft\Windows\Maintenance\SystemMaintenance` avec « Microsoft Corporation » pour auteur — c'est tout son intérêt — et trier par auteur aurait haché ses voisines en laissant l'imposteur lisible. **(3)** `Hash` est devenu **idempotent**, ce qui était la condition du reste : `SyntheticSnapshot.Build` posait `Anonymised = true` sans jamais faire tourner l'anonymiseur, et le lui faire exécuter aurait re-haché le nom de machine et les profils de navigateur en digests de digests. Le drapeau est désormais **mérité**, produit par `Anonymiser.Apply` au lieu d'être affirmé. **Preuve** : `grep` des onze marqueurs sur tout `tests/fixtures/synthetic/` rend **le code 1** (aucune occurrence), la même commande rendant **35 occurrences** sur la capture locale non versionnée, qui sert de contrôle négatif. **Aucun marqueur d'intrusion abîmé** : les **17 marqueurs** que `CompromiseMarkersTests` fige — adresses RFC 5737, port 4444 et sa règle, `syndrv64`, extension sideloadée, compte pré-haché — survivent, et la fixture compromise rend **exactement** ses 7 constats `Suspicious` et 3 `Notable`, aux mêmes lignes qu'avant. Les 4 `.diff.txt` sont **identiques au caractère près**. **Ce qui reste, et pourquoi** : les chemins d'exécutables — actions de tâches, 307 entrées de signature — nomment encore les éditeurs installés, et **ils ne sont pas seuls** : les noms de services WMI (`AdobeUpdateService`, « AMD Crash Defender Service »), et jusqu'à des **noms de valeurs** de clé `Run` (`Adobe CCXProcess`), en portent aussi. L'anonymiseur ne regarde que le contenu d'une valeur, jamais son nom. Compté : 35 occurrences d'éditeur par capture. Ils sont l'objet de l'audit (`SignatureLadder` les juge, le rapport les nomme, et le collecteur lit leur **forme** pour distinguer un chemin résolu d'un nom nu : un digest ne porte pas de séparateur et inventerait un constat « chemin non résolu » sur chaque tâche tierce). C'est la **forme** héritée de la capture source, distincte de l'**identité** désormais lavée — distinction écrite dans `ARCHITECTURE.md` plutôt que laissée à découvrir |
| DET-APPX-VERSIONS | Un paquet dont plusieurs versions restent enregistrées était remonté autant de fois | Phase 2 dette — `AppxPackageName.LatestPerIdentity`. L'identité est la famille **et** l'architecture, jamais la famille seule : vérifié par mutation, grouper sur la famille perd le paquet x86. Mesuré sur machine réelle : 268 → 228 lignes Appx, pour 134 → 114 identités calculées indépendamment |

## Ouvert

Classé par priorité décroissante.

| Réf | Dette | Catégorie | I | R | E | Prio | Note |
|---|---|---|:-:|:-:|:-:|:-:|---|
| DET-CATALOGUE-MUET | `CatalogSignature.Verify` rend `null` pour deux choses différentes : « aucun catalogue ne référence ce fichier », qui est une réponse, et « l'API n'a pas pu être interrogée » — contexte non acquis, hachage non calculable, fichier non ouvrable — qui n'en est pas une. Le jugement rend `Unsigned` dans les deux cas, et `SignatureLadder` en fait un constat **`Suspicious`**. Un fichier illisible est donc **accusé**, là où le commentaire d'en-tête de `LiveSignatureProvider` promet exactement l'inverse : « conflating *could not verify* with *not signed* would produce false alerts on the least auditable machines » | Code | 3 | 2 | 2 | 20 | Trouvé en descendant le jugement en Core (DET-WINDOWS-TESTS), **figé plutôt que corrigé** : `An_unaskable_catalog_is_reported_as_unsigned_rather_than_unverifiable` l'assert tel quel. C'est la forme de DET-WMI-MUET une couche plus bas, et du mauvais côté — les autres occurrences taisaient une panne, celle-ci invente une accusation. Se corrige en distinguant les deux `null` (un `CatalogOutcome` nommé plutôt qu'un `int?`) et en mappant l'échec sur `Unknown` ; ça déplace des verdicts sur machine réelle, donc son propre commit |
| DET-PORTS-MUET | `IListeningPortProvider.Enumerate` rend une liste nue : une lecture ratée rend la même chose qu'une machine sans service exposé. Aucune machine allumée n'écoute sur zéro port — RPC, SMB, le résolveur local — donc zéro ne peut être qu'une panne, et le rapport conclut pourtant « aucun port en écoute », qui se lit comme une bonne nouvelle | Code | 3 | 3 | 3 | 18 | Quatrième occurrence de DET-WMI-MUET, trouvée par le garde `ProviderStatusChannelTests` écrit pour ça — **avant qu'elle ne nuise**, comme le garde de DET-REPLAY-CABLAGE l'avait fait pour la troisième. Se corrige exactement comme la phase 2 : un statut **à côté** de la liste, jamais à la place, sinon les captures existantes deviennent illisibles |
| DET-ARITE-REPORT | `--report` est lu par `OptionalValue` sur `scan` et par `OptionValue` sur `diff`. Sur `rempart diff --report --baseline b.json a.json`, la comparaison part donc dans un dossier nommé `--baseline` | Code | 2 | 2 | 2 | 16 | Figé par `Positional_and_OptionValue_disagree_on_a_value_that_starts_with_a_dash`. Se corrige en alignant `diff` sur `OptionalValue` — changement de comportement d'une ligne de commande existante, donc son propre commit |
| DET-EXPLAIN-POSITIONNEL | `explain` lit son identifiant à l'indice 1 au lieu de passer par `Positional` : `rempart explain --rules <dossier> WIN-CRED-001` liste les 82 contrôles au lieu d'expliquer la règle demandée | Code | 1 | 1 | 1 | 10 | Figé par `An_identifier_placed_after_an_option_is_not_seen`. **Ne s'est pas refermé au découpage** (ADR-005, PR 2), comme annoncé ici d'abord : ce lot devait prouver qu'il ne changeait rien, et il ne pouvait donc pas changer ça en même temps. `ExplainCommand` appelle désormais `Positional` pour ses options — il ne lui reste qu'à l'appeler aussi pour son identifiant |
| DET-COUVERTURE | La couverture n'est mesurée que sur `Rempart.Core`, par le job Linux : `Rempart.Windows` (2 712 l.) et `Rempart.Cli` (1 799 l.) n'entrent pas au dénominateur, et aucun seuil ne garde le chiffre | Test | 1 | 1 | 2 | 8 | **L'absence de seuil est un choix, pas un oubli** — voir l'encadré ci-dessous, à lire avant de le « corriger ». Lié à DET-WINDOWS-TESTS : c'est désormais la seule couche à la fois hors mesure et faiblement testée, DET-PROGRAM étant fermée |
| DET-TACHE-EXPIREE | La branche « tâche supprimée après expiration » n'a aucun cas positif sur machine réelle : 196 tâches sur le poste de test, aucune concernée. Couverte par fixture fabriquée seulement | Test | 2 | 2 | 2 | 16 | Se ferme sur la première capture d'une machine qui en porte une ; le zéro a été vérifié, pas supposé |
| DET-WINDEFAULT | ~60 `windowsDefault` validés sur **une seule machine** — la « dette n°4 » d'ADR-002 | Code | 2 | 3 | 3 | 15 | Se corrige à mesure des captures réelles |
| DET-CI-SHA | Toutes les actions GitHub sont épinglées par SHA (vérifié). Ce qui flotte encore : le tag Docker d'actionlint (`:1.7.12`) et la bande `dotnet-version: '10.0.x'` | Infrastructure | 1 | 2 | 1 | 15 | Épingler actionlint par digest ; un `global.json` fermerait le SDK en même temps que DET-SDK |
| DET-WINDOWS-TESTS | La couche P/Invoke — 2 700 lignes, celle dont l'échec est « une valeur plausible et fausse » — a désormais 986 lignes de tests (826 à l'ouverture). **Quatre fournisseurs** n'ont plus ni test dédié ni commande `diagnose` : `LiveSecurityPolicyProvider`, `LiveDnsProvider`, `LiveHostsFileProvider`, `LiveFileSystemProvider` | Test | 2 | 3 | 3 | 15 | 2026-07-27 : les trois plus gênants des sept sont fermés. `LiveDriverProvider` et `LiveProcessProvider` par `diagnose-drivers`/`diagnose-processes` contre le binaire AOT ; `CatalogSignature` en deux temps — le jugement descendu en Core, donc testé **sur le job Linux**, et l'interop tenue par 5 tests Windows sondés. Les quatre restants sont d'un autre calibre : aucun ne décide qu'un binaire est sain. La cotation baisse en impact et en effort — le patron est maintenant établi deux fois — et remonte donc mécaniquement en priorité |
| DET-SDK | Pas de `global.json` (SDK non verrouillé) ni de Central Package Management | Infrastructure | 1 | 2 | 2 | 12 | Versions de test dupliquées dans 2 `.csproj` |
| DET-SCRIPTS | `verify.ps1` réimplémente la CI (actionlint, tests, publish, diagnose) sans être appelé par elle | Infrastructure | 2 | 2 | 3 | 12 | Divergence silencieuse possible ; confirmé structurellement à l'audit |
| DET-DIRTY | **Moitié fermée le 2026-07-27.** Une fixture compromise fabriquée existe désormais (`compromised-win11`, `synthesise --compromised`) : 17 marqueurs, 7 constats `Suspicious` et 3 `Notable`, chacun apparié à un jumeau bénin que le collecteur doit laisser tranquille. Reste ouverte la partie qu'aucun code ne peut produire : **une capture réelle compromise** | Test | 2 | 2 | 5 | 4 | La fabrication prouve la non-régression du jugement, pas la détection sur du réel — c'est ce qu'on attendait d'elle, et c'est tout ce qu'elle prouve. Ce qu'elle a révélé dépasse la couverture : le score d'une machine portant un implant actif, un port de commande joignable et un DNS détourné est **identique au point près** à celui d'une machine simplement non durcie et saine (52 %), domaine par domaine. Voulu (les constats n'entrent pas au score) mais jamais démontré de bout en bout avant |
| DET-TLS | Règles SCHANNEL/TLS non livrées : les défauts varient selon la build | Code | 3 | 3 | 4 | 12 | Demande une vérification sur plusieurs machines (ROADMAP M2b) |
| DET-RECPROV | 13 paires `Recording`/`Snapshot` quasi-identiques — `RecordingProviders.cs` fait 327 lignes | Code | 2 | 2 | 3 | 12 | Généraliser par `RecordingProvider<T>`/`SnapshotProvider<T>`. Lié à DET-REPLAY-CABLAGE : moins de répétition, moins d'occasions d'oublier un câblage |
| DET-PLAGE-DYNAMIQUE | Le premier port de la plage dynamique (49152) est une constante, non lue de la machine | Code | 1 | 1 | 3 | 6 | Dégradation gracieuse, jamais une affirmation fausse |

### Pourquoi la couverture n'a pas de seuil

Six raisons, dans l'ordre où elles mordent. Écrites ici pour qu'un prochain audit ne
prenne pas l'absence de porte pour un oubli.

1. **Le chiffre ne couvre pas ce qu'il a l'air de couvrir.** Le job Linux ne construit que
   `Rempart.Core`. Un seuil global poserait donc une porte sur la couche **déjà la mieux
   testée**, en restant aveugle aux deux que ce registre désigne comme les moins testées.
2. **Il bougerait dans le mauvais sens.** Ajouter du code non testé dans `Rempart.Cli`
   *améliore* le pourcentage mesuré, puisque ça n'entre pas au dénominateur. Une métrique
   qu'on améliore en écrivant du code non testé au mauvais endroit ne peut pas être une porte.
3. **La phase 3 déplace précisément du code de Cli vers Core.** #78, #79 et la PR « filet »
   ont sorti plus de 400 lignes de `Program.cs` vers Core. Chaque tranche suivante ajoute
   d'un coup des lignes au dénominateur et fait chuter le pourcentage sans qu'aucun test
   n'ait disparu. Un cliquet bloquerait exactement le refactoring que ce registre réclame.
4. **Ligne exécutée n'est pas ligne vérifiée.** `FixtureReplayTests` appelle
   `ScanEngine.Default().Run(...)`, moteur et règles compris, sur chaque fixture : un seul
   test marque presque tout Core comme couvert. Un seuil récompenserait l'ajout de
   fixtures, pas l'ajout d'assertions.
5. **Il n'est pas reproductible d'une machine à l'autre.** `tests/fixtures/local/` est
   gitignoré : ce poste rejoue plus de captures que la CI (DET-FIXTURE-LOCALE, déjà payé
   une fois avec l'écart 513/511 que rien n'annonçait).
6. **Le dépôt a déjà payé une CI qui rougit sans rapport avec le changement**
   (DET-WMI-FLAKY, cinq builds rouges en une journée dont un sur une PR sans C#). Ajouter
   un second moyen de rougir pour une raison étrangère à la modification serait refaire
   l'erreur en connaissance de cause.

## Plan de remédiation par phases

Pensé pour avancer **à côté du développement de fonctionnalités**, pas à sa place.

### Phase 1 — ✅ faite le 2026-07-26, sauf un item re-coté

`DET-DEPENDABOT` ✅ · `DET-SECURITY` ✅ · `DET-SYSTEM32` ✅ · ~~`DET-EXT-MUET`~~ → phase 2

Les trois premiers sont fermés. `DET-EXT-MUET`, coté effort 2 sur la foi de « trois
`catch` vides à remplir », s'est révélé coté 4 une fois le chemin suivi : le mécanisme de
dégradation existe, mais l'atteindre traverse une interface enregistrée dans les
instantanés. Le corriger à la va-vite dans un lot de correctifs courts, c'est-à-dire dans
la zone précise où D2 et D2b sont passés, aurait été la mauvaise façon de le faire.

**Ce que la phase 1 a appris sur le registre lui-même** : une cotation d'effort faite en
lisant le code n'est pas une cotation faite en suivant le chemin de la correction. Deux
entrées sur quatre ont bougé à l'exécution — `DET-SYSTEM32` était plus simple qu'annoncé
(la duplication, pas le codage en dur, qui est délibéré), `DET-EXT-MUET` deux fois plus
cher.

`DET-FIXTURE-LOCALE`, découverte en vérifiant l'écart 513/511 entre le poste et la CI,
rejoint la phase 1 pour un prochain passage : effort 1, priorité 20.

### Phase 2 — ✅ faite le 2026-07-26

`DET-REPLAY-CABLAGE` ✅ · `DET-APPX-VERSIONS` ✅ · `DET-WMI-MUET` ✅ · `DET-EXT-MUET` ✅

Les quatre entrées touchaient la même question : **ce que le rapport dit quand l'outil n'a
pas pu regarder.** Trois d'entre elles produisaient un silence indistinguable d'une bonne
nouvelle — zéro pilote, zéro processus, un profil de navigateur sans extension — et la
quatrième laissait un collecteur tourner à vide derrière une référence figée.

Le principe retenu, appliqué partout : **un canal de statut à côté de la donnée, jamais à
la place.** Changer une liste JSON en objet aurait rendu illisibles les captures
existantes, y compris les captures réelles gardées hors dépôt ; le statut s'ajoute, et une
capture qui n'en porte pas est relue comme le succès qu'elle était.

Et une asymétrie assumée plutôt que subie : zéro pilote ou zéro processus **ne peut pas**
être vrai sur une machine allumée, donc c'est une panne ; zéro extension de navigateur
l'est parfaitement, donc c'est une réponse. Traiter les deux pareil aurait ajouté du bruit
là où on venait d'enlever du silence.

**Ce que la phase 2 a appris.** Le garde de `DET-REPLAY-CABLAGE` a trouvé la troisième
occurrence de D2/D2b à sa première exécution — pour la première fois **avant** qu'elle ne
nuise. Et `DET-WMI-VIDE`, écrite le matin même, s'est révélée fausse à l'endroit qu'elle
désignait : le moteur de règles fait déjà ce qu'elle réclamait. Une entrée de registre
écrite en lisant un fichier n'est pas une entrée écrite en suivant le chemin jusqu'à ses
consommateurs.

Ces trois-là décident de ce que le rapport **dit**. `DET-WMI-VIDE` peut transformer une
machine non auditée en machine jugée ; `DET-REPLAY-CABLAGE` a déjà laissé passer deux fois
un collecteur tournant à vide derrière une référence figée à « rien trouvé ». À traiter
avant d'ajouter des collecteurs, chacun en étant une occasion de plus.

### Phase 3 — structure, avant M9 — conçue dans [ADR-005](adr/ADR-005-decoupage-de-la-couche-cli.md)

`DET-PROGRAM` · `DET-RECPROV` · `DET-WINDOWS-TESTS`

**L'ordre a changé après conception.** Il avait été avancé que `DET-RECPROV` réduirait la
surface de `DET-PROGRAM` et devait donc passer en premier : c'est faux, `RecordingProviders`
vit dans Core et ne touche `Program.cs` que par une cinquantaine de lignes sur 1 881. Les
deux dettes sont indépendantes.

Le vrai bloqueur est ailleurs : **la couche CLI n'a aucun test**. Les 534 tests unitaires
et 56 Windows n'en touchent pas une ligne, et la CI ne vérifie que des codes de sortie.
D'où la séquence retenue — extraire d'abord un rendu console **pur**, comme M6 l'a fait
pour les rapports, pour que le découpage des commandes soit comparable à une référence.
On ne déplace pas 1 400 lignes avant d'avoir posé le garde qui les surveille, exactement
le raisonnement qui a fermé `DET-REPLAY-CABLAGE`.

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
