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
porte plus que **29** — 1 881 → 29 depuis l'ouverture de DET-PROGRAM. **678 tests unitaires
en CI** et 64 Windows, soit 742 — 681 sur le poste de développement, qui porte une capture
réelle dans `tests/fixtures/local/` et exécute donc trois théories de plus
(DET-FIXTURE-LOCALE, dont c'est exactement le symptôme : le chiffre du poste et celui de
la CI ne sont pas le même chiffre, et le second est le seul reproductible). Le tableau
ci-dessus reste tel que mesuré le 2026-07-26 : c'est la photo qui a servi à prioriser, et
la réécrire effacerait le point de comparaison.

**Après la phase 3 complète** (DET-RECPROV, DET-PLAGE-DYNAMIQUE, DET-WINDOWS-TESTS) :
**714 tests unitaires en CI** et **78 Windows**, soit 792 — 717 sur le poste, toujours les
trois théories de la capture locale. Les lignes de production ne sont **pas** rapportées ici
dans la même colonne que le relevé ci-dessus : recomptées à la même commande sur le commit
de départ, elles donnent Core 12 077, Windows 2 765, CLI 1 975, c'est-à-dire d'autres
chiffres que ceux du paragraphe précédent pour un code identique. Les deux mesures ne
comptent donc pas la même chose, et les empiler ferait un historique qui décrit une
croissance qui n'a pas eu lieu. Ce lot vaut, à cette commande : Core +513, Windows +166,
CLI **−53**.

**Après DET-FICHIERS-MUET** (2026-07-27) : **722 tests unitaires en CI** et **78 Windows**,
soit **800** — 725 sur le poste, toujours les trois théories de la capture locale. Les huit
unitaires ajoutés sont comptés et non déduits, le chiffre CI mesuré en retirant la capture
locale du disque. La suite Windows n'en gagne aucun : ses trois tests de
`LiveFileSystemProvider` ont été réécrits plutôt que doublés, et celui qui figeait le silence
asserte maintenant exactement l'inverse de ce qu'il figeait.

**Ce qui est sain, et mérite d'être dit.** Aucun marqueur de dette laissé dans le code :
elle est écrite en prose là où elle se trouve, et rassemblée ici. Une seule dépendance de
production sur un outil de sécurité, ce qui réduit d'autant la surface d'attaque de chaîne
d'approvisionnement. Toutes les actions GitHub épinglées par SHA, et depuis le 2026-07-27 le
conteneur actionlint par digest, et le SDK verrouillé par `global.json` (DET-CI-SHA,
DET-SDK). Ce qui flotte encore, et qu'il faut dire plutôt que se féliciter trop vite : les
six `runs-on: *-latest` et les quatre `dotnet-version: '10.0.x'`, ces derniers désormais
bornés par `global.json`. 800 tests, dont un rejeu de fixtures qui exerce le chemin complet
du scan sans machine Windows.

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
| DET-CATALOGUE-MUET | `CatalogSignature.Verify` rendait `null` pour deux choses différentes — « aucun catalogue ne référence ce fichier », qui est une réponse, et « l'API n'a pas pu être interrogée », qui n'en est pas une — et le jugement rendait `Unsigned` dans les deux cas, donc un constat **`Suspicious`**. Un fichier illisible était **accusé** | 2026-07-27 — `CatalogOutcome`, quatre cas nommés en Core (`NotAsked`, `Verified`, `NotCatalogued`, `Refused`, `Unaskable`). Seul `NotCatalogued` peut encore accuser ; `Unaskable` et `NotAsked` tombent sur `Unknown`, que `SignatureLadder` rend « non vérifiable. Ce n'est pas un défaut du binaire ». **L'état existait déjà** : `SignatureStatus.Unknown` et sa branche `Notable` étaient là depuis le début, c'est la couche interop qui ne pouvait pas les atteindre. `NotAsked` est la valeur par défaut de l'énumération, délibérément : un appelant qui oublie l'argument obtient « personne n'a regardé », jamais « rien trouvé ». Le test qui figeait le défaut a été **inversé, pas supprimé** — `An_unaskable_catalog_is_reported_as_unverifiable_rather_than_unsigned`, avec l'ancien nom et l'ancien comportement racontés dans son commentaire. **Mesuré sur machine réelle : 303 signatures capturées avant et après, 0 verdict déplacé** — le chemin d'un fichier qui s'ouvre est inchangé, la correction ne mord que là où une lecture échoue vraiment. Aucune référence de fixture ne bouge : les instantanés enregistrent des `FileSignature`, pas des HRESULT. Un test Windows déterministe tient la distinction sur le vrai magasin : le **même fichier** rendu `NotCatalogued` puis `Unaskable` selon qu'un handle `FileShare.None` le tient ouvert |
| DET-PORTS-MUET | `IListeningPortProvider.Enumerate` rendait une liste nue : une lecture ratée rendait la même chose qu'une machine sans service exposé, et le rapport concluait « aucun port en écoute », qui se lit comme une bonne nouvelle | 2026-07-27 — `ListeningPortRead` porte `Status` + `Diagnostic`, sur le modèle de `DriverRead` et `ProcessRead`. Le statut est **ajouté à côté** de la liste dans l'instantané (`listeningPortsStatus`, `listeningPortsDiagnostic`), jamais en remplacement : un objet à la place du tableau `listeningPorts` aurait rendu illisible toute capture existante. **Vérifié sur une vraie capture antérieure au changement** : rejouée par le binaire AOT neuf, elle rend ses 54 constats de port et n'invente aucun manque. Une troisième forme est nécessaire ici et l'était moins ailleurs : quatre tables sont lues (TCP/UDP × IPv4/IPv6) et elles échouent une par une, donc `Partial` garde ce qui a été lu **et** nomme la table muette — jeter les ports IPv4 parce que la table IPv6 refuse aurait déplacé le silence d'un protocole. Trois références de fixture bougent, et c'est le but : `default-win11`, `hardened-win11` et `restricted-access` n'ont jamais collecté de ports, elles gagnent donc chacune un constat `Notable` « Points d'écoute absents de l'instantané », exactement comme elles portent déjà « Pilotes chargés absents » et « Processus courants absents » depuis DET-WMI-MUET. La quatrième référence qui bouge est le `.diff.txt` `default-win11 → compromised-win11`, où ce constat apparaît en « disparu » : la capture compromise, elle, a des ports |
| DET-ARITE-REPORT | `--report` était lu par `OptionalValue` sur `scan` et par `OptionValue` sur `diff`. Sur `rempart diff --report --baseline b.json a.json`, la comparaison partait donc dans un dossier nommé `--baseline` | 2026-07-27 — `diff` lit `--report` avec `OptionalValue`, comme `scan` l'a toujours fait, et la surface déclare l'arité correspondante. **Vérifié sur le binaire construit** : la même ligne de commande écrivait ses trois fichiers dans `--baseline\`, elle les écrit maintenant dans le dossier courant ; `rempart diff --report ./sortie a.json b.json` écrit toujours dans `./sortie`. La paire comparée, elle, ne bouge pas — `Positional` n'est pas touchée, et c'est `--baseline b.json` qui désignait déjà le rapport « avant ». **La portée réelle du défaut était donc le dossier de sortie, pas le choix des fichiers** : mesuré, sortie console identique octet pour octet avant et après. Le test qui figeait le défaut a été **inversé, pas supprimé** — `Positional_and_OptionalValue_agree_on_a_value_that_starts_with_a_dash`, ancien nom et ancien comportement racontés dans son commentaire. Un garde nouveau interdit la récidive de la *cause* plutôt que du symptôme : `Every_option_a_command_reads_is_declared_with_the_reader_it_is_read_with` compare l'arité déclarée au lecteur réellement appelé, ce qu'aucun garde ne faisait — celui qui existait se contentait de vérifier que l'option était lue par *l'un* des quatre |
| DET-EXPLAIN-POSITIONNEL | `explain` lisait son identifiant à l'indice 1 au lieu de passer par `Positional` : `rempart explain --rules <dossier> WIN-CRED-001` listait les contrôles au lieu d'expliquer la règle demandée | 2026-07-27 — `Positional(args, CommandSurface.ValueTaking("explain"))`. **Vérifié sur le binaire construit**, avec un dossier `--rules` portant une règle supplémentaire : la commande sortait 110 lignes de catalogue (83 contrôles), elle sort les 28 lignes de `WIN-CRED-001` ; l'ordre inverse et la forme sans identifiant sont inchangés. Le défaut ne faisait rien échouer, et c'est ce qui le rendait durable : lister est ce qu'`explain` sans argument fait légitimement. `WordAt` reste juste et reste en place pour le mot de commande à l'indice 0 — le seul indice fixe qui soit un fait plutôt qu'une hypothèse, puisque aucune option ne peut le précéder. Son test n'a donc pas été inversé : `An_identifier_placed_after_an_option_is_not_seen` décrit toujours `WordAt`, et un test jumeau décrit ce que `Positional` en fait. Garde de récidive : `Only_the_command_word_is_read_at_a_fixed_index` |
| DET-SDK | Pas de `global.json` (SDK non verrouillé) ni de gestion centrale des paquets ; `Microsoft.NET.Test.Sdk`, `xunit` et `xunit.runner.visualstudio` déclarés **deux fois**, dans les deux `.csproj` de test, sans que rien ne relie les copies | 2026-07-27 — `global.json` verrouille **10.0.302** en `rollForward: latestFeature`. Le choix est le sujet de l'entrée et il est écrit dans le fichier : `disable`/`patch` exigeraient 10.0.302 au chiffre près, or les images de runner rafraîchissent leur SDK toutes les quelques semaines et la bande `10.0.x` finirait par résoudre une bande de fonctionnalités supérieure — chaque job s'arrêterait sur « compatible SDK not found », sur un commit qui n'a rien changé, et un verrou qu'il faut éditer pour garder un build correct au vert est un verrou qu'on supprime à la deuxième fois. `latestMajor` accepterait un SDK .NET 11, c'est-à-dire ne verrouillerait rien. `latestFeature` donne un plancher à 10.0.302 et un plafond à la fin de 10.0 : exactement la bande que les workflows demandent, à ceci près que la bande est une requête faite à un installeur sur un runner et que ce fichier est vérifié par MSBuild partout. **Vérifié par mutation, et la mutation a prouvé le verrou plutôt que le test** : passer la version à 9.0.100 fait refuser `dotnet` lui-même avant tout test. Les commentaires JSON sont tolérés — mesuré, `dotnet --version` résout 10.0.302 avec l'en-tête en place, et setup-dotnet analyse en JSON5. `Directory.Packages.props` porte les cinq versions ; `PrivateAssets`/`IncludeAssets` de `coverlet.collector` **restent dans les `.csproj`**, la gestion centrale ne déplaçant que la version — vérifié sur `-getItem:PackageReference` après restauration à froid, les deux métadonnées survivent. Restauration à froid, `obj/` et `bin/` supprimés : cinq projets restaurés, build et publication AOT au vert |
| DET-CI-SHA | Le tag Docker d'actionlint (`:1.7.12`) et la bande `dotnet-version: '10.0.x'` flottaient encore, seules exceptions à l'épinglage par empreinte | 2026-07-27 — actionlint épinglé par **digest** : `sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667`, l'index OCI de `rhysd/actionlint:1.7.12`. Lu au registre plutôt que recopié : en-tête `docker-content-digest` sur la requête de manifeste, confirmé par l'API de tags du Hub, et le digest se résout bien à un index listant linux/amd64 et linux/arm64. Le runner passe tout ce qui suit `docker://` à `docker pull` sans l'analyser (actions/runner, `PrepareRepositoryActionAsync`), donc une référence par digest est résolue par Docker. **Un fait à ne pas oublier au prochain audit** : Dependabot **ne rafraîchira pas** ce pin. Son analyseur d'actions écarte toute valeur `uses:` commençant par `docker://` avant de regarder quoi que ce soit (`github_actions/lib/dependabot/github_actions/file_parser.rb`) — ce qui explique aussi pourquoi cette étape n'apparaît dans aucune des trois PR de bump qui ont épinglé les autres actions. Le rafraîchissement était donc **déjà manuel** quand la ligne disait `:1.7.12` ; la différence est qu'un tag pouvait bouger sous nos pieds sans que le fichier change. La bande `10.0.x` est fermée par `global.json` (DET-SDK) et les deux orthographes sont tenues ensemble par un garde |
| DET-RECPROV | 13 paires `Recording`/`Snapshot` quasi-identiques, et — ce que l'entrée ne disait pas — **quatre copies de la liste des 20 fournisseurs** : le câblage réel, le câblage d'enregistrement, le câblage de rejeu, et une seconde copie de ce dernier dans la suite de tests | 2026-07-27 — **la généralisation qui payait n'était pas celle qui était écrite.** Un `RecordingProvider<T>` générique est impossible sans réflexion : la seule chose qui varie d'une paire à l'autre est le **nom de la méthode** de l'interface (`Read`, `Enumerate`, `Verify`, `ListFiles`, `Query`) et le **champ** de `MachineSnapshot`, deux noms résolus à la compilation. Il faudrait donc toujours une classe par interface et par sens, et pour neuf des treize paires le corps fait **une ligne** — mesuré : toute forme générique (délégués get/set, classe de base abstraite, `static abstract` sur un slot) en ajoute plus qu'elle n'en retire. Ce qui a été fait à la place, dans l'ordre de ce que ça rapporte. **(1) Les quatre listes deviennent trois fabriques nommées, chacune surveillée** : `SnapshotProviders.Replaying`, `SnapshotProviders.Recording` (Core) et `LiveProviders.All` (couche Windows). Le garde `Every_provider_is_wired_into_the_replay` lisait jusqu'ici **la copie du test** : `rempart scan --from` pouvait perdre un fournisseur en laissant tout au vert, et c'est la forme circulaire que ce dépôt s'est déjà reproché. Il lit maintenant la liste que la commande exécute. Deux gardes nouveaux ferment les deux autres sens — `Every_provider_is_wrapped_by_the_capture`, direction que **rien ne surveillait** et dont l'échec est le pire (une capture sans fournisseur n'a rien écrit, aucun rejeu ne le rattrape), et `Every_provider_has_a_live_implementation` dans la suite Windows. Les trois vérifiés par mutation. **(2) Le seul motif réellement dupliqué est généralisé** : la lecture en trois temps d'un instantané portant un canal de statut, recopiée à l'identique pour pilotes, processus, ports et extensions, devient `StatusChannel.Replay`/`Record` via une interface à membres `static abstract` — résolue à la compilation, donc sans réflexion et compatible AOT. Sa branche subtile — une capture antérieure au champ de statut, qui portait une liste et rien d'autre — **n'était exercée par aucune fixture** ; elle a maintenant cinq tests, tous cassés par mutation. **(3) Ce qui n'est pas généralisé, et pourquoi** : les neuf paires « enregistrer une fois, se rabattre » restent des lignes uniques ; les trois champs par surface restent trois champs, parce qu'un objet à la place du tableau JSON rendrait illisible toute capture existante (décision de la phase 2, inchangée) ; l'asymétrie zéro-pilote/zéro-extension reste un paramètre de `Replay` et non une constante, et une mutation qui l'aplatit rougit. **Les 4 fixtures et 11 de leurs 12 références n'ont pas bougé d'un octet** — la douzième pour DET-PLAGE-DYNAMIQUE, pas pour ce lot |
| DET-PLAGE-DYNAMIQUE | Le premier port de la plage dynamique (49152) était une constante, affirmée de toute machine scannée. Sur une machine reconfigurée, l'outil marquait comme « éphémères » des ports qui ne l'étaient pas, en taisant ceux qui l'étaient — et sans jamais dire qu'il supposait | 2026-07-27 — la plage est **lue de la machine**, par un fournisseur (`IDynamicPortRangeProvider`), donc enregistrée dans l'instantané et rejouable : une lecture faite depuis le collecteur aurait répondu autrement sur le poste Windows et sur le job Linux, et chaque référence de fixture aurait dépendu de l'endroit où la suite tourne. **Ni registre ni API** : vérifié plutôt que supposé, `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` ne porte aucune plage sur ce poste (`MaxUserPort` est le mécanisme pré-Vista, absent par défaut), et il n'existe pas d'API documentée — `netsh` passe par NSI, non documenté. Donc `netsh`, comme le magasin de composants passe par DISM, avec les deux mêmes précautions : **chemin absolu** depuis `Environment.SystemDirectory` (résoudre par `PATH` laisserait un fichier déposé dans le dossier courant décider de ce qu'un outil d'audit exécute) et **aucun verbe qui écrit** — `netsh set dynamicport` déplace la plage, à un mot de ce qui est demandé, et un test lit la liste d'arguments. **L'analyse ne regarde aucun libellé** : `netsh` n'a pas de `/English`, sa table sort dans la langue du système (« Port de démarrage » ici), donc seules les deux **valeurs** sont lues, à leur position. Un analyseur écrit sur les libellés aurait rendu la bonne plage sur le poste du mainteneur et une plage fausse, en silence, partout ailleurs. **La constante reste le repli** et le constat dit lequel des deux il a utilisé : « plage dynamique **relevée sur la machine** (49152–65535) » ou « plage dynamique **par défaut de Windows** (49152–65535), faute d'avoir pu lire celle de la machine ». Mêmes nombres, pas la même affirmation. **Relevé sur ce poste** : 49152, 16384 ports, identique pour les quatre tables (TCP/UDP × IPv4/IPv6) — confirmé par le binaire AOT publié, qui marque 30 constats de port. **Une référence de fixture bouge**, et c'est le but : `compromised-win11` n'a jamais relevé de plage, son port 49669 porte donc désormais la phrase de repli au lieu d'une affirmation. **Un défaut trouvé en exécutant le binaire publié, que rien d'autre n'aurait montré** : la détection de désaccord entre les quatre tables comparait les descriptions **étiquetées**, donc quatre plages identiques comptaient pour quatre différentes et chaque capture portait « Les tables ne déclarent pas la même plage » à propos d'une machine dont elles disaient toutes la même chose. Rien n'échouait ; seule la phrase à côté était fausse. Le pliage des quatre tables est descendu en Core et porte quatre tests |
| DET-WINDOWS-TESTS | La couche P/Invoke — celle dont l'échec est « une valeur plausible et fausse » — laissait quatre fournisseurs sans test dédié : `LiveSecurityPolicyProvider`, `LiveDnsProvider`, `LiveHostsFileProvider`, `LiveFileSystemProvider` | 2026-07-27 — **l'entrée était fausse sur deux des quatre** : `LiveDnsProvider` et `LiveHostsFileProvider` avaient un test dédié depuis M4 (#44). Ce qui manquait était autre chose, et pire : le test DNS **assertait à l'intérieur d'une boucle** sur ce que la lecture avait rendu, donc un résultat vide — le symptôme exact d'un mauvais chemin de clé — exécutait zéro assertion et rendait vert. Une forme par fournisseur, choisie plutôt qu'appliquée. **`LiveDnsProvider` : la logique descend en Core.** Il n'y avait aucune interop dedans — chemin de clé, deux noms de valeurs, séparateurs, règle « pas de résolveur, pas d'interface » — seulement du code posé dans un projet que le job Linux ne compile pas. `RegistryDnsProvider` porte tout cela avec **11 tests sur le job Linux** ; il reste ici un test Windows qui **confronte** la lecture à `NetworkInterface` : tout résolveur IPv4 dont le système dit qu'il s'en sert doit être trouvé par la lecture du registre, sinon un résolveur détourné serait absent du rapport. **`LiveHostsFileProvider` : une confrontation, pas une commande.** L'ancien test prouvait qu'*un* fichier portant un commentaire avait été lu ; le nouveau compare son contenu à celui du fichier désigné par `DataBasePath` sous les paramètres TCP/IP — là où la pile elle-même le cherche. Un mauvais chemin rendait « aucune redirection » sur une machine dont le fichier hosts pointe une banque ailleurs. **`LiveFileSystemProvider` : ni descente ni commande, un test de contrat.** Douze lignes autour de `Directory.GetFiles`, aucun jugement à descendre et aucune interop : trois tests figent ce dont le collecteur d'autoruns dépend — des chemins **absolus** (`GetFiles` rend des noms nus sur un dossier relatif, et la vérification de signature sortirait alors « fichier introuvable » sur chaque élément de démarrage), un dossier absent qui rend vide plutôt que de lever, et un dossier refusé qui rend vide — ce dernier **nommé comme la silence qu'il est** plutôt que loué : c'est la forme DET-*-MUET, laissée telle quelle parce que la corriger change ce qu'un instantané stocke, décision à part entière. **`LiveSecurityPolicyProvider` : cinq tests sondés, et une confrontation avec `net accounts`.** 70 lignes de parcours de structures non sûres, 0 % couvert, **six contrôles livrés** dessus dont un `critical` : `WIN-ACC-002` passe quand `accounts.withoutPassword` vaut **zéro**, c'est-à-dire que la bonne réponse est celle qu'une lecture ratée produirait aussi. Les faits de mot de passe et de verrouillage sont donc tenus par `net.exe`, autre implémentation de la même politique, **par rang et jamais par libellé** (même raison que `netsh`) ; intervertir deux champs de `USER_MODALS_INFO_0` fait rougir. Le compte d'administrateurs locaux refuse le zéro, qui ne peut pas être vrai. Et la **disposition mémoire** de `USER_INFO_1` est confrontée à l'ABI que `netapi32` publie — 56 octets, `Flags` à l'offset 40, exactement les deux nombres que la première version de ce fichier avait faux (64 et 28, le lecteur plantait) : mesuré, un `Flags` lu au mauvais offset transforme « compte invité désactivé » en « compte invité **actif** » et déplace deux compteurs, sans qu'aucune borne ni aucun analyseur ne s'en aperçoive. `sizeof` et arithmétique de pointeurs, jamais `Marshal.OffsetOf`, qui lit des métadonnées à l'exécution. **Aucune commande `diagnose` ajoutée, et c'est mesuré et non supposé.** La seule des quatre à porter un risque propre à l'AOT était la politique, via `SecurityIdentifier.Translate(typeof(NTAccount))` ; le binaire publié a été construit et interrogé : les **six** règles `WIN-ACC-*` sont évaluées, `WIN-ACC-004` observe 2 administrateurs, aux mêmes valeurs que sous JIT. L'argument tombe, donc la commande aussi — quatre commandes pour la symétrie auraient été du remplissage, et une seule sans motif mesuré l'aurait été autant |
| DET-SCRIPTS | `verify.ps1` réimplémentait la CI sans être appelé par elle. **Le prix avait déjà été payé** : le lot du code 5 a élargi les deux workflows à `{0, 3, 5}` et laissé `verify.ps1` à `{0, 3}`, ce qui aurait fait rejeter en local tout build correct. Un relecteur l'a attrapé, pas un test | 2026-07-27 — **voie retenue : un garde**, `BuildChainParityTests`, sur le modèle de `CoverageSettingsTests`. Les deux autres voies ont été écartées et méritent de l'être par écrit : faire appeler `verify.ps1` par la CI donnerait une source unique mais la CI est quatre jobs parallèles et le script est séquentiel — on paierait le retour rapide pour supprimer une duplication qui ne coûte rien tant qu'elle est surveillée ; extraire les constantes dans un fichier partagé demanderait d'inventer un quatrième format et d'en écrire l'analyseur en PowerShell, en YAML et en C#, pour deux listes courtes. Les listes sont extraites des deux côtés et comparées **l'une à l'autre**, jamais à une troisième écrite dans le test, qui n'aurait fait que déplacer la dérive. Là où un troisième avis existe déjà en code compilé, ce sont les scripts qui lui sont confrontés : les codes acceptés doivent tous exister dans `ExitCode`, les commandes appelées dans `CommandSurface`. La réconciliation ne s'est pas arrêtée au garde : `verify.ps1` prétendait rejouer la CI et ne passait **aucune** des quatre commandes `diagnose-*` que le job `publish-aot` fait tourner contre le binaire publié — il les passe maintenant, et itère sur les deux suites comme la CI le fait en deux jobs. Sept gardes, **tous vérifiés par mutation** |
| DET-FICHIERS-MUET | `IFileSystemProvider.ListFiles` rendait une liste nue : un dossier de démarrage **refusé** rendait exactement ce que rend un dossier vide, et le rapport concluait « aucun autorun » sur la première surface qu'une persistance utilise | 2026-07-27 — **cinquième et dernière occurrence de la forme DET-*-MUET**, traitée comme les quatre précédentes et sans en réinventer le patron. `DirectoryRead` porte `Status` + `Diagnostic` et implémente `IStatusCarryingRead`, donc la lecture en trois temps d'une capture passe par `StatusChannel` — **pas une cinquième copie**, ce que DET-RECPROV désignait comme l'endroit de la prochaine erreur. **Trois états et non deux, parce que trois faits existent** : `Found` — le dossier a été listé, et **une liste vide y est une réponse** (un dossier de démarrage vide est l'état ordinaire de la plupart des machines, contrairement à zéro pilote ou zéro port, qui ne peuvent pas être vrais) ; `NotFound` — le dossier n'est pas sur le disque, muet lui aussi, mais enregistré séparément parce que « j'ai listé ce dossier et il était vide » est une affirmation que le scan n'a pas faite ; `AccessDenied` — le seul qui parle. Le collecteur teste donc `== AccessDenied` là où ses quatre frères testent `!= Found`, et l'écart est commenté : tester `!= Found` ici poserait un `Notable` sur presque chaque scan, et un rapport qu'on ne finit plus de lire ne protège rien. **Pas de `Partial`, contrairement à `ListeningPortRead`, et la différence est l'argument** : un `Enumerate` de ports couvre quatre tables derrière un seul appel et peut revenir à moitié lu ; `ListFiles` prend le répertoire en paramètre, donc un appel = un dossier, et `Directory.GetFiles` rend tout ou lève. La partialité est réelle mais elle vit **un cran plus haut**, dans la boucle du collecteur — un dossier machine refusé ne doit pas coûter les fichiers du dossier utilisateur qui a répondu — et c'est là qu'elle est testée. **Le statut est à côté de la liste** : `directoriesStatus` et `directoriesDiagnostic`, deux dictionnaires **sur la même clé** que `directories`, jamais un objet à la place du tableau JSON — décision de la phase 2, reprise pour la cinquième fois. Clé par répertoire parce que la lecture l'est : un statut unique pour toute la carte devrait mentir sur l'un des deux dossiers. **Une capture ancienne, qui portait une liste et rien d'autre, se relit comme le succès qu'elle était** — testé, et cassé par mutation. **Une fuite fermée en passant** : le diagnostic **cite le dossier**, donc le dossier de démarrage d'un utilisateur y écrit son nom de compte ; l'anonymiseur lave désormais la **valeur** et pas seulement la clé, sans quoi une capture se déclarant anonymisée aurait reconduit le nom par le seul champ où il n'était jamais passé. **Aucune fixture ni aucune des 12 références n'a bougé d'un octet**, et c'est vérifié plutôt qu'espéré : aucune des 4 fixtures synthétiques n'énumère la clé `Shell Folders` — trois ont `registryLists` entièrement vide, la compromise y déclare deux clés `Run` et rien d'autre — donc aucune n'y résout de dossier de démarrage et `ListFiles` n'y est jamais appelé ; la capture réelle non versionnée porte ses deux dossiers avec leur liste et sans statut, donc exactement la branche « lue comme un succès ». **Ce qui est le manque de cette fermeture, et il faut le dire** : les quatre dettes précédentes avaient chacune une fixture *versionnée* exerçant leur chemin — `compromised-win11` porte `listeningPorts` sans `listeningPortsStatus`, `restricted-access.console.txt` fige les quatre silences. Ici la seule capture au format ancien est hors dépôt, donc hors CI, et le rendu console du constat de dossier refusé n'est figé par aucune référence. La branche est tenue par des tests unitaires cassés par mutation, pas de bout en bout. Se referme en donnant à `restricted-access` — la fixture dont c'est le sujet même — une clé `Shell Folders` et un dossier refusé **15 mutations passées, toutes rouges** — dont celle qui remet exactement le code d'avant le lot, et les trois qui décâblent le fournisseur de fichiers des trois fabriques. **Une mutation a d'abord survécu**, et le test a été corrigé plutôt que la mutation écartée : ne plus écrire la **liste** dans la capture ne cassait rien, le statut suffisant à empêcher la seconde interrogation — une capture qui aurait noté « lu » sans les fichiers, c'est-à-dire le même silence un cran plus loin. **Vérifié sur le binaire AOT publié** : une capture réelle porte les deux nouveaux champs (source-générés en `DictionaryStringReadStatus`, aucune réflexion), et la même capture dont un dossier est marqué refusé sort un `NOTABLE` nommant le dossier là où elle ne disait rien |

## Ouvert

Classé par priorité décroissante.

| Réf | Dette | Catégorie | I | R | E | Prio | Note |
|---|---|---|:-:|:-:|:-:|:-:|---|
| DET-TACHE-EXPIREE | La branche « tâche supprimée après expiration » n'a aucun cas positif sur machine réelle : 196 tâches sur le poste de test, aucune concernée. Couverte par fixture fabriquée seulement | Test | 2 | 2 | 2 | 16 | Se ferme sur la première capture d'une machine qui en porte une ; le zéro a été vérifié, pas supposé |
| DET-WINDEFAULT | ~60 `windowsDefault` validés sur **une seule machine** — la « dette n°4 » d'ADR-002 | Code | 2 | 3 | 3 | 15 | Se corrige à mesure des captures réelles |
| DET-TLS | Règles SCHANNEL/TLS non livrées : les défauts varient selon la build | Code | 3 | 3 | 4 | 12 | Demande une vérification sur plusieurs machines (ROADMAP M2b) |
| DET-COUVERTURE | **Moitié fermée le 2026-07-27.** `Rempart.Windows` entre désormais au dénominateur, mesuré par le job `test-windows` — le seul qui puisse le compiler. Reste dehors `Rempart.Cli` (1 799 l.) | Test | 1 | 1 | 2 | 8 | **L'absence de seuil reste un choix, pas un oubli** — l'encadré ci-dessous est inchangé et n'a pas été affaibli : ce qui a bougé est le périmètre *vu*, pas ce qui est *imposé*. Voir le détail sous l'encadré |
| DET-DIRTY | **Moitié fermée le 2026-07-27.** Une fixture compromise fabriquée existe désormais (`compromised-win11`, `synthesise --compromised`) : 17 marqueurs, 7 constats `Suspicious` et 3 `Notable`, chacun apparié à un jumeau bénin que le collecteur doit laisser tranquille. Reste ouverte la partie qu'aucun code ne peut produire : **une capture réelle compromise** | Test | 2 | 2 | 5 | 4 | La fabrication prouve la non-régression du jugement, pas la détection sur du réel — c'est ce qu'on attendait d'elle, et c'est tout ce qu'elle prouve. Ce qu'elle a révélé dépasse la couverture : le score d'une machine portant un implant actif, un port de commande joignable et un DNS détourné est **identique au point près** à celui d'une machine simplement non durcie et saine (52 %), domaine par domaine. Voulu (les constats n'entrent pas au score) mais jamais démontré de bout en bout avant |

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

### Ce que la mesure Windows a changé, et ce qui reste ouvert — 2026-07-27

Les six raisons ci-dessus ne sont pas retouchées : elles argumentent l'absence de **seuil**,
et rien de ce qui suit n'en pose un. Ce qui a bougé est le **périmètre**. La raison n°1
devient à moitié caduque et c'est exactement l'intention : des « deux couches les moins
testées » qu'elle nomme, une est désormais au dénominateur.

**Ce qui est mesuré.** `test-windows` collecte avec `tests/coverage.windows.runsettings`, et
publie son résumé par le **même** `scripts/coverage-summary.ps1` que le job Linux, à un
paramètre près — un second script aurait été la dette d'à côté (DET-SCRIPTS). Deux fichiers
de configuration plutôt qu'un `Include` élargi : un pourcentage unique couvrant deux couches
testées par deux suites sur deux systèmes ne dirait à personne laquelle a bougé.

**Chiffre relevé sur le poste : 561 / 926 lignes, 60,6 %.** Il vaut d'être expliqué, parce
que le premier relevé disait 35,5 % et que ce chiffre-là était faux. `ExcludeByAttribute`
n'attrape pas les stubs COM que `ComInterfaceGenerator` émet dans `obj/` pour le
planificateur de tâches et WMI : **751 des 1 677 lignes** initiales étaient du code généré,
couvert à 4,7 %, et neuf des douze « fichiers » les moins couverts étaient de la sortie de
générateur. `ExcludeByFile` les écarte. Le chiffre publié mesure maintenant du code que
quelqu'un a écrit et à qui on peut le reprocher — et sa liste des moins couverts nomme
directement `LiveScheduledTaskProvider` (0/126) et `LiveSecurityPolicyProvider` (0/70), l'un
des quatre fournisseurs que DET-WINDOWS-TESTS désigne. Les deux entrées se répondent : la
mesure ne remplace pas les tests manquants, elle les compte.

**Recompté après la fermeture de DET-WINDOWS-TESTS : 677 / 979 lignes, 69,2 %.** La
prédiction du paragraphe ci-dessus se vérifie sur la ligne qu'il nommait —
`LiveSecurityPolicyProvider` passe de **0/70 à 64/72**, et sort de la tête de liste. Le
dénominateur monte de 926 à 979 parce que le lot y ajoute un fournisseur
(`LiveDynamicPortRangeProvider`, 31/40). Il reste un seul zéro, et c'est le même :
`LiveScheduledTaskProvider` (0/126), qu'aucun test Windows ne touche parce que
`diagnose-tasks` l'exerce contre le binaire publié — un chemin que la mesure de couverture
ne voit pas et ne verra jamais. Le compter comme non testé est faux ; l'exclure serait pire.

**Ce qui reste ouvert, et pourquoi.** `Rempart.Cli` (1 799 l.) n'est mesuré par personne, et
ce n'est pas un oubli de filtre : `Rempart.Tests.Windows` **ne référence pas** `Rempart.Cli`,
donc l'assembly n'est jamais chargée par cette suite et l'ajouter à l'`Include` n'aurait fait
que grossir un filtre qui ne correspond à rien. **Aucun garde n'interdit ce geste-là** :
`Every_measured_assembly_is_a_project_of_this_repository` refuse une assembly qui n'est pas
un projet du dépôt, et `Rempart.Cli` en est un — il refuserait `[Rempart.Win32]*`, pas
`[Rempart.Cli]*`. Vérifié par mutation lors de la relecture. Le mesurer
demande une décision qui n'est pas une décision de couverture : ajouter une référence de
projet vers un exécutable `PublishAot`/`win-x64` depuis une suite de tests, ou déplacer
encore du code de Cli vers Core. La seconde est ce que la phase 3 fait déjà, et le chiffre
suivra sans qu'on ait rien câblé pour lui. En attendant, la bonne lecture est celle-ci : le
dépôt mesure deux de ses trois couches, et **dit laquelle il ne mesure pas** plutôt que de
publier un pourcentage global qui l'aurait tue.

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

**Reliquat, fermé le 2026-07-27** : `DET-PORTS-MUET` ✅ · `DET-CATALOGUE-MUET` ✅

Les deux dernières occurrences de la même forme, trouvées par les gardes que la phase 2
avait laissés derrière elle et corrigées sur le principe qu'elle avait posé. Les ports
appliquent la recette telle quelle — un statut à côté de la liste — avec une nuance que
les pilotes n'avaient pas : la lecture est **quatre appels** et non un, donc un état
`Partial` garde ce qui a été lu au lieu de tout jeter.

Le catalogue est l'inverse des trois autres et mérite d'être noté comme tel : les
occurrences précédentes **taisaient une panne**, celle-ci **inventait une accusation**. Le
principe n'était donc pas « ajouter un canal » mais « ne pas répondre à la place de
quelqu'un qui n'a rien dit » — et l'état qui manquait existait déjà (`SignatureStatus
.Unknown`, rendu `Notable`) : c'est la couche interop qui, en rendant `int?`, ne pouvait
pas l'atteindre. **Une correction dont le prix réel se mesure** : 303 signatures capturées
avant et après sur la même machine, **aucun verdict déplacé**, parce qu'un fichier qui
s'ouvre suit exactement le chemin d'avant.

### Phase 3 — ✅ faite le 2026-07-27 — conçue dans [ADR-005](adr/ADR-005-decoupage-de-la-couche-cli.md)

`DET-PROGRAM` ✅ · `DET-RECPROV` ✅ · `DET-WINDOWS-TESTS` ✅

**Ce que la phase 3 a appris, et qui vaut pour la suite du registre.** Deux des trois entrées
étaient fausses à l'endroit précis qu'elles désignaient, chacune à sa manière.
`DET-RECPROV` prescrivait `RecordingProvider<T>`/`SnapshotProvider<T>` : suivre le chemin
montre que ce générique n'existe pas sans réflexion, parce que ce qui varie d'une paire à
l'autre est un nom de méthode et un nom de champ, tous deux résolus à la compilation. La
duplication qui coûtait vraiment était ailleurs et n'était pas dans l'entrée — quatre copies
de la liste des vingt fournisseurs, dont une **dans le test qui prétendait la
surveiller**. `DET-WINDOWS-TESTS` nommait quatre fournisseurs « sans test dédié » ; deux en
avaient un depuis M4, et le défaut n'était pas l'absence de test mais un test qui assertait
à l'intérieur d'une boucle sur son propre résultat, donc vert précisément quand la lecture
était cassée. Une entrée de registre écrite en lisant un fichier n'est toujours pas une
entrée écrite en suivant le chemin — la phase 1 l'avait noté pour la **cotation d'effort**,
la phase 3 l'étend à l'**énoncé du défaut**.

Et un défaut qu'aucune suite n'aurait montré : la détection de désaccord entre les quatre
tables de plage dynamique comparait des chaînes étiquetées, donc quatre plages identiques
comptaient pour quatre différentes. Trouvé en **exécutant le binaire publié et en lisant ce
qu'il avait écrit**, pas en relisant le code. Le jugement est descendu en Core dans la
foulée, où quatre tests le tiennent.

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
