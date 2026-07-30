# Revue complète du dépôt — 2026-07-29

Revue de l'intégralité du code à la version **v1.0.0** (`666f96c`), sur six axes menés en
parallèle : frontières de confiance cryptographiques, échappement et anonymisation des
sorties, faux négatifs de la logique d'audit, interop natif et ressources, qualité de la
suite de tests, chaîne de construction et de publication.

**Périmètre mesuré :** 21 000 lignes de source (`Rempart.Core` 15 161, `Rempart.Windows`
3 498, `Rempart.Cli` 2 400) et 15 200 lignes de tests.

---

## Verdict

Le dépôt tient ses promesses centrales. **Aucun chemin ne permet de faire accepter des
règles choisies, un catalogue de pilotes choisi ou une clé USB altérée** — la vérification
de signature, l'épinglage de clé et le sceau ont été attaqués sans résultat. L'échappement
HTML est complet, les parties difficiles de l'interop sont justes, et la suite de tests
tient réellement la doctrine qu'elle affiche.

Trois défauts sortent du lot et appellent une correction avant la prochaine étiquette :

1. **Un faux négatif atteignable sans privilèges** (REV-01) — l'échelle de signature, sur
   laquelle huit collecteurs s'appuient, se contourne en créant un dossier.
2. **Une fonctionnalité livrée sans son dernier maillon** (REV-02) — le catalogue bloatware
   d'ADR-006 n'a aucun chemin de livraison vers une machine auditée.
3. **Une fuite d'identifiants dans une capture marquée anonymisée** (REV-03).

**Suivi.** Les 33 trouvailles sont réparties en 18 issues sous le jalon
[Revue complète du 2026-07-29](https://github.com/naoutix/rempart/milestone/13). Chaque ligne
des tableaux ci-dessous porte son numéro. La revue elle-même s'arrête au constat : rien
n'était corrigé au moment où ce document a été écrit.

**Toutes l'ont été depuis**, une PR par issue, sauf REV-29 — refusée par argument, non par
oubli : les références golden sont suivies en git, la CI n'en a jamais d'absente, et toute
contrainte plus forte casserait le flux de régénération que CONTRIBUTING documente. Trois
correctifs laissent une dette nommée plutôt qu'une promesse : `DET-MSIX-VOLUME` (REV-01),
`DET-INTERPRETEURS` (REV-17), `DET-REJEU-REFUS` (REV-13) et `DET-VERROU-NUGET` (REV-31).
Le récit de ce que les correctifs ont généralisé est dans la
[feuille de route](../ROADMAP.md).

---

## Le motif

La plupart des autres trouvailles ont la même forme : **une classe de défaut a été corrigée
à un endroit, et la couche d'à côté a été laissée.**

| Corrigé | Laissé |
|---|---|
| Canal de statut posé sur cinq lectures | Les providers dessous (tâches, pare-feu) ne savent pas exprimer « partiel » et rendent `Found` |
| Garde par réflexion sur les *providers* | Rien ne confronte les *collecteurs* au disque |
| `Cell()` échappe treize fois dans le Markdown | Sauf dans la section des constats |
| `DirectoriesDiagnostic` nettoyé à l'anonymisation | Les quatre `*Diagnostic` frères ne le sont pas |
| `ScrubScope` traite `Server` et `AutoConfigUrl` | `Bypass`, même record, passe en clair |
| Le `catch (Exception)` de WMI refuse de déguiser un échec | Le `catch (COMException)` juste au-dessus le déguise |

C'est de la **couverture par énumération plutôt que par construction** : des listes tenues à
la main, justes le jour où elles ont été écrites, sans mécanisme pour le rester. Le dépôt
connaît ce piège — D2, D2b, DET-SCRIPTS, « une garde confrontée à une seconde liste écrite
de la même main ne garde rien » — mais la doctrine est appliquée aux tests, pas au code de
production.

---

## Ce qui tient

À consigner autant que les défauts, parce qu'un prochain audit n'a pas à le réattaquer.

- **Frontières de confiance.** Clé réellement épinglée (dictionnaire statique de littéraux,
  aucun fichier, variable d'environnement ou champ de manifeste ne l'alimente) ; on signe les
  octets puis on parse, jamais l'inverse ; `catch → false` ne peut pas devenir un succès ; la
  revérification du magasin est faite à **chaque** scan, sans cache ni marqueur ; comparaison
  de hash en temps constant sur les 64 caractères ; le sceau détecte un fichier **ajouté** et
  résiste au changement de casse et de séparateur.
- **Clé privée.** Aucun chemin non chiffré, AES-256-CBC, PBKDF2 600 000 itérations, refus si
  l'entrée est redirigée, saisie masquée, seul le blob chiffré est imprimé.
- **Rendu HTML.** Toutes les interpolations machine passent par `Escape` (les cinq caractères) ;
  les seules qui l'évitent sont des entiers, vérifiés un par un jusqu'à leur déclaration ;
  aucun `href`/`src` n'existe dans la sortie ; le script en ligne ne reçoit **aucune** donnée
  de scan — c'est structurel, pas déclaratif.
- **Interop.** Les quatre dispositions de lignes MIB sont justes, décalage de scope id IPv6
  compris ; l'ordre des slots vtable est correct sur les six interfaces COM ; le double appel
  obligatoire de `WinVerifyTrust` est présent ; aucune réflexion sur un chemin interop.
  Il n'existe aucun analyseur d'octets exposé à un attaquant — la classe de bugs
  « pointeur de compression DNS » est structurellement impossible ici.
- **Concurrence.** Le postulat « collecteurs en parallèle » de la documentation est faux :
  `ScanEngine` itère en `foreach`. Aucun état mutable partagé, donc aucun des risques associés.
- **Suite de tests.** Aucune assertion tautologique, aucun test sans assertion (une exception,
  REV-27), aucune source de théorie légitimement vide. Les gardes lisent le disque plutôt
  qu'une seconde liste. La discipline de mutation est documentée jusqu'à la suppression d'un
  test qu'on n'arrivait pas à faire rougir.
- **Chaîne de build.** Treize `uses:` épinglés par SHA, actionlint par digest d'image, versions
  de paquets centralisées sans rien de flottant, SDK verrouillé et gardé par un test, **zéro
  secret** dans les workflows, `pull_request` et non `pull_request_target`. Les deux
  préconditions de release documentées sont réellement appliquées et font échouer le job.

---

## Trouvailles

**État :** *vérifié* = tracé et confirmé dans le code au cours de cette revue ;
*rapporté* = tracé par le relecteur de l'axe, non recontrôlé indépendamment ;
*à confirmer* = repose sur une prémisse invérifiable depuis le dépôt.

### Critique

| Réf | Trouvaille | Fichier | État | Issue |
|---|---|---|---|---|
| REV-01 | `\WindowsApps\` cherché en sous-chaîne : un binaire non signé posé dans un dossier de ce nom créé dans le profil utilisateur est jugé `Benign`, et l'escalade « emplacement inhabituel » est sautée | `Findings/SignatureJudgement.cs:49` | vérifié | #105 |

### Élevée

| Réf | Trouvaille | Fichier | État | Issue |
|---|---|---|---|---|
| REV-02 | `UpdatePlanner` ne route pas `DatasetKind.Bloatware` : un catalogue signé est refusé comme « type inconnu de cette version ». `fetch-bloatware` imprime pourtant cette marche à suivre | `Updates/UpdatePlanner.cs:108` | vérifié | #106 |
| REV-03 | `ScrubScope` ne nettoie pas `ProxyScope.Bypass` ; `ProxyCollector` le recopie dans les détails d'un constat. Domaines internes et hôte du proxy partent en clair dans une capture `anonymised: true` | `Snapshots/Anonymiser.cs:235`, `Findings/ProxyCollector.cs:95` | vérifié | #107 |
| REV-04 | Tout HRESULT COM non reconnu devient `AccessDenied` : un dépôt WMI endommagé fait dire « relancer en administrateur » indéfiniment. Enfreint l'invariant de CONTRIBUTING, dans le fichier qui le documente | `Windows/Wmi/LiveWmiProvider.cs:81` | vérifié | #108 |
| REV-05 | Le tag et l'entrée `workflow_dispatch` (texte libre, sans contrainte) sont interpolés dans un corps PowerShell avant exécution, sur un job portant `contents: write` et `GH_TOKEN` | `.github/workflows/release.yml:57,80,128` | vérifié | #109 |
| REV-06 | Un manifeste dont une signature n'a pas de `keyId` fait lever `ArgumentNullException` hors du `try` : tout scan ultérieur meurt. Atteignable par écriture non privilégiée dans `rempart-data/`, que le sceau exclut volontairement | `Updates/ManifestVerifier.cs:84,142` | vérifié | #110 |
| REV-07 | Un pare-feu illisible est indiscernable d'un pare-feu qui bloque : `FirewallState.Readable` vaut `true` par défaut et aucun chemin d'échec live ne produit `Unread`. Un binaire non signé exposé sur `0.0.0.0` devient `Benign`, avec l'affirmation « bloqué en entrée » | `Windows/LiveFirewallProvider.cs:40` | rapporté | #111 |
| REV-08 | `--fetch-pac` : `NotSupportedException` (URL `file://` ou `ftp://`, valeur WinINET légitime) échappe au filtre du `catch` et détruit un scan déjà complet avant sa sérialisation | `Pac/LivePacFetcher.cs:43` | vérifié | #112 |

### Moyenne

| Réf | Trouvaille | Fichier | État | Issue |
|---|---|---|---|---|
| REV-09 | Aucune garde ne confronte les 16 collecteurs de constats enregistrés à la main aux 16 présents sur disque. Un collecteur oublié ne remonte rien et tous les goldens restent identiques — moitié non traitée de D2 | `Engine/ScanEngine.cs:71` | vérifié | #113 |
| REV-10 | Une énumération de tâches planifiées partiellement refusée est rendue avec le statut `Found` : quatre branches abandonnent des données sans trace. Le résumé de classe promet l'inverse | `Windows/Tasks/LiveScheduledTaskProvider.cs:119` | rapporté | #114 |
| REV-11 | L'énumération du registre rend vide sur refus d'accès, sans statut. Un déni de lecture posé sur une clé `Run` ou sur `HKCU\…\CLSID` produit « aucun autorun » / aucun détournement COM | `Windows/LiveRegistryProvider.cs:81,97` | rapporté | #115 |
| REV-12 | Le fichier `hosts` illisible est indiscernable d'un fichier vide — le déni de lecture est précisément la technique qui protège une redirection | `Windows/LiveHostsFileProvider.cs:22` | rapporté | #115 |
| REV-13 | Le code de sortie ne consulte que `Collectors` et `Verdicts` : un refus remonté par un collecteur de **constats** n'atteint jamais `ForScan`. Trois surfaces refusées peuvent rendre `0` | `Cli/ExitCodes.cs:122` | rapporté | #116 |
| REV-14 | Un fichier de règles multi-document perd silencieusement tout ce qui suit le premier `---` : seul `Documents[0]` est lu. Vérifié en exécutant le chargeur — une règle `critical` disparaît et le chargement se déclare réussi | `Rules/RuleLoader.cs:37` | vérifié | #117 |
| REV-15 | La section des constats du rapport Markdown interpole cinq valeurs machine sans `Cell()`, là où le reste du fichier l'applique treize fois : rupture de span et lien cliquable | `Reports/MarkdownReport.cs:206` | vérifié | #118 |
| REV-16 | Quatre champs `*Diagnostic` sur cinq échappent à l'anonymisation ; celui des extensions porte le sel de profil Firefox que l'anonymiseur masque ailleurs. Le cinquième a été corrigé pour cette raison exacte | `Snapshots/Anonymiser.cs` | rapporté | #107 |
| REV-17 | Seul l'interpréteur est jugé, pas sa charge utile : `powershell.exe -enc <base64>` en persistance rend `Benign`, zéro raison, et disparaît de la console, du HTML et du Markdown | `Findings/AutorunsCollector.cs:192` | rapporté | #119 |
| REV-18 | Rien n'exige qu'une étiquette pointe un commit ayant passé la CI : `ci.yml` ne se déclenche pas sur les tags et le job de release n'a ni `needs:` ni `dotnet test` | `.github/workflows/` | vérifié | #120 |
| REV-19 | La suite de tests porte une seconde copie du câblage de rejeu, déjà dérivée d'un provider (`dynamicPortRange` absent), alors que `ProviderSets.cs` affirme cette copie éliminée | `tests/…/CompromiseMarkersTests.cs:166` | vérifié | #121 |
| REV-20 | `NetUserEnum` : sur `ERROR_MORE_DATA` le buffer est alloué mais `NetApiBufferFree` n'est jamais appelé, et trois faits de compte ne sont jamais écrits — une lecture tronquée se présente en fait manquant | `Windows/LiveSecurityPolicyProvider.cs:171,239` | rapporté | #122 |
| REV-21 | Aucun délai maximal sur l'énumération WMI (`WbemInfiniteTimeout`) là où DISM et netsh en ont un : un provider bloqué fige le scan sans sortie | `Windows/Wmi/LiveWmiProvider.cs:27,121` | rapporté | #122 |
| REV-22 | `ci.yml` n'a aucun bloc `permissions:` : les cinq jobs tournent avec le jeton par défaut du dépôt là où `contents: read` suffit | `.github/workflows/ci.yml` | vérifié | #120 |

### Basse

| Réf | Trouvaille | Fichier | État | Issue |
|---|---|---|---|---|
| REV-23 | `Copy-Item "README.md","LICENSE" -ErrorAction SilentlyContinue` : la clé peut être publiée sans licence, en vert. `verify.ps1` fait l'inverse (`throw`) et le test de parité ne compare que les listes | `.github/workflows/release.yml:86` | rapporté | #120 |
| REV-24 | Le nom `-unsealed` et l'absence de clé d'éditeur en CI — les deux affirmations les plus fortes de SECURITY.md — ne sont tenues par aucune garde | `.github/workflows/release.yml` | rapporté | #120 |
| REV-25 | Dans un dossier mixte, les fichiers `.yml` sont ignorés sans un mot ; le cas « que des `.yml` » est correctement rattrapé | `Rules/RuleCatalog.cs:161` | vérifié | #117 |
| REV-26 | `verify.ps1` inscrit `ok` pour actionlint absent, indiscernable d'une vraie réussite dans le tableau final | `scripts/verify.ps1:104` | rapporté | #120 |
| REV-27 | Un test sans assertion (`_ = info.IsDomainJoined;`) et un test Windows qui se saute en silence, là où tous les autres l'annoncent | `tests/Rempart.Tests.Windows/` | rapporté | #121 |
| REV-28 | La garde des filtres de couverture énumère `tests/` récursivement : déplacer le test d'anonymisation vers le projet Windows la laisse verte pendant que le job ne filtre plus rien | `tests/…/CoverageSettingsTests.cs:224` | rapporté | #121 |
| REV-29 | Les goldens absents se réécrivent et passent au second lancement ; atténué (fichiers suivis en git, CI sans référence non commitée) | `tests/…/FixtureReplayTests.cs:95` | rapporté | #121 |
| REV-30 | `WinVerifyTrust` fait de la révocation en ligne sans `WTD_CACHE_ONLY_URL_RETRIEVAL` ni budget, une fois par binaire remonté : sortie réseau hors du régime opt-in d'ADR-001 D9 | `Windows/LiveSignatureProvider.cs:123` | rapporté | #122 |
| REV-31 | Aucun fichier de verrou NuGet et aucun `NuGet.config` : le graphe résolu n'est jamais vérifié par empreinte et la liste des sources vient de la machine | racine | rapporté | #120 |
| REV-32 | Une extension Chromium dépaquetée dont le chemin est absolu est écartée avant que sa provenance ne soit lue — repose sur ce que Chrome écrit réellement pour `location: 4`, invérifiable depuis le dépôt | `Browsers/ChromiumExtensions.cs:175` | à confirmer | #123 |
| REV-33 | `DET-NOTES-AMONT` annonce « 113 des 116 » notes d'impact ; le compte réel du catalogue est **120 sur 123**. Trois autres documents et le jalon GitHub sont justes | `docs/DEBT.md:107` | vérifié | #124 |

---

## Ce que la correction a fait apparaître

Chaque correctif a été relu de façon adverse, avec pour consigne de le **réfuter**. Aucun n'a
été cassé, mais six voisins du même motif ont été trouvés en chemin. Ils n'appartiennent à
aucune ligne ci-dessus. **Tous ont été corrigés depuis**, une PR par issue :

| Fichier | Voisin | Issue | Corrigé par |
|---|---|---|---|
| `Windows/LiveServiceStateProvider.cs:56,67,78` | Tout code Win32 autre que « service inexistant » devient `AccessDenied` — la forme exacte que REV-04 condamne, une interface plus loin. Le champ qui l'aurait distingué existe et n'est jamais écrit | #147 | #154 |
| `Reputation/FindingEnrichment.cs:52` | Le jumeau structurel de REV-08 : `--virustotal` enrichit un scan déjà terminé, et deux filtres de `catch` tenus à la main décident s'il le détruit | #148 | #157 |
| `Updates/DriverBlocklist.cs:48`, `Updates/BloatwareCatalog.cs:227` | Un élément `null` dans le tableau JSON lève `NullReferenceException` — REV-06 un cran plus bas, dans les lecteurs que son correctif croyait couvrir | #149 | #155 |
| `Updates/UpdateStore.cs:100,129` | `File.ReadAllText` et `ReadAllBytes` sans `try` sur un fichier de `rempart-data/`, que le sceau exclut : même origine, même conséquence que REV-06 | #150 | #156 |
| `Engine/ScanEngine.cs:60`, `Cli/CliHost.cs:89` | La moitié « collecteurs de champs » de REV-09 : deux tables écrites à la main que rien ne confronte au disque. Mesuré : désenregistrer `--analyze-store` laisse la suite verte | #151 | #158 |
| `Wmi/LiveWmiProvider.cs`, `Drain` | Un HRESULT négatif rendu par `IEnumWbemClassObject::Next` termine la boucle en silence : une énumération tronquée se présente en `Found` | #152 | #153 |

---

## Le second tour, et pourquoi il s'arrête là

Les six correctifs ci-dessus ont été relus de la même manière. **Trois ont été réfutés** —
la garde de #158 ne mordait sur aucune des deux mutations qu'elle prétendait tenir, #157
laissait la construction de sa source hors de toute garde, et #156 laissait le même défaut
trois lignes sous celle qu'il venait de poser. Les trois ont été réparés, et les mutations
rejouées à la main sur la branche fusionnée.

Un correctif a introduit sa propre régression, attrapée par sa relecture : #154 faisait
d'un échec de lecture de service un `Fail` critique contre la machine, là où l'ancien code
n'en faisait qu'un refus. Un échec traduit en refus était le défaut ; un échec traduit en
verdict est pire.

Ce second tour a produit six trouvailles de plus, ouvertes et non corrigées : #159 à #164.
Elles ne sont pas de la même nature que les précédentes, et c'est la raison de s'arrêter
là. La plus grosse — **#159** — dit que le canal de statut posé par cette revue n'a toujours
pas de mot pour « un échec que l'élévation ne répare pas » : le rapport titre les deux
« accès refusé », `AuditGap` n'a que `Refused` et `Broken`, et le code de sortie rend `3`.
Le corriger demande de traverser trois rendus, leurs goldens, une énumération et le code de
sortie. Ce n'est plus la correction d'un audit, c'est la moitié suivante du travail.

---

## Questions de conception, pas défauts

À trancher plutôt qu'à corriger.

- **`rempart diff` ne rend `4` que sur `Pass → Fail`** (`Cli/ExitCodes.cs:137`). Une machine qui
  rejoint un domaine et acquiert quinze contrôles de stratégie en échec (`NotApplicable → Fail`)
  sort `0`, tout comme un contrôle passé hors de vue (`Pass → Unknown`). Le classement des
  transitions est juste et argumenté ; c'est le contrat rendu à un ordonnanceur qui n'est pas
  tranché. À verser à l'issue #102, qui pose exactement cette question.
- **La pondération de sévérité ne plafonne pas.** Une machine échouant un seul contrôle
  `critical` et réussissant tout le reste marque 97 %. C'est la non-linéarité voulue ; à savoir,
  atténué en pratique parce que le score n'est jamais affiché seul.
- **Le chemin COM du planificateur de tâches n'a aucun test machine** — cinq vtables dérivées
  d'`IDispatch`, la plus risquée du dépôt, couverte seulement par `diagnose-tasks` lancé à la
  main.

---

## Méthode et limites

Six relectures menées en parallèle, chacune tenue de tracer le code plutôt que de reconnaître
un motif, et de chercher d'abord à **réfuter** sa propre trouvaille — plusieurs candidates ont
été écartées ainsi, notamment sur les cinq lectures à canal de statut, le calcul du score et
l'ordre des slots vtable. Les trouvailles marquées *vérifié* ont été recontrôlées ligne à
ligne ; REV-14 l'a été en exécutant le chargeur de règles sur un cas construit.

Trois limites à consigner. Aucune exécution n'a eu lieu sur une machine compromise réelle, donc
les faux négatifs sont établis par lecture du jugement et non par observation. REV-32 repose sur
une prémisse qu'aucune lecture du dépôt ne peut trancher. Et la revue n'a pas cherché les défauts
de rendu ni d'ergonomie : elle a porté sur ce que l'outil affirme et sur ce qu'il expose.
