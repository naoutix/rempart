# Plan d'attaque — Rempart

Chaque lot se termine par un livrable **vérifiable sur une machine réelle**.
Pas de lot qui ne produise que de l'infrastructure invisible.

La dette technique connue est suivie à part, dans [DEBT.md](DEBT.md).

## Où on en est

| | |
|---|---|
| Dernière version | **1.2.0**, publiée le 2026-08-02 |
| Ce qui est livré | L'audit en lecture seule. v1 close le 2026-07-28 — huit lots, les deux critères de sortie réglés |
| Ce qui vient | La suite du flux **1.x** — mode appairé, règles TLS/IPv6, notes vérifiées, couche image |
| Ce qui attend une décision | La **2.0**, celle où l'outil écrit sur la machine |

Ce qui a changé entre deux versions est dans [CHANGELOG.md](../CHANGELOG.md), pas ici. Ce
document garde les jalons **et surtout ce qui a été reporté, avec la raison** — c'est la partie
qu'aucun autre fichier ne porte, et la seule qu'on relit.

## Langue de la documentation

Décision du 2026-07-23, sur retour de relecture externe : la vitrine du dépôt passe
en anglais — README, CONTRIBUTING, ARCHITECTURE, BUILD, commentaires de code et
messages de commit. Les archives internes datées (ADR, specs de conception, cette
feuille de route, DEBT) restent en français. Les textes des règles — titres et
rationales, c'est-à-dire la sortie de `scan` et `explain` — restent en français
tant que l'outil vise un public francophone.

- [ ] Traduire les 82 règles YAML et la sortie CLI en anglais — à trancher le jour
      où l'outil vise un public plus large qu'aujourd'hui.

---

## v1 — Audit en lecture seule

**État au 2026-07-28 : v1 est close.** Les huit lots M0 → M7 sont livrés, **les deux critères
de sortie sont réglés**, et la version empaquetée est **v1.0.0** (voir
[CHANGELOG.md](../CHANGELOG.md)). Deux candidates l'ont précédée : rc.1, construite et jamais
publiée, et rc.2, publiée — et c'est en la faisant tourner ailleurs que le dernier critère est
tombé. La **1.1.0** a suivi le 2026-08-01 ; ce qu'elle ajoute est plus bas, sous 1.x.

**M6 — atteint le 2026-07-28, et à la lettre.** L'archive **scellée** de rc.2, celle qui ne
contient plus de `rules/`, a tourné sur une machine tierce sans rien installer. Ce qui est
observé, et non déduit : une autre build de Windows (25H2 contre 26200 sur le poste de
développement), un instantané anonymisé qui se rejoue ici **intégralement** — 82 règles
évaluées, aucune illisible, aucun collecteur refusé, code de sortie **0**, le premier sur une
machine réelle. 346 logiciels, 279 tâches, 137 constats à examiner.

**M5 — découpé le 2026-07-28** plutôt qu'attendu ([ADR-006](adr/ADR-006-catalogue-bloatware-importe.md),
D21) : il posait une question de données sous la forme d'un test, et sa partie mécanisme était
déjà démontrée. La couverture du catalogue est passée de 5 à **123 entrées** dans la foulée.

Ce qui reste ouvert n'est plus un critère de sortie, et demande des machines, pas du code :

- **TLS/SCHANNEL** (M2b) et **IPv6** (M4) — reportés faute de pouvoir observer les défauts
  effectifs sur plusieurs builds de Windows. Un `windowsDefault` deviné ferait crier au
  loup, ce que le projet refuse par principe. **La collecte IPv6, elle, est faite** depuis
  le 2026-07-26 (DET-IPV6) : seules les règles de durcissement restent reportées. La capture
  de la seconde machine est le premier point de comparaison utilisable : 45 règles en échec
  là-bas contre 44 ici, aucune inévaluable — cohérent, sans que cela **prouve** un défaut.
- **Notes d'impact du catalogue** : 120 des 123 sont décrites en amont et non vérifiées sur
  machine (DET-NOTES-AMONT). Chaque logiciel réellement observé en fait tomber une.

Le lecteur DISM, longtemps le point aveugle de M6, est **éprouvé depuis le 2026-07-26** :
les libellés tirés de la documentation se sont révélés justes face à une exécution élevée
réelle (DET-DISM, fermée).

### M0 · Socle — ✅ terminé

- [x] `git init`, solution .NET 10, publication AOT vérifiée — **2,6 Mo**, testé isolé
- [x] `IRegistryProvider` / `ISystemInfoProvider` + implémentations Live et Snapshot
- [x] Collecteur `Inventory` (modèle, OS, build, TPM, Secure Boot, UEFI, uptime)
- [x] `rempart capture` produit un instantané rejouable, anonymisé par défaut
- [x] Fixtures synthétiques versionnées + captures réelles hors dépôt
- [x] 34 tests, sans machine Windows ni VM
- [x] CI écrite et **vérifiée** — les 4 jobs passent, `publish-aot` produit 4,1 Mo
      sur runner Windows, identique au build local
- [x] `IWmiProvider` — reporté en M2 puis **résolu en M2b** : accessible par interop COM
      générée à la compilation, `System.Management` reste hors de portée sous AOT (voir M2b)

**Critère de sortie reformulé.** Le critère initial — « scan live identique au rejeu » —
est intenable : l'uptime change entre les deux et l'anonymisation modifie le hostname
par conception. L'invariant retenu est *rejouer une fixture donne toujours la même sortie
qu'une référence versionnée*. `FieldSemantics` distingue les champs volatils et
identifiants ; `rempart diff` (M7) s'appuiera sur la même distinction.

**Trouvé en chemin.** `ProductName` annonce « Windows 10 » sur tout Windows 11 —
Microsoft ne l'a jamais corrigé. `os.name` dérive du numéro de build, faute de quoi
toute règle conditionnée à la version porterait sur une valeur fausse.

**Corrigé le 2026-08-03** (#226) : la dérivation ne vaut que pour une installation
**cliente**. La build 26100 appartient à Windows 11 24H2 comme à Windows Server 2025 ;
le numéro seul ne peut donc pas les séparer, et `InstallationType` — déjà lu — le fait.
Sur une édition Serveur la valeur du registre est juste, et c'est elle qui est rendue.

### M1 · Moteur de règles — ✅ terminé

- [x] Schéma de règle + chargeur strict, validation au chargement
- [x] Types de check : `registry`, `registryKey` — `service` et `policy` en M2
- [x] Scoring par domaine et global, mappé CIS / Essential Eight
- [x] **Test de propriété (D7)** : aucune règle ne cible la liste noire
- [x] 12 contrôles réels de bout en bout
- [x] 4 fixtures synthétiques : durcie, défaut Windows, ancienne, accès restreint
- [x] 85 tests

**Fait :** ajouter un contrôle ne demande que d'éditer un YAML.

**La décision de conception du lot.** Le champ `windowsDefault` est obligatoire pour
tout opérateur de comparaison. Sur le registre Windows une clé absente est le cas
courant, et le comportement effectif dépend d'un défaut documenté — souvent l'état
souhaité. La première version traitait toute absence comme un échec et remontait trois
alertes `CRITICAL` fausses sur une machine saine. Un outil qui crie au loup cesse d'être lu.

**Trouvé en chemin.** `RunAsPPL` vaut `1` (avec verrou UEFI) ou `2` (sans) ; exiger
l'égalité rejetait une machine correctement configurée. D'où l'opérateur `atLeast`.

**Écart à l'[ADR-001](adr/ADR-001-stack-et-perimetre.md).** YamlDotNet est utilisé par son API bas niveau (`YamlStream`),
sans réflexion donc compatible AOT, avec un mapping écrit à la main. Le générateur de
source officiel n'est pas publié sur NuGet — seul un paquet tiers existe, écarté sur un
outil de sécurité. Bénéfice collatéral : des erreurs situées, avec fichier et règle.

### M2a · Posture de sécurité, contrôles registre — ✅ terminé

- [x] 48 contrôles répartis sur 8 domaines
- [x] Les 17 règles ASR applicables aux postes de travail, GUID vérifiés sur la
      référence Microsoft du 2026-07-02
- [x] Defender, pare-feu (3 profils), journalisation, durcissement réseau, confidentialité
- [x] Fixtures régénérées : durcie (100 %), défaut Windows (46 %), accès restreint
- [x] **Test : toute règle livrée est satisfiable** — la fixture durcie atteint 100 %,
      donc aucune règle ne produit d'échec permanent incorrigible

**Deux règles retirées après confrontation au réel**, plutôt que livrées sur une
supposition. La raison est consignée dans le fichier concerné, à l'emplacement où la
règle se trouvait.

- `WIN-DEF-009` protection contre les altérations : la valeur de registre vaut 1 là où
  la documentation laisse attendre 5. Sémantique non fiable → à reprendre par l'API
  Defender en M2b.
- `WIN-FW-006` fusion des règles locales : n'a de sens que sur une machine pilotée par
  stratégie de groupe. Sur un poste autonome, la « correction » supprimerait toutes les
  règles créées par les applications.

**Le manque révélé : les règles n'ont pas de condition d'applicabilité.** Plusieurs
contrôles ne valent que dans un contexte donné — machine jointe à un domaine, RDP
activé, matériel Copilot+. Sans `appliesWhen`, ils produisent du bruit ailleurs.
C'est le premier chantier de M2b, avant même les nouveaux providers.

### M2b · Nouveaux providers et applicabilité — ✅ terminé

- [x] `appliesWhen` : conditionner une règle au contexte de la machine
- [x] `WIN-FW-006` et `WIN-RDP-002` rétablies, désormais conditionnées
- [x] Check `service` — état et mode de démarrage, via `advapi32`, sans WMI
- [x] Comptes locaux et politique de mot de passe — via `netapi32`, sans WMI
- [x] **Question WMI/AOT tranchée** : accessible par interop COM générée à la
      compilation. `System.Management` reste hors de portée, mais les interfaces
      COM de WMI passent, sans réflexion ni avertissement de trim.
- [x] Provider WMI câblé au moteur — type de contrôle `wmi`
- [x] BitLocker : `WIN-ENC-001`, état effectif du chiffrement
- [x] Credential Guard, VBS, HVCI — au registre, aucun blocage
- [x] **État effectif de Defender par WMI** — `WIN-DEF-009` rétablie, plus la
      protection en temps réel effective et l'âge des signatures. Noms de propriétés
      relevés sur une machine élevée, pas déduits de la documentation : c'est ce qui
      avait manqué à la première tentative.
- [ ] TLS — reporté : les valeurs par défaut de SCHANNEL varient selon la build de
      Windows, et un `windowsDefault` deviné produirait de faux constats. Demande une
      vérification sur plusieurs machines.

### M3 · Persistance & processus — ✅ terminé

Toutes les surfaces livrées : démarrages, WMI, tâches, pilotes (avec LOLDrivers par le
canal signé), processus courants, Winlogon/AppInit, LSA, COM hijacking, chemins de
service non-quotés, et l'enrichissement VirusTotal opt-in. La détection MSIX, ajoutée en
cours, épargne les applications du Store à tous les collecteurs.

**Le modèle a dû s'étendre.** Une règle compare une valeur à une attente ; la
persistance ne s'exprime pas ainsi. Dix-sept programmes au démarrage dont trois non
signés ne se résument pas à « 3, attendu 0 » — ce qui compte, ce sont lesquels.

D'où un troisième concept à côté des collecteurs et des verdicts : les **constats**,
éléments énumérés portant chacun son propre jugement. Les deux ne se mélangent pas
dans le score : une configuration à 94 % ne doit pas masquer un binaire non signé
lancé au démarrage.

- [x] Modèle `Finding` — famille, source, cible, gravité, raisons, détails
- [x] `ISignatureProvider` — Authenticode par `WinVerifyTrust`, SHA-256
- [x] Collecteur des démarrages automatiques — clés Run et RunOnce, HKLM et HKCU,
      plus la vue 32 bits. Signature vérifiée par certificat embarqué **et par catalogue**.
- [x] Abonnements WMI permanents — consommateurs et filtres, filtres livrés avec
      Windows écartés du bruit
- [x] Dossiers Startup — machine et utilisateur. Les raccourcis sont énumérés sans
      être jugés : leur cible compte, et la résoudre demande de lire le format .lnk
- [x] Tâches planifiées — cinq interfaces COM, dérivées d'`IDispatch` donc décalées de
      quatre emplacements de table virtuelle. Ordre repris de `taskschd.h`, pas de
      mémoire. La définition est lue en XML via `get_Xml` plutôt qu'en descendant la
      chaîne `ITaskDefinition` : une occasion de se tromper d'emplacement au lieu de dix.
      Couvert en CI par `rempart diagnose-tasks` contre le binaire AOT — même garde-fou
      que WMI, posé avant que le problème ne se pose et non après
- [x] Pilotes chargés — énumérés par `Win32_SystemDriver` (WMI), et non par
      `EnumDeviceDrivers` qui, hors élévation, rend le nombre de pilotes mais met leurs
      adresses noyau à zéro (protection KASLR) — un succès qui ment. Chaque pilote est
      jugé sur sa signature, échelle commune aux autres persistances : un pilote noyau
      non signé est le premier signe d'un chargement forcé. Vérifié en direct : 190
      pilotes, 190 signés, zéro faux positif
- [x] Comparaison à LOLDrivers — bout en bout. `fetch-loldrivers` télécharge la liste
      officielle et la met au format à signer ; l'éditeur signe (lui seul) ; le canal
      type le jeu de données (`drivers`), le magasin le route, et un pilote chargé dont
      l'empreinte y figure ressort suspect même signé. Éprouvé sur du réel : 2003
      empreintes téléchargées, signées par la vraie clé, appliquées, aucun des 190
      pilotes chargés de la machine de test n'y figurant

**Deux transitoires à traiter avant `rempart diff` (M7).** Les entrées `RunOnce` sont
consommées puis supprimées par Windows : deux scans successifs montrent un écart sans
qu'il se soit rien passé. Même question pour les tâches planifiées à déclenchement
unique.

Surfaces visées : processus courants (chemin, signature Authenticode, parent, ligne de
commande), services, tâches planifiées, clés Run, dossiers Startup, **abonnements WMI
permanents**, COM hijacking, Winlogon/LSA providers, AppInit_DLLs, pilotes chargés. Les
cinq en gras et apparentées sont faites ; les autres restent.

- [x] Hash SHA-256 et vérification de signature de chaque binaire remonté — `SignatureLadder`,
      appliqué à chaque constat (démarrage, tâche, pilote). Pas un scan de tous les
      binaires du disque : la signature de ce qu'on énumère
- [x] Pilotes vulnérables connus (LOLDrivers) — voir la liste ci-dessus, bout en bout
- [x] Collecteur des processus courants — chemin, parent, ligne de commande, signature,
      énumérés par `Win32_Process` (WMI). Regroupés par exécutable (une douzaine de
      `svchost.exe` = un constat), jugés par `SignatureLadder`. Vérifié en direct : 60
      exécutables, 6 non signés remontés — tous de vrais binaires de dev, dont `rempart`
      lui-même ; zéro faux positif
- [x] Winlogon (Userinit, Shell) et AppInit_DLLs — points d'extension au démarrage et à
      l'injection, jugés par `SignatureLadder` comme le reste. Défaut connu par
      emplacement ; un ajout à Userinit est signalé même signé, une DLL AppInit l'est par
      principe. Vérifié en direct : deux constats bénins, zéro faux positif après avoir
      résolu `explorer.exe` vers le dossier Windows et non System32
- [x] Détection des chemins de service non-quotés — via `Win32_Service.PathName` (WMI).
      Un chemin non quoté avec un espace laisse Windows résoudre des préfixes avant le vrai
      fichier ; correction : des guillemets. Notable, pas suspect — l'exploitabilité
      demande un dossier intermédiaire inscriptible, pas encore vérifié. Sur la machine de
      test : 291 services, zéro non quoté (confirmé par PowerShell)
- [x] LSA — paquets d'authentification, de securite (SSP) et de notification, lus en
      `REG_MULTI_SZ` sous `Lsa` et `Lsa\OSConfig`, juges par `SignatureLadder`. Le
      marqueur de liste vide `""` de Windows est ecarte, un acces refuse est dit et non
      tu. Verifie en direct : 2 paquets, tous benins
- [x] COM hijacking — enregistrements COM cote utilisateur (HKCU\Software\Classes\CLSID),
      qui priment sur le composant systeme sans droits d'''administrateur. A demande une
      capacite d'''enumeration de sous-cles au fournisseur de registre. Juge par
      SignatureLadder ; plancher Notable car l'''emplacement inscriptible fait le vecteur.
      Deux faux positifs corriges en verifiant : extraction de l'''exe d'''un LocalServer32
      (chemin quote + args), et reconnaissance MSIX -- un binaire WindowsApps est signe par
      son paquet, pas au niveau fichier, et ne doit pas passer pour suspect (correction
      partagee par tous les collecteurs). Sur la machine de test : 2 COM utilisateur
      (Adobe, Paint), Notable, aucun suspect
- [x] Enrichissement VirusTotal **opt-in explicite** (D9) — `--virustotal-key` (ou
      `REMPART_VT_KEY`), le seul appel réseau du scan, jamais par défaut ni en rejeu.
      Consulte l'API v3 pour les constats signalés porteurs d'une empreinte ; une
      détection hisse à suspect, « inconnu » ne rassure pas. Clé dans l'en-tête, pas
      l'URL. Chaque code de réponse a sa lecture, aucune ne se déguise en « sain »

**Fait quand** un binaire non signé posé en persistance est remonté sur une VM de test —
atteint pour les surfaces livrées ; le volet processus rouvre le lot.

### M4 · Réseau & DNS — ✅ terminé
Interfaces, DNS configurés, **test actif DoH/DoT avec mesure de latence**, fichier hosts,
proxy et PAC, profils Wi-Fi, IPv6, NetBIOS, mDNS.

Ports en écoute enrichis : adresse de bind (`127.0.0.1` vs `0.0.0.0` — la distinction
qui compte), processus propriétaire et signature, service associé, **règle pare-feu
correspondante**, réputation du port.

- [x] `GetExtendedTcpTable` / `UdpTable` en P-Invoke — collecteur `listening-port`,
      TCP en écoute et UDP, adresse de bind conservée. Le propriétaire est résolu par
      son PID vers le chemin du binaire, puis jugé sur la même échelle de signature que
      les processus et les pilotes. Un binaire non signé exposé sur `0.0.0.0` est
      suspect ; en écoute locale il ne l'est pas — le collecteur de processus s'en
      charge déjà. Vérifié sur machine réelle : 47 ports, zéro faux positif.
- [x] Règle croisée : écoute exposée **ET** autorisée en entrée sur le profil Public →
      relevée. Le pare-feu est lu depuis le registre (règles locales + stratégie de
      groupe), chaque règle analysée, et l'atteignabilité d'un port croisée avec le
      binaire propriétaire — un blocage l'emporte sur une autorisation, le défaut entrant
      de Windows bloque. Non signé et atteignable → suspect ; signé et atteignable →
      notable ; ouvert mais bloqué → bénin. Vérifié sur machine réelle : sur 44 points
      d'écoute, seuls 2 sont réellement joignables (DNS, mDNS), là où le compte brut en
      donnait 39 — les règles d'app empaquetées ouvraient tout à tort.
- [x] Résolveurs DNS et fichier `hosts` — deux collecteurs. Le DNS distingue le résolveur
      reçu du DHCP (inventorié) du résolveur posé statiquement : un statique non reconnu,
      ni résolveur public connu ni boucle locale, est relevé — c'est le levier d'un
      détournement. Le fichier `hosts` sépare la redirection (domaine vers une adresse
      routable, suspect s'il vise une mise à jour ou une authentification) du blocage (vers
      une adresse nulle, agrégé, suspect s'il neutralise une mise à jour). Vérifié sur
      machine réelle : DNS en DHCP inventorié, `hosts` par défaut muet.
- [x] Test actif DoH/DoT (`--probe-dns`) — enrichissement opt-in, jamais par défaut ni en
      rejeu. Un même paquet DNS wire sert DoT (socket TLS/853) et DoH (HTTPS `/dns-query`,
      HTTP/2 préféré) ; latence mesurée (médiane de 3 échantillons) vers Cloudflare, Google
      et Quad9. Le constat « DNS chiffré bloqué » entre dans les findings ; la
      recommandation du plus rapide reste **hors du score**, clairement étiquetée comme un
      avis. Vérifié sur réseau réel : DoH 3/3, DoT 2/3 (un 853 filtré par le réseau),
      recommandation cohérente.
- [x] Proxy et PAC — configuration relevée et jugée, sans appel réseau. Trois portées :
      WinINET (par utilisateur), proxy imposé par stratégie de groupe, et proxy machine
      WinHTTP (blob binaire décodé, format confronté à un vrai blob). Un PAC http externe
      non imposé ressort suspect (un script en clair, altérable, hébergé hors du contrôle
      de la machine réécrit tout le routage) ; un proxy imposé par GPO est inventorié sans
      alarme, comme un résolveur reçu du DHCP ; un proxy local reste bénin. Le blob WinHTTP
      est lu en hex via `IRegistryProvider`, décodé par une fonction pure Core testable
      sans Windows. Vérifié sur machine réelle : accès direct, zéro faux positif.
- [x] Récupération et analyse opt-in du script PAC (`--fetch-pac`) — récupère par HTTP le
      script référencé par `AutoConfigURL`, en extrait **statiquement** les directives de
      routage (`PROXY`/`SOCKS`/`HTTPS host:port`) sans jamais l'exécuter, et hisse un
      constat proxy à suspect si le PAC route vers un hôte externe. Le second appel réseau
      possible du scan, jamais par défaut ni en rejeu (précédent VirusTotal, D9).
- [x] Profils Wi-Fi enregistrés — chaque profil jugé sur sa sécurité : réseau ouvert (pire
      en connexion automatique, vecteur d'« evil twin »), WEP cassé, WPA/TKIP déprécié,
      WPA2/WPA3 + AES bénin. Lu depuis les fichiers XML de profil
      (`ProgramData\Microsoft\Wlansvc\Profiles`), décodé et rejouable ; le SSID, qui nomme
      un lieu, est haché à l'anonymisation. Vérifié sur machine réelle : 23 profils,
      19 bénins, 4 réseaux ouverts relevés dont 3 en connexion automatique.
- [x] NetBIOS, mDNS, LLMNR — déjà audités par règles : `WIN-NET-001` (NodeType, NetBIOS
      restreint), `WIN-NET-002` (EnableMDNS), `WIN-LEG-003` (EnableMulticast, LLMNR). Les
      trois protocoles de résolution par diffusion, vecteurs d'empoisonnement et de capture
      d'authentification NTLM.
- [x] **Ports en écoute IPv6 collectés** — fait le 2026-07-26. Les tables `AF_INET6` ont
      leur propre forme de ligne : le scope id sépare l'adresse du port et décale tout ce
      qui suit. Vérifié contre `netstat -ano` plutôt que déduit : 18 triplets sur 19
      identiques, l'unique écart étant un port de la plage dynamique — le transitoire
      `éphémère` de M7. Sur la machine de test, 20 points d'écoute IPv6 qui étaient
      jusque-là absents du rapport, dont 16 sur `::`, c'est-à-dire toutes les interfaces.
- [ ] Règles de durcissement IPv6 — **reporté**, même raison que TLS/SCHANNEL (M2b), et
      distinct de la collecte ci-dessus qui est faite. Le durcissement des
      technologies de transition (Teredo, 6to4, ISATAP) est piloté par une stratégie
      absente par défaut (`…\TCPIP\v6Transition`), dont l'état effectif par défaut varie
      selon la build de Windows — Teredo est par exemple déjà désactivé par défaut sur un
      client moderne. Un `windowsDefault` deviné ferait échouer toute machine non
      explicitement configurée alors qu'elle est déjà sûre : c'est crier au loup. À
      reprendre après vérification sur plusieurs machines. IPv6 lui-même n'est pas visé :
      Microsoft déconseille de le désactiver, et une règle l'exigeant serait un faux
      positif contraire au principe du projet.

**Fait quand** un port ouvert mais bloqué par le pare-feu n'est pas classé au même
niveau qu'un port réellement exposé. ✅ Le critère est atteint : SMB (445) et RPC (135),
ouverts mais bloqués en Public, retombent en bénin ; seuls les services qu'une règle
active laisse entrer sont relevés.

### M5 · Logiciels & bloatware — ✅ terminé
Inventaire (MSI, Appx, winget, Chocolatey, portables), extensions navigateur avec
leurs permissions, catalogue bloatware classé par risque.

Découpé en trois sous-lots : **M5a** inventaire, **M5b** catalogue bloatware,
**M5c** extensions navigateur — tous trois livrés.

- [x] **M5a — inventaire logiciel.** Collecteur `software` sur quatre sources
      autoritatives : Uninstall (registre, 3 racines — updates et composants système
      écartés), Appx/MSIX (registre), App Paths, Chocolatey (système de fichiers). winget
      apparaît déjà dans Uninstall/Appx ; les portables purs ne sont pas énumérables de
      façon fiable (documenté, pas contourné par une heuristique bruyante). Constats
      bénins, rejouables ; M5b les escaladera par enrichissement. Vérifié sur machine
      réelle : 219 logiciels.
- [x] Distinction **provisionné vs installé par utilisateur** (D6) — via M5a
- [x] Champ `survives_feature_update` renseigné — via M5a ; un paquet Appx provisionné
      revient après une mise à jour de fonctionnalité (6 relevés sur la machine de test)
- [x] **M5b — catalogue bloatware** : dataset signé (type `bloatware`, canal [ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md))
      croisé avec l'inventaire, note d'impact obligatoire par entrée. Vérifié sur machine
      réelle : socle de 5 entrées, 3 installées (Xbox Gaming Overlay, Xbox App, Groove
      Musique) et confirmées via `Get-AppxPackage` — PFN exacts, aucune correction
      nécessaire ; escalade en Notable observée pour ces trois avec `bloatware`/`catalogue`
      renseignés, zéro faux positif sur le reste de l'inventaire. Les 2 entrées restantes
      (météo Bing, Clipchamp) sont absentes de `Get-AppxPackage` sur cette machine — mais y
      ont quand même escaladé en Notable, via une entrée-ressource orpheline du registre
      Appx ; elles restent valables pour d'autres machines où le paquet est réellement
      présent. **Ce faux positif est corrigé depuis** (DET-APPX-FAUXPOS) : une entrée dont
      le segment ressource commence par `split.` n'est plus prise pour une installation.
- [x] Canal de rafraîchissement du catalogue — **déjà tranché** : le canal signé d'ADR-002,
      comme LOLDrivers ([ADR-001](adr/ADR-001-stack-et-perimetre.md) le renvoyait à [ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md))
- [x] **M5c — extensions navigateur** avec leurs permissions effectives. Parseurs purs
      (Chromium : manifeste + `Secure Preferences` ; Firefox : `extensions.json`),
      constat `browser-extension` par extension. La provenance décide du palier :
      sideload (`location` 2/3/4, ou non signée) → Suspicious ; accès large ou
      permission forte (`debugger`, `nativeMessaging`, `proxy`) depuis le magasin →
      Notable — un gestionnaire de mots de passe légitime cumule `<all_urls>` +
      `nativeMessaging`, le marquer Suspicious crierait au loup. Vérifié sur machine
      réelle : 22 extensions (Chrome + 3 profils Edge), noms `__MSG__` résolus,
      composants exclus, états désactivés détectés, zéro faux Suspicious.

**Trouvé en chemin (M5c).** `from_webstore` est inutilisable comme signal de sideload :
sur Edge, les extensions du magasin Microsoft portent `from_webstore: false` — seul
`location` distingue une installation externe. Et `state` n'existe plus dans les
Chromium récents : l'état activé/désactivé se lit dans `disable_reasons`. Les deux
relevés viennent de l'inspection des fichiers réels, pas de la documentation — voir la
spec du 2026-07-24. Firefox : parseur testé sur fixtures fabriquées, à confirmer sur
une machine qui l'a.

**Critère de sortie découpé le 2026-07-28** — voir
[ADR-006](adr/ADR-006-catalogue-bloatware-importe.md), décision D21. Il posait une question de
**données** sous la forme d'un test, et c'est ce qui le rendait infermable : une machine OEM
validerait un constructeur et laisserait aveugle sur tous les autres.

- ✅ **Le mécanisme est éprouvé** : 6 paquets provisionnés relevés, 3 entrées confirmées via
  `Get-AppxPackage` avec les PFN exacts, zéro faux positif sur les 219 logiciels restants.
  Windows provisionne lui-même des paquets — aucune machine OEM n'a jamais été nécessaire pour
  éprouver ça.
- ↪ **La couverture du catalogue sort des critères de sortie de v1** et devient une entrée de
  données vivante : import d'une liste tierce épinglée (D18), puis signalements.

### M6 · Rapport & packaging clé — ✅ terminé
HTML autonome (fichier unique, thème clair/sombre), JSON, Markdown.
Espace récupérable par couche via `AnalyzeComponentStore`, sans rien supprimer.

- [x] Générateur de rapport dans `Rempart.Core/Reports/` — rendu **pur**
      `ScanResult → texte`, donc testable sans Windows ni système de fichiers. HTML
      autonome (un fichier, CSS et script en ligne, aucune ressource externe, thème
      clair/sombre), Markdown pour un ticket, JSON pour la donnée complète.
- [x] `rempart scan --report [dossier]` écrit les trois fichiers dans
      `<dossier>/<machine>-<date>/`, par défaut `reports/` à côté du binaire.
      Deux scans le même jour ne s'écrasent pas : le second prend un suffixe — le
      « avant » d'une correction est la moitié qu'on ne peut pas refaire.
- [x] `rempart report --from <rapport.json>` re-fabrique HTML et Markdown sans
      rescanner, et **ne demande pas Windows**. C'est aussi la brique dont `diff` (M7)
      aura besoin : le JSON est l'artefact complet, les deux autres le résument.
- [x] Layout de la clé : `/rempart.exe`, `/reports/<machine>-<date>/`, et un `/rules/`
      **facultatif**. Un dossier `rules/` posé à côté du binaire est chargé sans option —
      même raisonnement que le magasin de mise à jour, déjà résolu à côté de l'exécutable :
      la clé se branche et tourne. Jamais en silence : l'en-tête nomme le dossier et
      l'empreinte du catalogue change. **Ce dossier est un supplément, jamais une copie des
      règles livrées** : les 82 sont compilées dans le binaire, et un identifiant présent des
      deux côtés est refusé comme une redéfinition. L'archive de release n'en contient donc
      pas — elle en a contenu un, et v1.0.0-rc.2 en est morte (voir CHANGELOG).
- [x] Manifeste d'intégrité — `rempart seal`, **signé par la clé d'éditeur d'[ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md)**.
      Une liste d'empreintes posée à côté des fichiers qu'elle décrit ne protège de
      rien : qui modifie un fichier recalcule la ligne. Rapports et magasin exclus du
      sceau (ils changent à l'usage normal ; le magasin est de toute façon revérifié à
      chaque scan, D13). Un fichier **ajouté** est signalé autant qu'un fichier modifié :
      poser une DLL à côté de l'exécutable est le vecteur, pas éditer ce qui est déjà
      listé.
- [x] Dégradation propre sans droits admin — le rapport s'ouvre sur ce qui le limite
      avant d'afficher le moindre chiffre : scan non élevé, score partiel, collecteur
      dégradé. Un support en lecture seule est nommé comme tel, avec la sortie à prendre.
- [x] Espace récupérable par couche — collecteur `component-store`, en opt-in
      (`--analyze-store`) : la pile de maintenance met des dizaines de secondes à
      répondre et exige l'élévation. Le découpage est le livrable : la part partagée
      avec Windows n'est pas récupérable, et c'est elle qui fait l'essentiel du magasin.
- [x] **Lecteur DISM confronté à une vraie sortie élevée** — fait le 2026-07-26 en console
      administrateur (`rempart diagnose-store --raw`). Les libellés tirés de la
      documentation étaient justes : les 7 correspondent, `Found`, aucune correction. La
      machine a rendu 16,45 Gio réels dont 7,76 partagés avec Windows et 8,68 de
      sauvegardes, 5 paquets récupérables, nettoyage recommandé. Deux détails du lecteur se
      valident enfin sur du réel plutôt qu'en théorie : le découpage au *premier*
      deux-points, parce que la date de dernier nettoyage porte les siens, et `0 bytes`
      écrit avec deux espaces. La sortie est bien anglaise sur un Windows français —
      `/English` est demandé à l'outil pour n'affronter qu'un jeu de libellés.

**Trouvé en chemin.** Les jauges de score étaient plafonnées à 70 % de la cellule :
mesurées dans un navigateur, 67 %, 88 % et 100 % rendaient 136, 142 et 142 pixels. Un
graphe qui fait passer un domaine médiocre pour parfait est pire que pas de graphe. La
barre remplit désormais une piste de largeur fixe, et un test vérifie que sa longueur
est le score.

Deux autres constats. `dism.exe` refuse **même `/?`** sans élévation (code 740, immédiat)
— la dégradation est donc nette, et c'est ce que le collecteur exploite. Et le rejeu de
fixtures ne câblait pas le fournisseur d'extensions de navigateur ajouté en M5c : le
collecteur tournait à vide et la référence figeait « rien trouvé ». C'est la dette D2,
réapparue par une PR ; corrigé ici.

**La décision de conception du lot.** Les notes de provenance — mise à jour appliquée ou
refusée, sceau vérifié ou rompu, règles supplémentaires chargées — sont portées **par
`ScanResult`**, pas passées à côté du rendu. Sans cela, `rempart report --from` aurait
re-fabriqué un rapport amputé de la phrase « la mise à jour a été refusée » : exactement
le silence qu'[ADR-002](adr/ADR-002-mise-a-jour-des-donnees.md) (D14, D17) interdit. Trois notes, trois versions de la même
question que se pose le lecteur avant de comparer deux rapports.

**Le rapport est construit à partir de chaînes choisies par la machine auditée** —
lignes de commande, chemins, noms d'extensions. L'échappement HTML n'y est pas une
politesse : c'est le seul endroit du projet où une erreur de formatage devient une
vulnérabilité, et un test plante du balisage dans chaque champ. Le script en ligne ne
reçoit **aucune donnée** du scan : il filtre des nœuds déjà présents, ce qui supprime la
seconde voie d'injection au lieu de la sécuriser.

**Fait quand** la clé tourne sur une machine tierce sans rien installer. ✅ **Atteint le
2026-07-28** — l'archive scellée de v1.0.0-rc.2, sur une machine que la chaîne d'outils n'a
jamais touchée et sur une autre build de Windows. La capture produite là-bas se rejoue ici
sans un seul collecteur refusé ni une seule règle inévaluable, code de sortie 0. C'est ce
critère qui gardait la 1.0.0, et il ne pouvait pas être éprouvé avant le 2026-07-28 : jusqu'au
correctif du même jour, la clé livrée ne démarrait pas.

### M7 · Flotte — ✅ terminé
`rempart diff a.json b.json`, baseline de référence, page d'agrégation des rapports.

- [x] `rempart diff` — moteur pur `Rempart.Core/Diff/`, alimenté par le JSON de M6 :
      aucune des deux machines n'a besoin d'être là, et la comparaison ne demande pas
      Windows. Trois concepts, trois comparaisons, parce qu'ils ne répondent pas à la
      même question — verdicts par identifiant de règle, constats par ce qu'ils
      désignent, champs d'inventaire en contexte.
- [x] **Un verdict devenu illisible n'est pas un verdict qui échoue.** C'est la
      distinction pour laquelle tout le classement existe : un audit qui perd de vue un
      contrôle appelle une élévation, un contrôle qui tombe appelle une correction. Les
      confondre enterrerait le premier sous le second — et le premier est celui que
      personne ne remarquerait autrement.
- [x] Baseline conventionnelle : `rempart diff <rapport.json>` sans second argument
      compare à `baseline.json` posé à côté du binaire, comme le magasin et `rules/`.
- [x] `rempart index [dossier]` — page de parc autonome, ordonnée par ce qu'il reste à
      faire : score le plus bas d'abord, et un rapport **sans score en tête** — une
      machine qu'on n'a pas pu noter n'est pas une machine saine. Les rapports issus de
      catalogues différents sont signalés : leurs pourcentages ne sont pas sur la même
      échelle.
- [x] Les deux transitoires annoncés en M3 sont traités **à la source** : les
      collecteurs posent une clé de détail, le diff la lit. `RunOnce` d'un côté ; de
      l'autre, la vraie condition n'est pas « déclencheur unique » mais
      `DeleteExpiredTaskAfter` **et** un déclencheur avec date de fin — les deux
      ensemble, seuls Windows supprime la tâche. `ScheduledTask` porte désormais ces
      deux faits bruts, le jugement restant dans Core.

**Trouvé en chemin — un troisième transitoire, que seule l'exécution a révélé.** Deux
scans à quatorze secondes d'écart sur la machine de test différaient de trois sockets UDP
de Chrome, et de rien d'autre. Les ports de la plage dynamique (49152–65535, valeur
relevée par `netsh int ipv4 show dynamicport`) sont renumérotés à chaque ouverture.

Ce n'est pas le même phénomène que `RunOnce` et la distinction compte : une entrée
`RunOnce` qui *apparaît* est une nouvelle — c'est ainsi qu'on fait exécuter du code au
prochain démarrage — alors qu'un port éphémère qui disparaît et un qui apparaît sont le
même fait sous un autre numéro. D'où deux clés distinctes, `transitoire` et `éphémère` :
la première n'excuse que la disparition, la seconde les deux sens. N'excuser qu'un côté
aurait divisé le bruit par deux en laissant le rapport faux.

Le marquage ne s'applique qu'aux constats **déjà jugés bénins** : un binaire non attesté
joignable sur un port haut est une nouvelle à chaque fois. Cette clé fait taire du bruit,
jamais un jugement.

**Fait quand** l'écart de posture entre deux machines est lisible d'un coup d'œil. ✅
Deux scans consécutifs rendent « aucun écart de posture, N mouvements attendus » au lieu
de trois lignes de ports Chrome.

---

### Consolidation post-v1 — ✅ 2026-07-26 → 2026-07-28

Un lot sans nouveau jalon : la première version empaquetée, puis les trois phases du plan
de remédiation de [DEBT.md](DEBT.md). Consigné ici parce que
[CHANGELOG.md](../CHANGELOG.md) renvoie à cette feuille de route pour l'histoire jalon par
jalon, et qu'elle n'en portait aucune trace.

- [x] **v1.0.0-rc.1 construite** le 2026-07-26 — binaire AOT et manifeste d'intégrité signé,
      mis en brouillon par la CI. Le brouillon **n'a jamais été publié**, et rc.2 le remplace
      au lieu de le compléter : les cinq silences fermés depuis changent ce que le rapport
      dit sur les machines précisément les plus difficiles à auditer, et deux lignes de
      commande ne faisaient pas ce qu'elles annonçaient.
- [x] **v1.0.0-rc.2** le 2026-07-28 — le contenu de ce lot empaqueté, soit vingt et un
      commits depuis rc.1. Reste un candidat, et pour l'unique raison qui valait déjà pour
      rc.1 : la clé n'a pas tourné sur une autre machine que celle qui l'a construite.
- [x] **Découpage de la couche CLI**, conçu dans
      [ADR-005](adr/ADR-005-decoupage-de-la-couche-cli.md) et livré en trois étapes.
      `Program.cs` passe de 1 881 lignes non vides à **29** : l'encodage console, un appel à
      `CommandTable`, et le `try`/`catch` qui traduit une exception en code de sortie. Les
      19 commandes sont une classe chacune ; le rendu console, le parsing d'arguments et le
      contrat de sortie vivent dans `Rempart.Core`, donc sous test sur le job Linux —
      `Rempart.Cli` cible `net10.0-windows`, qu'aucun job Linux ne compile.
- [x] **Nouveau code de sortie 5, « audit partiel »** — un scan qui va au bout mais dont
      des règles reviennent `Unknown` ne rend plus 0. Distinct du 3 (droits insuffisants),
      où c'est un *collecteur* qui a été refusé : ici tout a été lu et le score répond pour
      moins de machine qu'il n'en a l'air. `restricted-access` est le cas exact — 100 %,
      quatre contrôles invérifiables, et jusqu'ici un 0 indiscernable, pour un
      ordonnanceur, d'une machine entièrement vérifiée.
- [x] **`diagnose-drivers` et `diagnose-processes`** — même garde-fou que `diagnose-wmi` et
      `diagnose-tasks` : aucune machine allumée ne fait tourner zéro pilote ni zéro
      processus, donc une énumération vide depuis le binaire publié est une panne et non
      une réponse.
- [x] **Quatrième fixture versionnée, `compromised-win11`** — 7 constats `Suspicious` et 3
      `Notable`, chacun apparié à un jumeau bénin que le collecteur doit laisser tranquille.
      Elle a montré de bout en bout ce qui n'avait jamais été vérifié : le score d'une
      machine portant un implant, un port de commande joignable et un DNS détourné est
      **identique** à celui d'une machine simplement non durcie et saine — 52 %, domaine par
      domaine. Voulu, les constats n'entrant pas au score, mais jamais montré avant.
- [x] **Cinq silences fermés**, tous de la même forme : une liste vide était indiscernable
      d'une lecture refusée. Pilotes, processus, extensions de navigateur, ports en écoute,
      dossiers de démarrage portent désormais un statut **à côté** de la liste, jamais à sa
      place — une capture antérieure se relit comme le succès qu'elle était.
- [x] **Couverture instrumentée, sans seuil** — `Rempart.Core` sur le job Linux,
      `Rempart.Windows` sur le job Windows, seul capable de le compiler. L'absence de porte
      est un choix argumenté dans [DEBT.md](DEBT.md), pas un oubli.
- [x] **Chaîne de construction verrouillée** — `global.json` fixe le SDK,
      `Directory.Packages.props` centralise les versions, actionlint est épinglé par digest
      d'image et non par tag.

**Ce qui reste au registre** : cinq entrées, toutes suspendues à une machine ou à une
décision — `DET-TACHE-EXPIREE`, `DET-WINDEFAULT`, `DET-TLS`, et la moitié de
`DET-COUVERTURE` et de `DET-DIRTY`.

### Passe de documentation — ✅ 2026-07-29

Réécriture des cinq documents vitrine (README, ARCHITECTURE, BUILD, CONTRIBUTING,
SECURITY) pour la lisibilité : tableaux, diagrammes et chiffres conservés, la prose
autour dépliée — l'idée d'abord, les inversions défaites (PR #103). La relecture a
surtout montré que la doc avait un commit de retard sur le pipeline d'import (#94) :

- `fetch-bloatware` manquait partout où les commandes en ligne sont énumérées ;
- `Commands/` compte 20 classes, pas 19 ;
- l'import du catalogue bloatware était encore décrit comme « à venir » ;
- le compte de tests d'un clone frais est 827 — 830 en local avec une capture,
  trois théories de rejeu par fixture ;
- [ADR-006](adr/ADR-006-catalogue-bloatware-importe.md) passée de « Proposé » à
  « Accepté — exécuté le même jour (#94, #95) ».

### Correction de la revue — ✅ 2026-07-29

Les 33 trouvailles de la [revue complète](revues/2026-07-29-revue-complete.md) sont
traitées, 18 issues fermées, une par PR. Ce qui compte n'est pas le compte mais ce que
la revue reprochait : **une classe de défaut corrigée à un endroit, la couche d'à côté
laissée**. Trois mécanismes remplacent des listes tenues à la main.

- **Le canal de statut descend jusqu'aux fournisseurs.** Pare-feu, tâches planifiées,
  énumérations du registre et fichier `hosts` savent désormais dire « refusé » là où ils
  rendaient un vide indiscernable d'une machine saine. `ListValues` et `ListSubKeys`
  changent de type de retour plutôt que de gagner une surcharge : le compilateur tient la
  liste des seize appelants, une surcharge aurait laissé le silence revenir au prochain
  collecteur écrit. Et ce refus atteint enfin le code de sortie, qui n'écoutait que les
  collecteurs de champs.
- **Ce qui est enregistré à la main est confronté au disque.** Les collecteurs de constats,
  le compte de dette du catalogue, les corps de script des workflows : trois gardes qui
  lisent la réalité au lieu d'une seconde liste écrite de la même main.
- **Un échec cesse d'emprunter le sens d'un refus.** HRESULT COM inconnu, manifeste troué,
  PAC en `file://`, énumération WMI sans délai maximal : chacun se nommait « accès refusé »
  ou emportait un scan complet.

Trois conséquences visibles : le Markdown échappe tout ce que la machine a choisi et perd
ses spans de code ; un autorun `powershell.exe -enc` cesse d'être bénin ; trois fixtures
rejouées sortent `3` au lieu de `0` ou `5`, ce qui est la trouvaille elle-même — leurs
captures précèdent la collecte des pilotes, des processus et des points d'écoute.

Trois dettes ouvertes en contrepartie, toutes argumentées : `DET-INTERPRETEURS`,
`DET-REJEU-REFUS`, `DET-VERROU-NUGET`. Et REV-29 n'est pas corrigée — les références sont
suivies en git, la CI n'en a jamais d'absente, et toute contrainte plus forte casserait le
flux de régénération documenté.

---

---

## Après la v1 — refondu le 2026-07-28

Le plan qui occupait cette place — M8 à M12 — a été écrit **avant** que v1 existe. Il proposait
cinq jalons pour le chemin d'écriture complet, un second exécutable à interop matérielle, un
couple client/serveur et une couche d'image. v1 a demandé **huit jalons pour un outil qui ne
fait que lire**. Le registre de dette avait déjà écrit pourquoi ce genre d'estimation se
trompe : *une cotation faite en lisant n'est pas une cotation faite en suivant le chemin*.

[ADR-007](adr/ADR-007-perimetre-v2-et-ecriture.md) le refond, et restaure au passage une
décision que ce plan avait diluée — [ADR-001](adr/ADR-001-stack-et-perimetre.md) **D2** disait
déjà « la remédiation arrive en v2 ».

| | Contenu | Ce que ça change |
|---|---|---|
| **1.x** | Dérive, parc, mode appairé, règles TLS/IPv6 une fois observées, notes d'impact vérifiées | **Rien** — additif, en lecture seule |
| **2.0** | **Remédiation** | L'outil écrit. La promesse centrale de v1 change |
| `rempart-hw` | Santé matérielle | Produit séparé ([ADR-001](adr/ADR-001-stack-et-perimetre.md) **D4**) |

---

## 1.x — ce qui s'ajoute sans rien casser

Pas des jalons : un flux. Chaque élément sort quand il est prêt, en version mineure, et un
utilisateur de 1.0 met à jour sans rien réapprendre.

**Ce n'est pas une salle d'attente avant la vraie version.** Ce sont ces versions qui
accumulent les **captures réelles**, et ce sont les captures réelles qui ferment
`DET-WINDEFAULT` et font passer les 120 notes d'impact de « décrite en amont » à « vérifiée ».
D2 posait comme condition « une fois l'audit éprouvé sur des machines réelles » : les 1.x
**sont** cette épreuve.

### 1.1.0 — livrée le 2026-08-01

Rien de ce qui suivait cette liste : ce lot est sorti d'une **revue de l'intégralité du code**
(33 trouvailles) puis de neuf tours où les correctifs d'un tour étaient relus de façon adverse,
ce que la relecture réfutait devenant la trouvaille du tour suivant. Onze des dix-huit derniers
correctifs ont été réfutés avant fusion.

Ce qu'il change, et pourquoi c'était de la feuille de route et pas du correctif :

- **Trois niveaux de résolution DNS entrent dans l'audit** — la pile IPv6, le niveau au-dessus
  des cartes, et la table de stratégie de résolution de noms (NRPT). Chacun est un endroit où
  un résolveur se repointe sans toucher la configuration par carte que l'outil inspectait.
  Détail dans [ARCHITECTURE.md](ARCHITECTURE.md#what-the-dns-read-covers).
- **Une lecture refusée cesse de ressembler à une réponse propre**, et atteint le code de
  sortie. C'est la dette que cinq entrées fermaient une par une ; elle est fermée par un canal
  unique.
- **Un mot de commande mal tapé sort `6` et non `0`.** Seule rupture de contrat du lot.

Ce que ce lot **n'a pas** tranché, et qui reste ouvert : la valeur `NameServer` sous la clé de
stratégie DNS n'est pas lue, parce que les binaires du résolveur ne la lisent pas là — mesuré,
contre un texte d'aide Microsoft qui affirme l'inverse. `RemoteDnsResolver`, sous la même clé,
est le seul candidat restant et n'a pas été mesuré.

### Le flux qui reste

- [x] **Suivi de dérive** — livré le 2026-08-02. Pas la forme annoncée : la ligne ci-dessus
      décrivait une tâche planifiée comparant à la baseline, c'est-à-dire `diff` déclenché
      plus souvent. La spec ([2026-08-02](design/specs/2026-08-02-suivi-de-derive-design.md))
      a demandé ce qu'une **série** dit qu'une paire ne dit pas, et la réponse a fait le lot :
      la pente, l'âge d'une régression, un contrôle qui retombe après réparation, et le trou
      dans la série elle-même — ce dernier étant la seule façon de voir qu'un suivi a cessé de
      tourner. `rempart drift` lit, `rempart baseline` promeut en refusant, la tâche planifiée
      est **fournie et jamais créée** par l'outil.

      **Ce qui a été réfuté en chemin.** La spec affirmait que le moteur enchaînerait
      `ScanDiff.Compare` sur les points consécutifs ; écrire le plan a montré que non. Un
      contrôle qui passe, devient illisible, puis échoue ne produit aucune paire classée
      régression — `Pass → Unknown` est une visibilité perdue, `Unknown → Fail` une visibilité
      retrouvée, et les deux sont justes à leur échelle. La chute n'existe qu'à l'échelle de la
      série, et c'est devenu le meilleur argument que la commande a une raison d'exister.

      **Ce qui reste ouvert, et pourquoi.** Le seuil de péremption est mesuré — la cadence
      médiane de la série — mais le facteur trois posé dessus est un choix, pas une mesure
      (`DET-DERIVE-FACTEUR`). Aucune série réelle n'existe encore : c'est la première qui le
      recalera. Et faire répondre **5** à une série périmée étend le sens de « audit partiel » ;
      l'argument contraire est écrit dans `ExitCodes`, à une ligne d'être retourné.
- [ ] **Mode appairé** — `rempart listen` / `rempart probe <ip>`, la seule façon honnête de
      vérifier que le pare-feu filtre réellement plutôt que de constater qu'il *devrait*
      filtrer. Lit, n'écrit rien : d'où son passage de M8 à 1.x.
- [ ] **Règles TLS/SCHANNEL et durcissement IPv6** — le jour où assez de builds auront été
      observées. Aujourd'hui bloquées par `DET-TLS` et non par le code.
- [ ] **Notes d'impact vérifiées** — `DET-NOTES-AMONT`, 120 des 123 à confronter au logiciel
      réellement installé. Baisse d'une unité à chaque machine vue.
- [ ] **Couche image** — `autounattend.xml` versionné, marqueur registre posé à l'installation
      et détecté par `rempart`, recommandations adaptées. Ex-M10.

---

## 2.0 — Remédiation

**Le lot qui change ce que l'outil est.** Sept jalons, et le chiffre n'est pas une précaution
oratoire : le seul chemin d'écriture pèse plus que M1 et M2 réunis. L'ancien plan lui accordait
un jalon sur cinq.

Le découpage suit la frontière posée par [ADR-007](adr/ADR-007-perimetre-v2-et-ecriture.md)
**D25** — *décider* est une valeur pure, *exécuter* est une couche mince — parce que c'est cette
frontière qui rend la remédiation testable sur les fixtures existantes au lieu d'exiger une
machine à chaque pas.

**Préconditions techniques : levées le 2026-07-27** par
[ADR-005](adr/ADR-005-decoupage-de-la-couche-cli.md). `Program.cs` porte 29 lignes, chaque
commande est une classe testable, le contrat de sortie est une fonction pure.

**Périmètre borné (D28)** : v2.0 ne corrige que les contrôles adossés au registre, dont la
réversibilité est totale et démontrable. Désinstallation de logiciels et reconfiguration de
services sont **hors périmètre** et demanderont leur propre ADR.

### R1 · Le plan — n'écrit rien
Modèle de plan et planificateur pur dans `Rempart.Core` : à partir d'un `ScanResult`, la liste
des actions avec valeur observée, valeur visée, réversibilité et ce que la correction casse.
Éprouvé sur les quatre fixtures versionnées, sans qu'aucune machine soit touchée.

Le format de données d'une action de nettoyage est déjà arrêté — il vivait dans
`ARCHITECTURE.md`, qui décrit ce qui existe, alors qu'il décrit ce qui viendra :

```yaml
- id: CLEAN-APPX-COPILOT
  layer: B                        # A=image · B=policy · C=component
  reversibility: reinstallable    # trivial | reinstallable | restore-point-only | irreversible
  impact: "Copilot indisponible. Aucune dépendance système connue."
  survives_feature_update: false  # revient à la mise à jour de fonctionnalité
```

### R2 · Le plan rendu — n'écrit toujours rien
`rempart fix` affiche le plan. **`--dry-run` n'est pas un mode**, c'est ce rendu (D25) : un mode
séparé serait une seconde implémentation qui peut diverger de la vraie, ce que DET-SCRIPTS a
déjà coûté une fois. Référence golden, comme les rendus console de M6.

### R3 · Écrire, et le prouver par une relecture
Les premiers fournisseurs en écriture du projet, dans `Rempart.Windows`. **Chaque action est
relue par le fournisseur de lecture existant et comparée à l'intention** (D26) : une action dont
la relecture ne confirme pas est rapportée **échouée**, jamais appliquée. Un « succès » d'API ne
prouve rien — une stratégie de groupe réimpose, une redirection WOW64 écrit ailleurs.

### R4 · Le journal et le retour en arrière
Le journal est le plan augmenté de la valeur observée avant et du résultat de la relecture
(D27) — pas un format de plus. `rempart rollback <session>` applique le plan inverse par le même
exécutant, donc lui aussi testable sur fixture.

### R5 · Ce qui ne se répare pas d'un `undo`
Point de restauration créé avant toute session d'écriture, confirmation individuelle pour toute
action classée `irreversible`.

### R6 · Profils
`standard` / `durci` / `paranoiaque` en YAML — des données, comme les règles
([ADR-001](adr/ADR-001-stack-et-perimetre.md) D3).

### R7 · L'épreuve
**Critère de sortie de la 2.0**, au même titre que « la clé tourne sur une machine tierce »
l'était pour v1, et pour la même raison : c'est lui qui autorise à lancer l'outil sur la machine
de quelqu'un d'autre.

Capture avant, `fix --apply`, `rollback`, capture après — et **`rempart diff` ne doit rien
trouver**. L'outil est son propre juge, ce qui n'est possible que parce que la comparaison
existe depuis M7.

---

## `rempart-hw` — produit séparé

SMART/NVMe, températures, throttling, batterie, WHEA, temps de boot. **Pas un jalon de
rempart** : [ADR-001](adr/ADR-001-stack-et-perimetre.md) D4 refuse le pilote noyau dans le
binaire principal — un pilote de lecture MSR est lui-même une surface d'attaque, complique la
signature et déclenche des antivirus. En faire « M11 » était une dérive par rapport à l'ADR.

Diagnostic thermique formulé comme une heuristique, jamais comme un verdict : `âge > 3 ans`
**ET** `ΔT idle→charge anormal` **ET** `throttling observé` **ET** `RPM élevé au repos` →
signaler les mesures et recommander une vérification physique.

---

## Ordre recommandé

M0 → M1 → M2 livrait déjà un outil réellement utile ; M7 fait gagner du temps à partir de la
troisième machine.

Pour la suite : **les 1.x d'abord**, non par prudence mais parce qu'elles produisent la matière
dont 2.0 a besoin. On ne répare bien que ce qu'on a mesuré plusieurs fois.
