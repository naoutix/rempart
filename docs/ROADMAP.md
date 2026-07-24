# Plan d'attaque — Rempart

Chaque lot se termine par un livrable **vérifiable sur une machine réelle**.
Pas de lot qui ne produise que de l'infrastructure invisible.

La dette technique connue est suivie à part, dans [DEBT.md](DEBT.md).

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

**Écart à l'ADR-001.** YamlDotNet est utilisé par son API bas niveau (`YamlStream`),
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

### M4 · Réseau & DNS
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
- [ ] IPv6 — **reporté**, même raison que TLS/SCHANNEL (M2b). Le durcissement des
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
- [x] **M5b — catalogue bloatware** : dataset signé (type `bloatware`, canal ADR-002)
      croisé avec l'inventaire, note d'impact obligatoire par entrée. Vérifié sur machine
      réelle : socle de 5 entrées, 3 installées (Xbox Gaming Overlay, Xbox App, Groove
      Musique) et confirmées via `Get-AppxPackage` — PFN exacts, aucune correction
      nécessaire ; escalade en Notable observée pour ces trois avec `bloatware`/`catalogue`
      renseignés, zéro faux positif sur le reste de l'inventaire. Les 2 entrées restantes
      (météo Bing, Clipchamp) sont absentes de `Get-AppxPackage` sur cette machine — mais y
      ont quand même escaladé en Notable, via une entrée-ressource orpheline du registre
      Appx (faux positif assumé, DET-APPX-FAUXPOS dans DEBT.md) ; elles restent valables
      pour d'autres machines où le paquet est réellement présent.
- [x] Canal de rafraîchissement du catalogue — **déjà tranché** : le canal signé d'ADR-002,
      comme LOLDrivers (ADR-001 le renvoyait à ADR-002)
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

**Fait quand** le catalogue est validé sur une machine OEM réelle, pas sur une VM.

### M6 · Rapport & packaging clé
HTML autonome (fichier unique, thème clair/sombre), JSON, Markdown.
Espace récupérable par couche via `AnalyzeComponentStore`, sans rien supprimer.

- [ ] Layout de la clé : `/rempart.exe`, `/rules/`, `/reports/<hostname>-<date>/`
- [ ] Manifeste d'intégrité : hash des binaires, pour détecter une clé compromise
- [ ] Dégradation propre sans droits admin

**Fait quand** la clé tourne sur une machine tierce sans rien installer.

### M7 · Flotte
`rempart diff a.json b.json`, baseline de référence, page d'agrégation des rapports.

**Fait quand** l'écart de posture entre deux machines est lisible d'un coup d'œil.

---

## Post-v1

### M8 · Mode appairé
`rempart listen` / `rempart probe <ip>` — la seule façon honnête de vérifier que le pare-feu
filtre réellement, plutôt que de constater qu'il *devrait* filtrer. Pertinent puisque
plusieurs machines sont préparées.

### M9 · Remédiation
Le lot le plus sensible. Ne démarre qu'une fois l'audit éprouvé.

- [ ] Providers en écriture (les premiers du projet)
- [ ] `--dry-run` par défaut, écriture derrière un flag explicite
- [ ] Journal de rollback JSON sur la clé + `rempart rollback <session-id>`
- [ ] Point de restauration créé avant toute session d'écriture
- [ ] Profils `standard` / `durci` / `paranoiaque` en YAML
- [ ] Confirmation individuelle pour tout `irreversible`
- [ ] **Test VM : appliquer → rollback → assert état identique à l'initial**

Ce dernier test est le plus important du projet : c'est lui qui autorise à lancer
l'outil sur une machine réelle.

### M10 · Couche image
`autounattend.xml` versionné dans `image/`. Pour toute machine réinstallable, c'est
le chemin que l'outil recommande — une machine née propre plutôt que nettoyée après coup.

- [ ] Marqueur registre posé à l'installation, détecté par `rempart`
- [ ] Recommandations adaptées selon que la machine vient ou non de cette image

### M11 · Santé matérielle
Add-on `rempart-hw.exe` : SMART/NVMe, températures, throttling, batterie, WHEA, temps de boot.

Diagnostic thermique formulé comme une heuristique, jamais comme un verdict :
`âge > 3 ans` **ET** `ΔT idle→charge anormal` **ET** `throttling observé` **ET**
`RPM élevé au repos` → signaler les mesures et recommander une vérification physique.

### M12 · Suivi de dérive
Tâche planifiée mensuelle comparant à la baseline, alerte sur écart.

---

## Ordre recommandé

M0 → M1 → M2 livre déjà un outil réellement utile.
M7 est ce qui fait gagner du temps à partir de la troisième machine.
M9 attend que l'audit ait tourné sur plusieurs machines réelles.
