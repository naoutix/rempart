# Plan d'attaque — Rempart

Chaque lot se termine par un livrable **vérifiable sur une machine réelle**.
Pas de lot qui ne produise que de l'infrastructure invisible.

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
- [ ] `IWmiProvider` — **reporté en M2**, System.Management ne survit pas à Native AOT

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

### M3 · Persistance & processus — 🚧 persistance faite, processus à venir

Les quatre surfaces de persistance sont livrées et le canal de mise à jour signé qui
leur manquait (LOLDrivers) aussi. Le volet **processus** — énumérer les processus
courants et leurs relations — reste à faire, avec les surfaces mineures ci-dessous.

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
- [ ] Enrichissement VirusTotal **opt-in explicite** (D9)

**Fait quand** un binaire non signé posé en persistance est remonté sur une VM de test —
atteint pour les surfaces livrées ; le volet processus rouvre le lot.

### M4 · Réseau & DNS
Interfaces, DNS configurés, **test actif DoH/DoT avec mesure de latence**, fichier hosts,
proxy et PAC, profils Wi-Fi, IPv6, NetBIOS, mDNS.

Ports en écoute enrichis : adresse de bind (`127.0.0.1` vs `0.0.0.0` — la distinction
qui compte), processus propriétaire et signature, service associé, **règle pare-feu
correspondante**, réputation du port.

- [ ] `GetExtendedTcpTable` / `UdpTable` en P-Invoke
- [ ] Règle croisée : écoute sur `0.0.0.0` **ET** autorisé en profil Public → sévérité haute
- [ ] Recommandation de résolveur basée sur une latence mesurée

**Fait quand** un port ouvert mais bloqué par le pare-feu n'est pas classé au même
niveau qu'un port réellement exposé.

### M5 · Logiciels & bloatware
Inventaire (MSI, Appx, winget, Chocolatey, portables), extensions navigateur avec
leurs permissions, catalogue bloatware classé par risque.

- [ ] Distinction **provisionné vs installé par utilisateur** (D6)
- [ ] Champ `survives_feature_update` renseigné
- [ ] Note d'impact obligatoire sur chaque entrée du catalogue
- [ ] Trancher le canal de rafraîchissement du catalogue *(point ouvert ADR-001)*

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
