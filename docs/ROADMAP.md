# Plan d'attaque — Rempart

Chaque lot se termine par un livrable **vérifiable sur une machine réelle**.
Pas de lot qui ne produise que de l'infrastructure invisible.

---

## v1 — Audit en lecture seule

### M0 · Socle
Squelette de solution, CLI, contrat `ICollector`, **abstraction providers (D5)**,
`rempart capture`, sortie JSON, CI GitHub Actions.

Inclut un premier collecteur d'inventaire réel — pour juger l'ergonomie tout de suite
plutôt qu'après trente collecteurs.

- [ ] `git init`, solution .NET 10, publication AOT vérifiée
- [ ] `IRegistryProvider` / `IWmiProvider` + implémentations Live et FromSnapshot
- [ ] Collecteur `Inventory` (modèle, OS, build, TPM, Secure Boot, UEFI, uptime)
- [ ] `rempart capture` produit un snapshot rejouable
- [ ] Première fixture : snapshot de la machine de développement
- [ ] CI : build AOT + tests unitaires

**Fait quand** `rempart scan --json` affiche l'inventaire réel, et le même scan rejoué
depuis la fixture donne une sortie identique.

### M1 · Moteur de règles
Chargement YAML, évaluation, sévérités, scoring par domaine et global.

- [ ] Schéma de règle + chargeur, avec validation au démarrage
- [ ] Types de check : `registry`, `service`, `policy`, `wmi`
- [ ] Scoring par domaine, mappé CIS / Essential Eight
- [ ] **Test de propriété (D7)** : aucun profil ne cible la liste noire
- [ ] 10 contrôles réels de bout en bout

**Fait quand** ajouter un contrôle ne demande que d'éditer un YAML.

### M2 · Posture de sécurité — le gros morceau
Les ~120 contrôles : BitLocker, Defender et règles ASR, Credential Guard, LSA,
protocoles legacy, accès distant, comptes, pare-feu, mises à jour, journalisation.

- [ ] Un fichier YAML par domaine
- [ ] Gestion propre du manque de privilèges (`insufficient_privileges`, jamais d'omission)
- [ ] Fixtures pour au moins deux SKU différents

**Fait quand** le score et le détail par domaine sont cohérents sur trois machines réelles.

### M3 · Persistance & processus
Processus (chemin, signature Authenticode, parent, ligne de commande), services,
tâches planifiées, clés Run, dossiers Startup, **abonnements WMI permanents**,
COM hijacking, Winlogon/LSA providers, AppInit_DLLs, pilotes chargés.

- [ ] Hash SHA-256 et vérification de signature de chaque binaire
- [ ] Détection des chemins de service non-quotés
- [ ] Pilotes vulnérables connus (LOLDrivers)
- [ ] Enrichissement VirusTotal **opt-in explicite** (D9)

**Fait quand** un binaire non signé posé en persistance est remonté sur une VM de test.

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
