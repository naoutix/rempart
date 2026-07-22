# ADR-001 : Stack, périmètre v1 et principes de sécurité

**Statut :** Accepté
**Date :** 2026-07-20
**Projet :** Rempart — audit et durcissement Windows portable

---

## Contexte

Préparation de plusieurs machines Windows 11 en configuration durcie : audit complet,
durcissement, dé-bloatware, hygiène système. Aujourd'hui manuel, non reproductible, sans trace.

Contraintes structurantes :

- **Portable** — lancé depuis une clé USB, sans installation, machine potentiellement hors-ligne.
- **Multi-machines** — les résultats doivent être comparables entre machines (baseline + diff).
- **Chirurgical** — audit et remédiation sont deux phases strictement séparées.

## Décisions

### D1 — Stack : .NET 10 / C# en publication AOT autonome

Livrable : un `rempart.exe` unique, ~20 Mo, sans dépendance ni runtime à installer.

**Pourquoi .NET 10 et pas 8** — .NET 8 arrive en fin de support LTS en novembre 2026.
Démarrer un projet neuf sur une LTS expirant dans quelques mois serait une dette immédiate
et gratuite. .NET 10 est supporté jusqu'à fin 2028 et son Native AOT est plus mature,
ce dont dépend directement le livrable en binaire unique.

Alternatives écartées :

| Option | Raison du rejet |
|---|---|
| PowerShell 7 portable | Runtime ~70 Mo sur la clé, friction ExecutionPolicy/AMSI, faux positifs AV élevés, tests peu praticables |
| Go | Tout le domaine Windows admin (WMI, registre, WinAPI) serait à réimplémenter à la main |
| Rust | Même coût que Go, plus une vitesse de développement inférieure ; le gain mémoire est marginal pour un outil majoritairement en lecture |

PowerShell reste utilisé en **prototypage** : valider un contrôle en PS avant de le porter en C#.

### D2 — v1 en lecture seule

La v1 n'écrit rien sur le système. Elle collecte, évalue, score et rapporte.
La remédiation arrive en v2, une fois l'audit éprouvé sur des machines réelles.

Justification : un moteur de remédiation construit avant que l'audit soit fiable
applique des corrections à des diagnostics non validés.

### D3 — Les règles sont des données, pas du code

Tous les contrôles de sécurité, catalogues bloatware et profils sont en YAML embarqué.
Ajouter un contrôle = éditer un fichier, sans recompiler. Les règles sont relisibles en PR
par quelqu'un qui ne lit pas le C#.

### D4 — Santé matérielle en add-on séparé

Lire les températures et le SMART détaillé exige un pilote noyau (type LibreHardwareMonitor).
Un pilote de lecture MSR est lui-même une surface d'attaque, complique la signature et
déclenche des antivirus.

Le binaire principal reste sans pilote. `rempart-hw.exe` est un exécutable distinct, activé
explicitement.

### D5 — Abstraction providers obligatoire dès le premier collecteur

Aucun collecteur n'appelle Windows directement. Tout passe par `IRegistryProvider`,
`IWmiProvider`, `IServiceStateProvider`, `IFileSystemProvider` (et, depuis, une famille
de providers dédiés aux surfaces système volumineuses — voir [ADR-004](ADR-004-etat-systeme-en-champ-dedie.md)).

Débloque `rempart capture` (dump JSON de l'état brut d'une machine) et le rejeu hors-ligne en test.
Rétrofiter cette abstraction sur 30 collecteurs déjà écrits serait une réécriture — d'où
son caractère non négociable en M0.

### D6 — Nettoyage : classement par couche et par réversibilité

L'état de l'art distingue trois couches de nettoyage Windows :

| Couche | Moment | Réversibilité | Risque |
|---|---|---|---|
| **A** — Image (`autounattend.xml`, NTLite, tiny11) | Avant installation | Réinstallation | Faible |
| **B** — Politiques et réglages (registre, services, tâches) | Après installation | Bonne si journalisée | Modéré |
| **C** — Suppression de composants (Edge, Store, services système) | Après installation | Mauvaise à nulle | **Élevé** |

La couche C est celle qui casse les machines. Pour toute machine réinstallable, l'outil
recommande la couche A plutôt qu'un nettoyage post-installation plus agressif.

Chaque action porte une classe de réversibilité (`trivial`, `reinstallable`,
`restore-point-only`, `irreversible`) qui pilote l'interface : une action `irreversible`
n'entre jamais dans un profil et exige une confirmation individuelle.

### D7 — Liste noire codée en dur

Les éléments suivants ne peuvent être ciblés par aucun profil YAML, même par erreur d'édition :

- Microsoft Edge et le runtime WebView2 — moteur de rendu de nombreuses apps natives et surfaces système
- Microsoft Store et App Installer — chemin de réinstallation de composants système
- Services système critiques (liste explicite versionnée)
- Windows Update et son magasin de servicing

Un test de propriété en CI parcourt tous les profils livrés et échoue si l'un d'eux
cible un élément protégé.

### D8 — Pas de nettoyage de registre

Microsoft ne le supporte pas et le déconseille. Le registre ne se dégrade pas de façon
mesurable et une suppression automatisée casse des choses pour un gain nul.

C'est le marqueur qui distingue un outil d'audit sérieux d'un « PC optimizer ».
Décision définitive : hors périmètre, quelle que soit la version.

### D9 — Aucune sortie réseau par défaut

L'outil fonctionne intégralement hors-ligne. Tout enrichissement externe
(VirusTotal, bases CVE, exposition Internet) est opt-in explicite et par exécution.
Aucun hash, aucune IP, aucun inventaire ne quitte la machine sans demande.

### D10 — Périmètre limité à la machine hôte

`rempart` audite la machine sur laquelle il tourne. Pas de découverte réseau ni de scan du LAN :
cela rendrait son usage dépendant du réseau où la clé est branchée.

Exception cadrée : le mode appairé `listen`/`probe` (M8), où deux machines que l'opérateur
contrôle se testent mutuellement pour valider le filtrage réel du pare-feu.

## Conséquences

**Facilité** — livrable unique sur clé, exécution hors-ligne, résultats comparables entre
machines, règles éditables sans recompilation, tests rapides sans VM grâce aux fixtures.

**Difficulté** — élévation administrateur requise (dégradation propre attendue, jamais
d'échec silencieux) ; le module matériel reste un chantier à part ; un binaire qui énumère
la persistance sera signalé par certains antivirus, la signature de code devient nécessaire
en cas de distribution.

**À revoir** — le catalogue bloatware et les données CVE vieillissent vite : il leur faut
un canal de rafraîchissement hors du cycle de release du binaire.

## Points ouverts

- Signature de code : reporté tant que l'usage reste personnel.
- Canal de mise à jour des catalogues : à trancher en M5.
- Support Windows 10 : à confirmer selon le parc réel.
