# Rempart

Audit de postes Windows, en un binaire unique exécutable depuis une clé USB.

> **État : M4 (réseau) terminé, M5 (logiciels & bloatware) entamé.**
> Neuf surfaces de persistance auditées (démarrages, tâches, pilotes noyau, abonnements
> WMI, processus, extensibilité de session, paquets LSA, chemins de service non guillemetés,
> détournement COM), enrichissement VirusTotal optionnel, 82 contrôles sur 13 domaines,
> et l'inventaire logiciel (Uninstall, Appx, App Paths, Chocolatey, avec provisionné /
> survives_feature_update). 420 tests, binaire de 9,4 Mo sans installation. Les contrôles
> sont des fichiers YAML.
> **En cours dans M4** l'inventaire réseau : les ports en écoute sont reliés à leur binaire
> propriétaire et croisés avec les règles du pare-feu (un port bloqué n'est pas un port
> exposé) ; les résolveurs DNS, le fichier hosts et la configuration proxy (WinINET, GPO,
> WinHTTP, avec récupération opt-in du script PAC) sont audités, ainsi que les profils
> Wi-Fi enregistrés (réseaux ouverts, WEP, connexion automatique) ; le test actif DoH/DoT
> (`--probe-dns`) mesure la latence des résolveurs chiffrés et recommande le plus rapide.
> Seul le durcissement IPv6-transition reste reporté, ses défauts variant selon la build de
> Windows — voir [ROADMAP.md](docs/ROADMAP.md). **L'audit
> ne modifie rien** — aucune remédiation avant M9 ; la seule écriture est le magasin de
> données à jour, sur `update --apply`.

```
rempart scan             posture (règles) + constats (persistance), score par domaine
rempart explain <ID>     pourquoi une règle existe et ce que coûte sa correction
rempart capture          instantané rejouable hors-ligne, anonymisé
rempart update …         appliquer une mise à jour de données signée (voir plus bas)
```

## Ce que c'est, ce que ce n'est pas

Un outil pour préparer plusieurs machines Windows en configuration durcie, de façon
reproductible et traçable. Il inspecte la posture de sécurité et produit un rapport
comparable d'une machine à l'autre.

**Ce n'est pas** un « PC optimizer » — pas de nettoyage de registre, Microsoft ne le
supporte pas et le gain est nul. Ni un antivirus : il constate, il ne protège pas.
Ni un scanner réseau : il audite la machine sur laquelle il tourne, rien d'autre.

## Les commandes

Auditer, au quotidien :

| Commande | Ce qu'elle fait |
|---|---|
| `rempart scan [--json]` | Analyse la machine. **Élevé** pour la vue complète (BitLocker, comptes, LSA). |
| `rempart scan --from <capture>` | Rejoue un instantané, sans la machine. |
| `rempart explain [<ID>]` | Liste les contrôles, ou détaille une règle : justification, références, coût. |
| `rempart capture [--raw]` | Enregistre l'état, rejouable. Anonymisé par défaut. |

Le canal de mise à jour des données (règles, liste LOLDrivers) — voir
[ADR-002](docs/adr/ADR-002-mise-a-jour-des-donnees.md) et la section plus bas :

| Commande | Où | Ce qu'elle fait |
|---|---|---|
| `rempart keygen` | hors ligne, **une fois** | Génère la paire de clés d'éditeur. Clé privée chiffrée. |
| `rempart fetch-loldrivers` | en ligne | Télécharge la liste officielle LOLDrivers, prête à signer. |
| `rempart sign --key … --data …` | hors ligne | Signe un jeu de données (règles ou pilotes). |
| `rempart update --from <man.> \| --url <base>` | connecté | Vérifie et prévisualise ; `--apply` pose la mise à jour. |

Diagnostics de CI : `diagnose-wmi`, `diagnose-tasks` (l'interop COM répond dans le
binaire AOT). Fabrication de fixtures : `synthesise`. `rempart version` affiche la
version ; `rempart help` liste tout.

---

# Pour développer

## Démarrer

```bash
dotnet test                                   # 420 tests (51 exigent Windows), ~10 s
dotnet run --project src/Rempart.Cli -- scan  # sur la machine locale
```

Prérequis : [.NET SDK 10](docs/BUILD.md). Les Build Tools C++ ne servent qu'à la
publication AOT.

## Les six choses qui font perdre du temps

Toutes rencontrées pendant le développement, toutes documentées dans
[BUILD.md](docs/BUILD.md).

| Symptôme | Cause |
|---|---|
| `MSB3073 ... code 123` après plusieurs minutes de publication | `vswhere.exe` absent du `PATH` — le message accuse `link.exe` à tort |
| `winget` échoue en `0x8a15000f` | Terminal élevé : cache de sources distinct. Lancer depuis un PowerShell normal |
| `Une stratégie de contrôle d'application a bloqué ce fichier` | Smart App Control. Voir plus bas |
| Un test échoue sur une fixture après ajout d'une règle | `./scripts/regenerate-fixtures.ps1` |
| `verify.ps1` s'interrompt sans diagnostic | PowerShell 5.1 : la sortie d'erreur d'un exe natif devient terminante sous `$ErrorActionPreference = 'Stop'` |
| Le code compile mais échoue à la publication AOT | Le garde-fou `IsAotCompatible` les attrape à la compilation — s'il ne l'a pas fait, c'est du COM |

### Smart App Control

Sur une machine où il est actif, les assemblys fraîchement compilées peuvent être
**refusées au chargement** (`0x800711C7`). Le refus se lit dans le journal
`Microsoft-Windows-CodeIntegrity/Operational`, événement 3077.

**Ce comportement n'est pas prévisible localement** : chaque empreinte est soumise au
service de réputation Microsoft. Ni recompiler ni attendre n'est une méthode fiable.

Sur une machine concernée, **la CI fait foi** : ses runners n'appliquent pas cette
stratégie. `rempart diagnose-wmi` et `rempart diagnose-tasks` y sont exécutés contre
le binaire publié, parce qu'un bug d'interop COM ne se voit pas en JIT.

La désactiver reste un arbitrage à faire en connaissance de cause — voir
[BUILD.md](docs/BUILD.md#smart-app-control) : elle se réactive sans réinstaller
Windows, contrairement à ce que ce fichier a affirmé jusqu'ici.

## Ajouter un contrôle

Éditer un YAML dans [`rules/security/`](rules/security/), puis :

```powershell
./scripts/regenerate-fixtures.ps1   # une règle lit des clés absentes des fixtures
dotnet test                         # échoue une fois, pour relire les références
```

Sans recompiler, pour itérer :

```powershell
rempart scan --rules ./mes-regles
```

Le format complet est dans [ARCHITECTURE.md](docs/ARCHITECTURE.md). Trois champs
méritent l'attention.

**`windowsDefault` — obligatoire, et c'est lui qui décide de la justesse.** Sur le
registre Windows, une clé absente est le cas *courant* : le comportement suit alors un
défaut documenté, souvent l'état souhaité. Une version antérieure traitait toute
absence comme un échec et remontait trois alertes `CRITICAL` fausses sur une machine
saine. Un outil qui crie au loup cesse d'être lu.

**`appliesWhen` — quand une règle a un sens.** Plusieurs contrôles ne valent que sur
une machine jointe à un domaine, ou avec RDP actif. Ailleurs, ils font du bruit — et
le bruit disqualifie un outil d'audit plus sûrement qu'un contrôle manquant.

**`breaks` / `affects` / `verifyBefore` — pas un texte libre.** Les trois questions
qu'on se pose avant d'appliquer un durcissement : qu'est-ce qui cesse de marcher, qui
est concerné, comment le savoir à l'avance. « Rien » est recevable, mais doit être
écrit.

## Mettre les données à jour

Règles et liste de pilotes vulnérables vieillissent — la seconde chaque semaine. Le
binaire embarque un socle complet ; une mise à jour signée le corrige ou le complète,
sans jamais en retirer ([ADR-002](docs/adr/ADR-002-mise-a-jour-des-donnees.md)).

**Un seul principe gouverne le canal : le transport n'est jamais de confiance, seule la
signature l'est.** Un jeu de données — téléchargé, apporté sur clé USB, servi par un
dépôt public — est cru si et seulement s'il porte la signature d'une clé épinglée dans
le binaire. Un serveur compromis, un intermédiaire, une redirection : aucun ne peut
faire accepter des données que l'éditeur n'a pas signées. C'est pourquoi `update --url`
et `update --from` passent exactement la même vérification.

La cérémonie de publication, une fois la clé générée (`keygen`, hors ligne) :

```powershell
rempart fetch-loldrivers --out drivers\loldrivers.json   # en ligne : l'outil télécharge
rempart sign --key cle-privee.txt --data drivers          # hors ligne : vous seul signez
rempart update --from drivers\manifest.json --apply       # pose la mise à jour dans le magasin
```

Chaque `scan` **re-vérifie** ensuite le magasin — il ne fait pas confiance à ce qu'un
`--apply` antérieur a écrit — et affiche l'état des données dans son en-tête. Un fichier
du magasin altéré après coup est rejeté, le socle embarqué tient, et le rapport le dit.

La clé privée est générée et conservée **hors de la machine de développement** (une VM
jetable suffit), chiffrée par une phrase de passe. Aucune automatisation de CI ne la
détient : la signature est un acte manuel, sans quoi compromettre le dépôt rendrait au
dépôt le pouvoir que ce dispositif lui retire.

## Les principes qui tiennent le projet

Ils ont chacun coûté une erreur. Les enfreindre casse quelque chose qui ne se verra
pas tout de suite.

**Aucun collecteur n'appelle Windows directement.** Tout passe par les providers
(`IRegistryProvider`, `IServiceStateProvider`, `IWmiProvider`…). C'est ce qui permet
de rejouer un scan hors-ligne, et donc de tester sans machine ni VM.

**`Unknown` n'est jamais `Fail`.** Un contrôle qu'on n'a pas pu lire n'est pas un
contrôle échoué. Il sort du score, et un domaine entièrement illisible vaut `n/d`, pas
zéro. « Je ne sais pas » et « c'est mauvais » appellent des actions différentes.

**Ne jamais masquer une défaillance en refus d'accès.** Un `catch` généraliste
traduisant tout en « accès refusé » a rendu WMI inopérant dans le binaire publié
pendant deux lots, sans que rien ne le signale — le bug ressemblait à un manque de
droits. Une panne doit se voir.

**Une seule traduction d'un `CheckSpec` en lectures** — [`CheckReader`](src/Rempart.Core/Rules/CheckReader.cs).
L'évaluation et la capture y passent toutes deux ; un test verrouille l'invariant.
Sans lui, un nouveau type de contrôle oublié côté capture produirait des instantanés
silencieusement incomplets.

**Ne pas livrer une règle qu'on n'a pas pu vérifier.** Un nom de propriété deviné rend
`Unknown` pour toujours, sans que rien ne le distingue d'un manque de droits. Deux
règles ont été retirées pour cette raison, avec leur motif consigné à l'emplacement
exact où elles se trouvaient.

## Tests

| Projet | Portée | Où |
|---|---|---|
| `Rempart.Tests.Unit` | Moteur, règles, rejeu de fixtures | Partout, sans Windows |
| `Rempart.Tests.Windows` | Vrai registre, services, WMI, scan complet | Windows uniquement |

Les fixtures de `tests/fixtures/synthetic/` sont **versionnées et fabriquées**. Les
captures de machines réelles vont dans `tests/fixtures/local/`, **hors dépôt** : le
dépôt est public, et une capture réelle cartographie les faiblesses d'une machine
identifiable. Elles sont rejouées si présentes — les machines réelles portent les cas
que personne n'aurait pensé à fabriquer.

Quelques tests méritent d'être connus avant de toucher au moteur :

- *Aucune règle n'échoue sur une machine durcie* — attrape une règle inatteignable
- *L'évaluation ne lit jamais une clé que la capture n'enregistre pas*
- *Aucune règle ne cible un composant protégé* — Edge, Store, Windows Update
- *Les fixtures versionnées sont anonymisées*

## Workflow

`main` est protégé : pull request obligatoire, **les cinq checks verts**, historique
linéaire, et la règle s'applique aux administrateurs — sans quoi elle n'enforcerait rien.

```bash
git checkout -b feat/…
./scripts/verify.ps1        # workflows, tests, publication AOT, binaire isolé
gh pr create
gh pr merge --squash --delete-branch
```

Cinq jobs. Le contrôle le moins évident est l'étape `diagnose-wmi` de `publish-aot`,
exécutée **contre le binaire natif** : l'interop COM s'y comporte autrement qu'en JIT,
et c'est le seul endroit où un bug entier était observable.

## Où trouver quoi

| | |
|---|---|
| [ADR-001](docs/adr/ADR-001-stack-et-perimetre.md) | Les 10 décisions fondatrices, avec les alternatives écartées |
| [ADR-002](docs/adr/ADR-002-mise-a-jour-des-donnees.md) | Mise à jour des données qui vieillissent, manifeste signé |
| [ADR-003](docs/adr/ADR-003-pare-feu-par-registre.md) | Lire le pare-feu par le registre plutôt que par COM |
| [ADR-004](docs/adr/ADR-004-etat-systeme-en-champ-dedie.md) | État système volumineux en champ de snapshot dédié |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Schémas, format des règles, stratégie de test |
| [ROADMAP.md](docs/ROADMAP.md) | M0 → M12, ce qui est reporté **et pourquoi** |
| [DEBT.md](docs/DEBT.md) | Registre de dette technique, suivi au fil des audits |
| [BUILD.md](docs/BUILD.md) | Prérequis, publication AOT, pièges |
| [rules/security/](rules/security/) | Les 82 contrôles |

La feuille de route consigne aussi ce qui a été **écarté**, avec le motif. C'est là
qu'il faut regarder avant de réimplémenter quelque chose qui a déjà été essayé.

## Licence

[MIT](LICENSE). Fourni sans garantie : l'outil inspecte et, à terme, modifiera la
configuration d'un système. La responsabilité de son usage revient à celui qui
l'exécute.
