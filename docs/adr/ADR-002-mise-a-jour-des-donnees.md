# ADR-002 : Mise à jour des données qui vieillissent

**Statut :** Accepté — 2026-07-20
**Date :** 2026-07-20
**Complète :** [ADR-001](ADR-001-stack-et-perimetre.md), décisions D9 (hors-ligne) et D3 (règles en données)

---

## Contexte

Plusieurs jeux de données du projet vieillissent, à des rythmes différents :

| Donnée | Cadence | État |
|---|---|---|
| Catalogue de règles | Continue — 82 contrôles, corrections fréquentes | Embarqué |
| Défauts Windows (`windowsDefault`) | À chaque build de Windows | Embarqué |
| Pilotes vulnérables (LOLDrivers) | Hebdomadaire, ~1 500 entrées | Prévu M3 |
| Catalogue bloatware | Mensuelle, dépend des OEM | Prévu M5 |
| Données CVE | Quotidienne | Prévu M5 |

Toutes sont aujourd'hui figées au jour de la compilation. Un binaire vieux de six mois
audite avec des règles de six mois, **sans que rien ne le signale**.

Deux contraintes de l'ADR-001 encadrent la réponse. **D9** : aucune sortie réseau par
défaut, tout enrichissement externe est opt-in par exécution. **D1** : le livrable est
un binaire autonome, utilisable depuis une clé USB sur une machine hors-ligne.

Le point ouvert « canal de rafraîchissement du catalogue », laissé en suspens depuis la
rédaction de la feuille de route, se pose désormais pour cinq jeux de données au lieu
d'un. Il est temps de le traiter une fois.

## Le risque propre à ce canal

Il ne ressemble à aucune autre dépendance du projet.

**Les règles définissent ce que « sécurisé » signifie.** Quiconque les remplace
silencieusement ne casse pas l'outil : il le fait **mentir**. Un scan rendrait 100 %
sur une machine ouverte, et personne ne chercherait — c'est précisément ce qu'un
rapport vert est censé dispenser de faire.

Une règle qui *disparaît* est donc aussi dangereuse qu'une règle fausse qui apparaît,
et beaucoup moins visible. C'est ce que ce canal doit rendre impossible en silence.

## Décision

### D11 — `rempart update`, explicite et jamais automatique

Une commande dédiée, jamais déclenchée par `scan` ni par quoi que ce soit d'autre.
Sans elle, le comportement hors-ligne de l'ADR-001 reste intact.

Sur clé USB : la mise à jour se fait une fois depuis une machine connectée, et les
données voyagent avec la clé. Les postes audités n'ont jamais besoin de réseau — ce
qui est souvent le cas de ceux qu'on veut vraiment vérifier.

### D12 — Les données embarquées restent un socle complet

Le binaire seul demeure pleinement utilisable, jamais dégradé. Les données à jour, si
présentes, priment ; leur absence n'est pas une panne.

Conséquence : un jeu de données téléchargé ne peut pas *retirer* de contrôle embarqué,
seulement en corriger ou en ajouter. Le socle est un plancher.

### D13 — Rien n'est chargé sans vérification d'intégrité

Un manifeste liste chaque jeu de données avec son empreinte. Une donnée dont
l'empreinte ne correspond pas est **refusée**, jamais chargée « au mieux ».

Le manifeste lui-même est signé — voir D16.

### D14 — Aucune application silencieuse

`update` télécharge, vérifie, puis **montre ce qui change avant d'appliquer** :
contrôles ajoutés, modifiés, retirés, avec leurs identifiants. Une suppression est
affichée aussi visiblement qu'un ajout.

### D15 — L'âge des données apparaît dans chaque rapport

L'empreinte du catalogue y figure déjà (`règles : 82:c3e6e3029b12`). S'y ajoutent la
date des données et un avertissement au-delà d'un seuil. Des règles de six mois se
voient dans le rapport, pas dans un coin de la documentation.

## Le niveau de confiance du canal — décidé

### Option A — Empreintes épinglées dans le binaire

Le binaire connaît l'empreinte du manifeste attendu.

| Dimension | Évaluation |
|---|---|
| Complexité | Faible — quelques lignes, aucune infrastructure |
| Coût | Nul |
| Souplesse | **Faible** — toute mise à jour de données exige de republier le binaire |
| Surface d'attaque | Minimale : compromettre le dépôt ne suffit pas |

**Pour :** rien à protéger, rien à faire tourner, vérification triviale à auditer.
**Contre :** annule en grande partie l'intérêt — si republier le binaire est nécessaire,
autant y réembarquer les données.

### Option B — Manifeste signé

Une paire de clés ; l'empreinte de la clé publique est épinglée dans le binaire.

| Dimension | Évaluation |
|---|---|
| Complexité | Moyenne — signature à la publication, vérification au chargement |
| Coût | Nul en argent, réel en discipline : une clé privée à protéger |
| Souplesse | **Bonne** — les données évoluent sans republier |
| Surface d'attaque | Déplacée vers la clé privée, qui devient l'actif à protéger |

**Pour :** les données vivent à leur rythme ; compromettre le dépôt ne permet pas de
falsifier les règles.
**Contre :** une clé privée perdue interrompt les mises à jour ; une clé volée les
falsifie. La protéger devient une obligation permanente.

### Option C — Confiance dans le transport

HTTPS vers le dépôt, sans vérification propre.

| Dimension | Évaluation |
|---|---|
| Complexité | Très faible |
| Coût | Nul |
| Souplesse | Bonne |
| Surface d'attaque | **Élevée** — le contrôle du dépôt donne le contrôle des règles |

**Pour :** rien à construire.
**Contre :** sur un outil de sécurité, faire reposer la définition de « sécurisé » sur
la seule sécurité d'un compte GitHub est difficile à défendre. Le dépôt est public : un
jeton compromis suffirait.

## Analyse

L'option C est écartée sur un argument simple : c'est exactement le raisonnement qui a
fait refuser le paquet NuGet tiers en M1, et le générateur non officiel. On ne fait pas
reposer un outil de sécurité sur une confiance qu'on n'a pas vérifiée.

Entre A et B, l'arbitrage est net une fois posé le besoin réel. **A ne résout pas le
problème** : si chaque mise à jour de LOLDrivers exige un nouveau binaire, autant garder
les données embarquées et publier plus souvent. A n'a de sens que si l'on renonce à
l'objectif.

**B a un coût que je ne veux pas minimiser** : la clé privée devient l'actif le plus
sensible du projet. Perdue, les mises à jour s'arrêtent — sans casser les installations
existantes, grâce à D12. Volée, un attaquant signe des règles qui mentent.

Ce coût est acceptable **si et seulement si** la clé est traitée comme telle : hors de
la machine de développement, hors du dépôt, avec une procédure de révocation écrite
avant la première signature. Sans cet engagement, A reste préférable à un B mal tenu —
une signature qu'on croit sûre est pire qu'une empreinte qu'on sait rigide.

### D16 — Manifeste signé, avec engagement sur la clé

**Option B retenue.** L'engagement qui la conditionne est pris, et sa procédure est
écrite ci-dessous — avant toute signature, comme l'exigeait la formulation de cet ADR.

Une signature qu'on croit sûre est pire qu'une empreinte qu'on sait rigide : la
procédure n'est donc pas un accessoire de la décision, elle en fait partie.

## Protection et révocation de la clé

Écrit avant la première signature. Sans ces règles tenues, D16 n'est pas respectée et
il faut revenir à l'option A.

**Génération et conservation.** La clé privée est générée hors de la machine de
développement — une VM jetable suffit, voir la procédure — et n'y séjourne jamais.
Elle est chiffrée par une phrase de passe, sans variante en clair. Elle ne figure dans
aucun dépôt, aucune sauvegarde automatique, aucun gestionnaire de secrets partagé. Une
copie hors ligne suffit ; deux copies au même endroit n'en font pas une sauvegarde.

**Usage.** La signature est un acte manuel. Aucune automatisation de CI ne détient la
clé — un canal de publication automatisé redonnerait au dépôt le pouvoir que cette
décision lui retire.

**Rotation.** Le binaire accepte **deux clés publiques simultanément**. Une rotation se
fait donc sans coupure : publier avec la nouvelle, laisser l'ancienne valide le temps
que les binaires en circulation soient remplacés, puis la retirer. Sans ce
chevauchement, toute rotation casserait les installations existantes.

**Révocation.** Une clé compromise se révoque en publiant un binaire qui ne l'accepte
plus. C'est lent — c'est le prix de l'absence d'infrastructure — et cela suppose que le
compromis soit détecté. D12 limite les dégâts entre-temps : une mise à jour falsifiée ne
peut pas retirer de contrôle embarqué, seulement en ajouter de faux. Le socle tient.

**Perte.** Une clé perdue interrompt les mises à jour sans casser aucune installation,
toujours grâce à D12. La reprise passe par un nouveau binaire portant une nouvelle clé.

## Conséquences

**Facilité** — les corrections de règles atteignent les machines sans republier ; la
dette n°4 (60 `windowsDefault` validés sur une seule machine) devient corrigeable à
mesure des captures ; LOLDrivers et le catalogue bloatware deviennent possibles.

**Difficulté** — une clé privée à protéger et une procédure de révocation à tenir ; un
format de manifeste à faire vivre ; un chemin de code qui charge des données externes,
donc à tester autant que le reste.

**À revoir** — la fréquence de publication des jeux de données, une fois qu'on saura
lesquels bougent vraiment. Et le seuil d'ancienneté au-delà duquel le rapport avertit :
arbitraire tant qu'on n'a pas observé la cadence réelle.

## D17 — Une donnée refusée produit un constat, jamais un silence ni un arrêt

Ce point était laissé ouvert, à trancher sur du code réel plutôt que par anticipation.
Le code existe désormais (`ManifestVerifier`), et la décision est prise.

**Une donnée refusée n'est pas chargée, le socle embarqué sert, et le refus est visible
dans le rapport** — constat de type `update`, sévérité `Notable`, portant le motif
exact. `rempart update` sort en code non nul ; `rempart scan` continue et rend tous ses
verdicts.

Les trois comportements écartés le sont pour des raisons distinctes. **Se taire** est
exclu : c'est le défaut qui a rendu WMI inopérant deux lots durant. **Interrompre le
scan** l'est aussi — les autres domaines doivent rendre leurs verdicts, et un outil
d'audit qui refuse de fonctionner parce qu'une mise à jour a échoué ne sera pas relancé.
**Charger quand même en avertissant** est le pire des trois : il transforme la
vérification en formalité.

### Quatre motifs de refus, jamais confondus

L'implémentation les distingue parce qu'ils appellent des réactions opposées, et qu'un
diagnostic qui les mélange ne vaut rien le jour où il compte :

| Statut | Ce que ça veut dire | Ce qu'il faut faire |
|---|---|---|
| `Malformed` | Le fichier n'est pas un manifeste lisible | Vérifier le téléchargement |
| `UnknownKey` | Signé, mais par une clé que ce binaire ignore | Mettre à jour le binaire — probablement une rotation |
| `BadSignature` | Une clé connue est revendiquée, la signature ne suit pas | **Ne rien charger.** Contenu modifié après signature |
| empreinte de fichier | Manifeste authentique, fichier reçu différent | Retéléchargement ; distinct d'une falsification du manifeste |

Rendre un booléen aurait fait passer « ton binaire est trop vieux » pour « on t'attaque ».

## Choix de la primitive de signature — ECDSA P-256

Ed25519 aurait été le choix naturel : clés courtes, signatures déterministes, pas de
paramètre de courbe à se tromper. **.NET 10 ne l'expose pas comme type public.**

ML-DSA et SLH-DSA, post-quantiques, existent bien dans .NET 10 mais portent le
diagnostic `SYSLIB5006` : *« utilisé à des fins d'évaluation uniquement et susceptible
d'être modifié ou supprimé »*. Bâtir le canal de confiance sur une API que Microsoft se
réserve de retirer serait un mauvais échange pour un outil dont l'intérêt est de ne pas
casser.

**ECDSA P-256** est stable, disponible sur toute plateforme visée, compatible Native
AOT. Signature de 64 octets fixes (IEEE P1363, pas de DER à taille variable), clé
publique de 91 octets en SPKI. Vérifié à l'exécution avant d'être retenu, pas supposé
d'après la documentation.

À revoir si Ed25519 devient public, ou quand le post-quantique sortira d'évaluation.

## Ce qui est signé, exactement

La charge utile voyage **encodée en base64** dans le manifeste, et non comme un objet
JSON imbriqué. Ce n'est pas une commodité, c'est le cœur du dispositif : la signature
porte sur ces octets-là.

Un objet imbriqué obligerait à ré-sérialiser avant de vérifier, et la moindre
différence — un espace, l'ordre des champs, la façon d'échapper un accent — invaliderait
une signature parfaitement valide. Pire, cela inviterait à « normaliser » avant
comparaison, c'est-à-dire à écrire du code qui décide quelles différences ne comptent
pas, dans le seul endroit du projet où toutes comptent.

**On vérifie les octets, puis on les analyse. Jamais l'inverse.**

## Générer la paire de clés

### Deux risques, à ne pas confondre

La formulation initiale de D16 — « générée hors de la machine de développement » — les
mélangeait. Ils appellent des réponses différentes :

| Risque | Ce qui le traite |
|---|---|
| La clé est **fabriquée** sur une machine compromise | L'environnement de génération |
| La clé **réside** sur une machine compromise, ou sur un support perdu | Le stockage, et le chiffrement |

Une clé USB est un support de stockage, pas un environnement d'exécution : y écrire la
clé traite le second risque, jamais le premier. La génération tourne forcément sur le
processeur d'une machine, et le matériau passe par sa mémoire.

### Environnement de génération

**Une VM jetable suffit quand on n'a qu'une machine.** Elle isole de ce qui compte
réellement ici : le navigateur, la chaîne d'outils, les paquets tiers, les assistants
de développement. Elle ne protège pas d'une compromission au niveau noyau de l'hôte —
mais à ce stade, la clé de signature n'est plus le problème le plus urgent.

Plus propre encore, pour le même coût : démarrer sur un Linux live sans persistance.
Le système n'a jamais exécuté l'environnement de développement.

Ni l'une ni l'autre n'exige une seconde machine physique, et l'exigence de D16 est
donc tenable en pratique.

### La commande

```
rempart keygen --out cle-privee.txt
```

`rempart.exe` est autonome : on le copie sur une clé USB, on le lance dans la VM
jetable, rien à installer.

> **Une procédure PowerShell figurait ici et ne fonctionnait pas.** Elle appelait
> `ExportPkcs8PrivateKey`, absente de .NET Framework — donc de Windows PowerShell 5.1,
> le shell par défaut. Elle aurait échoué sur la machine hors ligne, sans accès à quoi
> que ce soit pour comprendre pourquoi. Écrite de mémoire, jamais exécutée.

La commande impose ce que la procédure précédente laissait au bon vouloir :

- **la clé privée est chiffrée**, par une phrase de passe d'au moins douze caractères.
  Il n'existe aucune option pour l'écrire en clair : un support amovible se perd, se
  prête, se laisse branché ;
- **la phrase de passe ne peut pas venir d'un tube ni d'un argument** — donc ni d'un
  historique de shell, ni d'un script, ni d'un journal. Sans console interactive, la
  commande refuse ;
- **la clé est relue immédiatement après écriture.** Une clé qu'on ne sait pas rouvrir
  ne doit pas se découvrir le jour de la publication, sur une machine détruite depuis ;
- **un fichier existant n'est jamais écrasé.** Il n'y a pas de copie ailleurs, c'est
  tout l'intérêt du dispositif.

### Ce qui revient, ce qui reste

Seules **la clé publique et son empreinte** reviennent sur la machine de développement,
pour être épinglées dans `ManifestVerifier`. Publiables l'une comme l'autre : la clé
publique vérifie, elle ne signe pas.

**Une clé privée qui traverse ce chemin est compromise** : il faut en générer une autre.

### Sauvegarde

La clé privée chiffrée tient en une ligne de texte. **Elle s'écrit sur papier**, et
c'est probablement la meilleure protection contre la perte du support — la panne la
plus probable, très loin devant le vol. La commande l'affiche à cette fin.

Deux copies au même endroit ne font pas une sauvegarde. La phrase de passe ne voyage
pas avec le support.

Rappel de D16 : la signature reste un acte manuel, aucune automatisation de CI ne
détient la clé. Un canal de publication automatisé redonnerait au dépôt le pouvoir que
cette décision lui retire.

## Actions

1. [x] Trancher le niveau de confiance — **manifeste signé (D16)**
2. [x] Format du manifeste — charge utile base64 signée, empreintes SHA-256, date de
       publication, plusieurs signatures pour la rotation
3. [x] `rempart update --from <manifeste>` : vérifie signature et jeux de données,
       montre le différentiel (D14), et sur `--apply` pose la mise à jour dans le
       magasin après confirmation. Restent le téléchargement réseau — qui produit ce
       même fichier — et un outil de signature de manifeste, sans lequel rien ne peut
       encore produire un manifeste de confiance
4. [x] Chargement des données externes avec priorité sur l'embarqué (D12) — le scan
       résout le magasin, re-vérifie signature et empreintes (D13), fusionne par-dessus
       le socle sans jamais en retirer, et prend la date de publication comme date des
       données (D15). Une mise à jour refusée est dite, jamais tue (D17)
5. [x] Date et ancienneté dans le rapport (D15) — ligne « données : » sous l'empreinte,
       date de référence embarquée, alerte au-delà de 180 jours (seuil provisoire)
6. [x] Procédure de protection et de révocation de la clé — **écrite ci-dessus**
7. [x] **Générer la paire de clés, hors de la machine de développement** — fait le
       2026-07-21, dans un bac à sable Windows jetable, hors ligne. La clé privée est
       chiffrée et n'a jamais touché la machine de développement. La clé publique
       `168e543a9424` est épinglée dans `PinnedKeys`, sa cohérence avec l'empreinte
       vérifiée par un test qui refuse de livrer une faute de recopie
8. [x] Trancher le sort d'une donnée refusée — **D17**
