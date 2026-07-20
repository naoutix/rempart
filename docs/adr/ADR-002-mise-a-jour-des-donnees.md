# ADR-002 : Mise à jour des données qui vieillissent

**Statut :** Proposé — une décision reste ouverte, voir « Trancher »
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

Le niveau de confiance du manifeste lui-même reste à trancher — voir plus bas.

### D14 — Aucune application silencieuse

`update` télécharge, vérifie, puis **montre ce qui change avant d'appliquer** :
contrôles ajoutés, modifiés, retirés, avec leurs identifiants. Une suppression est
affichée aussi visiblement qu'un ajout.

### D15 — L'âge des données apparaît dans chaque rapport

L'empreinte du catalogue y figure déjà (`règles : 82:c3e6e3029b12`). S'y ajoutent la
date des données et un avertissement au-delà d'un seuil. Des règles de six mois se
voient dans le rapport, pas dans un coin de la documentation.

## Trancher : le niveau de confiance du canal

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

**Recommandation : option B**, sous réserve de cet engagement.

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

## Points ouverts

- Rotation de la clé : prévoir deux clés valides simultanément, ou accepter une coupure.
- Que faire d'une donnée refusée à la vérification : ignorer en silence est exclu, mais
  interrompre le scan l'est aussi. Probablement un constat visible, comme pour WMI.

## Actions

1. [ ] Trancher le niveau de confiance — **décision ouverte**
2. [ ] Format du manifeste : jeux de données, versions, empreintes, date
3. [ ] `rempart update` : téléchargement, vérification, différentiel, confirmation
4. [ ] Chargement des données externes avec priorité sur l'embarqué (D12)
5. [ ] Date et ancienneté dans le rapport (D15)
6. [ ] Procédure de protection et de révocation de la clé, **écrite avant la première
   signature**
