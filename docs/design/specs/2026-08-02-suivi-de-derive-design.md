# Design — Suivi de dérive : ce qu'une série dit (1.x)

> État : proposé le 2026-08-02. Répond à l'issue #99 et précède le code du jalon
> « 1.x · Drift monitoring » (#100, #101, #102).

## Contexte

M7 a livré `diff`, et le moteur est bon : il compare deux rapports, distingue une
régression d'un contrôle devenu illisible, et les transitoires sont neutralisés à la
source. Mais **`diff` compare deux points, et une dérive est une série.** `index` agrège
des machines, pas des dates. Personne n'avait décidé ce qu'on veut lire avec douze
rapports d'un même poste étalés sur six mois.

Ce document répond aux quatre questions de #99 — ce qu'on affiche, ce qui compte comme
dérive, le bruit, la rétention — puis pose l'architecture et le contrat de sortie que
#100 et #102 consommeront.

## 1. Ce qu'une série dit que deux points ne peuvent pas dire

C'est le seul critère qui justifie une commande de plus. Tout ce qu'une paire sait déjà
dire reste chez `diff`.

| | Ce qu'une paire en dit | Ce que la série en dit |
|---|---|---|
| **Trajectoire** | deux scores | la pente, globale et par domaine |
| **Âge d'une régression** | « ça a basculé » | « ça échoue depuis 71 jours » |
| **Instabilité** | un mouvement ordinaire, recompté à chaque paire | un contrôle qui bascule dans les deux sens, nommé une fois |
| **Trou dans la série** | rien — une paire n'a pas de rythme | « dernière capture il y a 97 jours » |

Le quatrième est la réponse à ce que #102 pose comme un piège : *le silence est
confortable, et c'est aussi ce qui fait qu'on ne remarque pas qu'une tâche a cessé de
tourner depuis trois mois*. On n'y répond pas en rendant chaque exécution bruyante — un
journal que personne ne lit ne devient pas lu parce qu'il grossit — mais en faisant
porter l'absence par la série, seul endroit où elle est visible.

L'instabilité est le second signal proprement sériel. Un contrôle qui passe, échoue,
repasse et rechute quatre fois en six mois n'est pas quatre nouvelles : c'est une seule,
et elle ne se voit d'aucun des quatre points de vue.

## 2. Ce qui compte comme dérive

**Tous les mouvements sont affichés ; seule la régression touche le code de sortie.**

Sur une série, une régression est dite **ouverte** quand un contrôle qui a passé plus tôt
échoue au dernier point. Une régression suivie d'une correction reste dans la
trajectoire, avec ses deux dates ; elle ne réveille personne, puisqu'il n'y a plus rien à
corriger.

Le code 4 existe depuis M7 et dit exactement cela. Une amélioration, une règle apparue,
un changement de périmètre sont lisibles dans la page et ne réveillent personne. Un
contrôle devenu illisible garde la distinction pour laquelle tout le classement de M7
existe : il appelle une élévation, pas une correction, et il ne se déguise pas en
régression.

Rien de neuf ne rend `0` là où l'ancien rendait autre chose. Cette précédence a déjà été
payée une fois (`DET-SORTIE-PARTIELLE`).

## 3. Le bruit long terme

**Aucun nouveau filtre.** Les deux clés de M7 — `transitoire` (le système le retire de
lui-même) et `éphémère` (son identité change par conception) — restent la seule
neutralisation, posée par les collecteurs qui connaissent le mécanisme, et appliquée
uniquement aux constats déjà jugés bénins.

Ce que la série ajoute est un **regroupement, pas un silence** : les quatre bascules d'un
contrôle instable sont dites une fois, avec leur compte et leurs dates. Le fait n'est pas
tu, il cesse d'être répété. Un filtre long terme — « ignorer ce qui bouge souvent » —
ferait exactement l'inverse : il tairait le signal le plus intéressant que la série
produit.

## 4. La rétention

**Personne n'élague.** `drift` nomme la fenêtre couverte, le nombre de rapports lus, le
plus ancien, et la place occupée sur le disque. Il ne supprime rien, et aucune option ne
le lui fera faire dans ce jalon.

Deux raisons, dans cet ordre. Le jalon est classé 1.x parce qu'il ne casse rien : y
glisser une suppression de fichiers en ferait autre chose. Et M6 a déjà tranché la même
question en refusant qu'un second scan écrase le premier du jour — *le « avant » d'une
correction est la moitié qu'on ne peut pas refaire*. Un élagage automatique supprimerait
en priorité les rapports les plus anciens, c'est-à-dire précisément ceux qui donnent une
pente.

L'élagage est documenté comme un geste de l'utilisateur, au même titre que l'import de la
tâche planifiée (#101).

## 5. Architecture

`Rempart.Core/Drift/` — pur, donc sous test sur le job Linux, comme le moteur de diff.

| Type | Rôle |
|---|---|
| `DriftPoint` | un rapport réduit à ce qu'une série lit : date, score et domaines, empreinte de catalogue, élévation, verdicts par identifiant, constats par clé |
| `DriftSeries.Build(points)` | trie, enchaîne les comparaisons, produit le `DriftReport` |
| `DriftReport` | trajectoire, régressions ouvertes avec leur âge, contrôles instables, fraîcheur |

**La comparaison n'est pas réimplémentée** — mais elle ne suffit pas, et la frontière
mérite d'être écrite ici plutôt que découverte à l'implémentation. `ScanDiff.Compare` est
appelé sur chaque paire consécutive et produit les mouvements que la page liste : une
seconde implémentation de la comparaison pourrait diverger de la vraie, ce que
`DET-SCRIPTS` a déjà coûté une fois.

En revanche, **la régression ouverte et l'instabilité ne s'obtiennent pas en enchaînant des
paires**, et c'est la thèse de ce document plutôt qu'une entorse. Un contrôle qui passe,
devient illisible, puis échoue ne produit *aucune* paire classée `Regression` :
`Pass → Unknown` est une visibilité perdue, `Unknown → Fail` une visibilité retrouvée, et
les deux classements sont justes à leur échelle. La chute n'existe qu'à l'échelle de la
série. Ces deux calculs lisent donc la **suite des états connus** d'une règle, `Unknown` et
`NotApplicable` retirés — ce que ni l'une ni l'autre des paires ne porte.

La règle tient en une ligne : *comparer deux points* reste chez `ScanDiff`, *lire une
suite* est ce que ce moteur ajoute. C'est aussi la meilleure preuve que la commande a une
raison d'exister.

**La clé de série est la machine**, lue dans le rapport. Elle reste stable sur une capture
anonymisée : `Anonymiser.Hash` est un SHA-256 sans sel et idempotent, donc deux captures
du même poste portent le même nom haché. Ce fait est vérifié, pas supposé — et il est
testé, faute de quoi un sel ajouté plus tard découperait silencieusement chaque série en
points isolés.

**Deux empreintes de catalogue dans une même série coupent la pente.** `index` signale
déjà le cas pour le parc ; ici il faut davantage qu'un drapeau, parce qu'une pente est
une soustraction : relier deux scores qui ne sont pas sur la même échelle produirait une
progression ou une chute que rien n'a vécue. Les points sont gardés, la série est
segmentée, et la coupure est dite.

`rempart drift [dossier]` reste une commande mince, sur le modèle d'`IndexCommand` :
découverte des `rapport.json`, groupement, rendu console et page HTML autonome, code de
sortie. Le découpage de chemins reste côté CLI — `Rempart.Core` ne touche pas
`System.IO.Path`, sinon une capture Windows rejouée sur Linux résoudrait autrement.

## 6. Le contrat de sortie (#102)

`ExitCodes.ForDrift(DriftReport)`, à côté de `ForScan` et `ForDiff`, **sans aucun code
nouveau** :

| Code | Quand |
|---|---|
| `1` | dossier introuvable, ou aucun rapport lisible |
| `4` | au moins une régression encore ouverte à la dernière date |
| `5` | la dernière capture porte des contrôles inévaluables, **ou** la série est trouée |
| `0` | sinon |

**Le seuil de « trouée » n'est pas inventé** : c'est la cadence observée de la série
elle-même, médiane des intervalles entre points. En dessous de trois points, aucune
cadence n'est observable et rien n'est affirmé. Le facteur retenu — trois fois la médiane
— est en revanche un **choix et non une mesure** : il tolère un intervalle sauté (une
machine éteinte une semaine sur un rythme hebdomadaire) sans crier. Il est dit comme tel,
au même titre que le seuil de fraîcheur des données d'ADR-002, et se recalera le jour où
des séries réelles auront été observées.

**Le point à attaquer en relecture, et il est écrit ici pour cela.** Faire répondre `5` à
une série périmée étend le sens de « audit partiel ». La justification : le code 5 dit
que *le rapport répond pour moins de machine qu'il n'en a l'air*, et une trajectoire dont
le dernier point a trois mois décrit une machine telle qu'elle était il y a trois mois —
c'est la même phrase. La justification inverse se tient aussi : `5` a jusqu'ici toujours
désigné un contrôle inévaluable, jamais une donnée vieille, et l'alternative est de dire
la péremption sans toucher au code de sortie. Tranché dans le premier sens ; à retourner
si la relecture le réfute, le coût étant d'une ligne.

## 7. Ce que ce jalon ne fait pas

- **Il ne crée pas de tâche planifiée** (#101). Créer une tâche, c'est modifier la
  configuration du système, ce que v1 promet de ne pas faire — la définition est
  versionnée et importée par l'utilisateur.
- **Il n'écrit pas de journal de résumés.** Un second artefact peut diverger du rapport
  dont il dérive ; c'est la classe de défaut que ce dépôt a fermée cinq fois. Le JSON
  reste l'artefact complet, et la série se recalcule.
- **Il ne supprime rien** (§4).
- **Il n'ajoute aucun jugement.** Une règle n'est pas relue, un constat n'est pas
  requalifié : la série lit des rapports déjà jugés.

## 8. Ce qui le prouve

- Séries synthétiques bâties depuis les quatre fixtures versionnées, dates injectées :
  trajectoire, âge d'une régression, contrôle instable, série trouée, série d'un seul
  point, série à catalogues mélangés.
- `ForDrift` couvert par table, comme `ForScan` l'est.
- Le rendu HTML échappe tout ce que la machine a choisi, avec un test qui plante du
  balisage dans chaque champ — la règle de M6 vaut ici sans changement.
- La stabilité de la clé de série est tenue par un test, pas par la lecture d'un fichier.

## Reste ouvert

- **Aucune série réelle n'existe encore.** Le poste de développement n'a pas six mois de
  rapports, et une série fabriquée prouve la non-régression du calcul, pas sa justesse sur
  du réel — c'est exactement ce que `DET-DIRTY` dit d'une fixture compromise fabriquée. La
  première série réelle est ce qui recalera le facteur trois.
- **`5` pour une série périmée** est tranché mais attaquable (§6).
- La rétention est documentée, pas outillée. Si un dossier de rapports devient réellement
  encombrant sur une machine suivie, la question se rouvre — avec une mesure cette fois.
