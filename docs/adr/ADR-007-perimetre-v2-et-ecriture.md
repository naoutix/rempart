# ADR-007 : Périmètre de la v2, et comment on éprouve une écriture

**Statut :** Proposé — 2026-07-28
**Date :** 2026-07-28
**Décide :** l'éditeur du projet
**Restaure :** [ADR-001](ADR-001-stack-et-perimetre.md), décision **D2** (« la remédiation arrive
en v2 »), que la feuille de route avait diluée en cinq jalons post-v1
**Complète :** [ADR-001](ADR-001-stack-et-perimetre.md) D4 (santé matérielle en add-on) et D5
(abstraction providers), [ADR-005](ADR-005-decoupage-de-la-couche-cli.md) (préconditions CLI)

---

## Contexte

Le plan post-v1 — M8 à M12 — a été écrit **avant** que v1 existe. Il propose cinq jalons pour
le chemin d'écriture complet, un second exécutable à interop matérielle, un couple
client/serveur réseau et une couche d'image. v1 a demandé **huit jalons pour un outil qui ne
fait que lire**.

Le registre de dette a déjà écrit la conclusion, deux fois : *« une cotation d'effort faite en
lisant le code n'est pas une cotation faite en suivant le chemin »*. Ce plan-là n'a suivi aucun
chemin.

Mais le vrai motif de cet ADR n'est pas le compte des jalons. C'est une question d'architecture
que rien n'a tranchée, et dont tout découpage dépend.

## La question : une écriture ne se rejoue pas

Toute la vérifiabilité de v1 tient à un mécanisme. Vingt fournisseurs de lecture derrière des
interfaces ; `rempart capture` fige leurs réponses dans un instantané ; `scan --from` le rejoue.
752 tests tournent sur un job Linux, sans Windows, sur le chemin complet du scan.

**L'écriture casse ce modèle.** On ne rejoue pas une écriture : ce qui compte n'est pas une
valeur lue, c'est un *acte* et son effet sur un état. Il n'existe pas de fixture pour « la clé a
été modifiée puis restaurée ». Le corpus de fixtures — l'actif principal du projet — ne couvre
rien du chemin d'écriture, et ne le couvrira jamais tel quel.

Livrer la remédiation sans répondre à ça, c'est ajouter la seule fonction dangereuse du projet
**dans la seule zone non couverte**. C'est exactement l'argument qui a fait ouvrir
[ADR-005](ADR-005-decoupage-de-la-couche-cli.md) pour la couche CLI, transposé d'un cran plus
haut.

## Décision

### D24 — v2 est la remédiation, et rien d'autre

La feuille de route mélangeait sous « post-v1 » des choses de natures différentes. Elles se
séparent ainsi :

| | Contenu | Ce que ça change |
|---|---|---|
| **1.x** | Suivi de dérive, parc, règles TLS et IPv6 une fois observées, collecteurs supplémentaires, notes d'impact vérifiées | **Rien.** Additif, en lecture seule ; un utilisateur de 1.0 met à jour sans rien réapprendre |
| **2.0** | **Remédiation** | L'outil écrit. C'est la promesse centrale de v1 qui change, et c'est ce qu'un numéro majeur annonce |
| `rempart-hw` | Santé matérielle | Produit séparé, versions séparées — [ADR-001](ADR-001-stack-et-perimetre.md) **D4** |

`rempart-hw` n'est pas un jalon de rempart et n'aurait jamais dû en devenir un : D4 refuse le
pilote noyau dans le binaire principal, parce qu'un pilote de lecture MSR est lui-même une
surface d'attaque, complique la signature et déclenche des antivirus. En faire « M11 » était une
dérive par rapport à l'ADR.

**Le mode appairé (`listen`/`probe`) va en 1.x**, pas en v2 : il lit, il n'écrit rien.

**Conséquence à ne pas manquer.** Les 1.x ne sont pas une salle d'attente avant la vraie
version. Ce sont elles qui accumulent les **captures réelles**, et ce sont les captures réelles
qui ferment `DET-WINDEFAULT` et font passer les 120 notes d'impact de « décrite en amont » à
« vérifiée ». D2 disait *« une fois l'audit éprouvé sur des machines réelles »* : les 1.x **sont**
cette épreuve. Elles ne retardent pas la remédiation, elles la rendent possible.

### D25 — La décision est une valeur, l'écriture est un exécutant bête

C'est la réponse à la question ci-dessus, et elle rend à v2 la testabilité que v1 tenait du
rejeu.

`rempart fix` ne modifie pas la machine en la parcourant. Il produit d'abord un **plan** : une
structure de données décrivant chaque action, la valeur observée, la valeur visée, la
réversibilité, et ce que la correction casse. Le plan est une **valeur pure**, produite dans
`Rempart.Core` à partir d'un `ScanResult`.

Ce que ça débloque, et c'est tout l'intérêt :

- le plan se calcule **à partir d'une fixture**, donc les quatre captures versionnées éprouvent
  la remédiation sans qu'aucune machine soit touchée ;
- le plan se fige en **référence golden**, comme les rendus console de M6 ;
- le plan se sérialise, donc il se transporte, se relit et se compare — `diff` sait déjà faire ça ;
- `--dry-run` cesse d'être un mode à part : c'est **le plan, rendu**. Un mode séparé est une
  seconde implémentation qui peut diverger de la vraie, et ce dépôt a déjà payé ça
  (DET-SCRIPTS).

L'application du plan est alors une couche mince et sans jugement : elle exécute des actions
déjà décidées, dans `Rempart.Windows`, là où vit déjà toute l'interop.

### D26 — Une écriture est vérifiée par une relecture, jamais par son propre succès

La classe de défaut récurrente de v1 est le **silence** : cinq fois, une lecture refusée est
revenue indiscernable d'une réponse propre. En écriture, l'équivalent est pire — une écriture
qui n'a pas pris, ou un rollback qui n'a pas restauré, sans que rien le dise.

Une API qui rend « succès » ne prouve rien : une stratégie de groupe peut réimposer la valeur,
une redirection WOW64 peut écrire ailleurs, un droit peut manquer sur une sous-clé.

Donc : **après chaque action, la valeur est relue par le fournisseur de lecture existant et
comparée à l'intention.** Une action dont la relecture ne confirme pas est rapportée comme
**échouée**, jamais comme appliquée. Le mécanisme ne coûte presque rien — les vingt
fournisseurs de lecture existent déjà — et il transpose au chemin d'écriture le principe que la
phase 2 a appliqué cinq fois : un statut à côté du résultat, jamais à sa place.

### D27 — Le journal de rollback est le plan augmenté de ce qui a été observé

Pas un format de plus. Le plan porte déjà l'action et la valeur visée ; ce qui manque au
rollback est la valeur **observée avant**, et le résultat de la relecture de D26. Un journal est
donc un plan exécuté.

Conséquence : `rempart rollback <session>` n'est pas un moteur nouveau, c'est le même exécutant
appliquant le plan inverse — et ce plan inverse est lui aussi une valeur, donc testable sur
fixture.

### D28 — v2.0 ne corrige que ce que les règles évaluent déjà

Périmètre volontairement étroit pour la première version qui écrit.

**Dedans** : les contrôles adossés au registre, c'est-à-dire l'essentiel des 82 règles. Chacun
déclare déjà son `windowsDefault` et sa valeur attendue ; revenir en arrière est l'écriture de
la valeur précédente, la réversibilité y est donc totale et démontrable.

**Dehors, pour plus tard** : la désinstallation de logiciels (bloatware), la reconfiguration de
services, tout ce que le format d'actions de nettoyage déjà conçu classe en `reinstallable`,
`restore-point-only` ou `irreversible`. Ces actions demandent des garanties qu'on ne sait pas
encore offrir, et les mélanger à la première livraison ferait porter au lot entier le risque de
sa partie la plus dangereuse.

Ce n'est pas un renoncement : c'est l'ordre qui permet de prouver le mécanisme sur le cas
réversible avant de l'étendre au cas qui ne l'est pas.

### D29 — Le test VM apply → rollback → état identique est un critère de sortie, pas une tâche

La feuille de route l'appelait déjà *« le test le plus important du projet »* en le rangeant
parmi six autres cases. Il est promu **critère de sortie de la 2.0**, au même titre que « la clé
tourne sur une machine tierce » l'était pour v1 — et pour la même raison : c'est lui qui
autorise à lancer l'outil sur la machine de quelqu'un d'autre.

Et il s'énonce comme les critères de v1 s'énoncent : une capture avant, une capture après
rollback, et **`rempart diff` doit ne rien trouver**. L'outil est son propre juge, ce qui n'est
possible que parce que la comparaison existe depuis M7.

## Options considérées pour D25

### Option A — Fournisseurs en écriture, testés par des faux

| Dimension | Évaluation |
|---|---|
| Complexité | Faible — symétrique de la lecture |
| Ce que ça prouve | Que le code appelle ce qu'il croit appeler |
| Ce que ça ne prouve pas | Que l'effet sur une vraie machine est celui attendu |

**Pour :** familier, calqué sur D5, marche tout de suite.
**Contre :** insuffisant seul. C'est le niveau de preuve qu'avait `LiveWmiProvider` avant que
les commandes `diagnose-*` existent — et elles existent précisément parce que ce niveau-là
laissait passer une interop morte dans le binaire publié.

### Option B — Tout éprouver en VM

| Dimension | Évaluation |
|---|---|
| Complexité | Élevée — machines, instantanés, orchestration |
| Ce que ça prouve | Beaucoup, sur du réel |
| Coût | Impossible par commit ; des minutes à des dizaines de minutes |

**Pour :** c'est la seule preuve de bout en bout.
**Contre :** en faire le moyen *principal* de test rendrait la boucle de développement
inutilisable et concentrerait toute la vérification sur un mécanisme lent et fragile. Reste
nécessaire — D29 — mais comme porte, pas comme filet.

### Option C — Le plan comme valeur, l'écriture comme exécutant — **retenue**

| Dimension | Évaluation |
|---|---|
| Complexité | Moyenne — un modèle de plan, un planificateur pur, un exécutant mince |
| Ce que ça prouve | Toute la **décision**, sur fixture, sans Windows |
| Coût | Un type de données de plus, et la discipline de ne rien décider dans l'exécutant |

**Pour :** rend au chemin d'écriture le corpus de fixtures et les références golden, c'est-à-dire
ce qui a rendu v1 vérifiable. Fait disparaître `--dry-run` comme mode séparé. Donne le journal
de rollback presque gratuitement (D27).
**Contre :** ne dispense ni de A ni de B — elle les remet à leur place. A devient le mécanisme
d'exécution, B devient la porte de sortie.

## Conséquences

**Ce qui devient plus facile.** La remédiation se teste sur les quatre fixtures existantes, dès
avant qu'une seule ligne d'interop d'écriture existe. Le découpage en jalons cesse d'être
arbitraire : il suit la frontière entre décider et exécuter.

**Ce qui devient plus difficile.** Une discipline nouvelle à tenir : aucun jugement dans
l'exécutant. La tentation sera permanente d'y glisser un « si la clé n'existe pas, alors… », et
ce serait rouvrir exactement le trou que cet ADR ferme. Un garde devra le surveiller, comme
`CommandSurfaceTests` surveille la table de commandes.

**Ce qu'il faudra revoir.** D28 borne v2.0 au registre. L'extension aux actions non réversibles
demandera son propre ADR : le point de restauration, la confirmation individuelle et le
classement par réversibilité sont conçus mais non éprouvés.

**Ce que cela ne règle pas.** Le nombre de jalons. Il découle de ce document et se chiffrera
dans la feuille de route, mais l'ordre de grandeur est déjà lisible : **le seul chemin
d'écriture pèse plus que M1 et M2 réunis**, et l'intuition de départ — cinq jalons pour tout
post-v1 — était fausse d'un facteur trois au moins.

## Actions

1. [ ] Réécrire la section post-v1 de [ROADMAP.md](../ROADMAP.md) selon D24 : 1.x, 2.0,
       `rempart-hw` en produit séparé
2. [ ] Modèle de plan et planificateur pur dans `Rempart.Core`, éprouvé sur les quatre fixtures
3. [ ] Rendu du plan, et `--dry-run` défini comme ce rendu (D25)
4. [ ] Fournisseurs en écriture et relecture de vérification (D26)
5. [ ] Journal de rollback comme plan exécuté, et `rempart rollback` (D27)
6. [ ] Garde : aucun jugement dans la couche d'exécution
7. [ ] Critère de sortie 2.0 : apply → rollback → `rempart diff` ne trouve rien (D29)
