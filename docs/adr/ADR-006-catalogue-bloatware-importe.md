# ADR-006 : Le catalogue bloatware s'importe d'une liste tierce, le jugement reste au dépôt

**Statut :** Accepté — 2026-07-28, exécuté le même jour (#94 : pipeline d'import ; #95 : quatre constructeurs catalogués par nom de produit, et l'ADR corrigée en conséquence)
**Date :** 2026-07-28
**Décide :** l'éditeur du projet
**Complète :** [ADR-002](ADR-002-mise-a-jour-des-donnees.md), décisions D12 (socle embarqué complet),
D13 (rien sans vérification), D15 (âge des données) et D16 (manifeste signé) ; et
[ADR-001](ADR-001-stack-et-perimetre.md), décision D3 (les données ne sont pas du code)
**Critère visé :** le critère de sortie **M5** de [ROADMAP.md](../ROADMAP.md)

---

## Contexte

M5b a livré un catalogue bloatware de **5 entrées**, toutes des applications Microsoft
livrées avec Windows. Le critère de sortie du lot dit : *« fait quand le catalogue est validé
sur une machine OEM réelle, pas sur une VM »*. Il n'est pas atteint, et il est resté ouvert
au passage en v1.0.0-rc.1 puis rc.2.

Il ne s'agit pas d'un retard. En suivant le chemin, le critère se révèle **non fermable tel
qu'il est écrit** :

- La machine de développement est un assemblage personnel (carte mère MSI), donc sans couche
  constructeur. Elle ne peut pas servir.
- Une VM Hyper-V installée depuis un ISO Microsoft ne porte **aucun** logiciel constructeur :
  ni surcouche, ni service maison, ni logiciel d'essai préinstallé. Le parc de VM, envisagé
  pour ce critère, ne le touche pas — il sert en revanche très bien les dettes suspendues à
  « les défauts varient selon la build » (DET-WINDEFAULT, DET-TLS, DET-IPV6).
- Une machine OEM validerait **un** constructeur et laisserait aveugle sur tous les autres.
  Deux machines en valideraient deux.

## Ce que le critère demandait vraiment

Sous une seule phrase, il y a deux questions de nature différente.

**Le mécanisme fonctionne-t-il ?** Un paquet provisionné est-il distingué d'un paquet installé
par l'utilisateur, `survives_feature_update` est-il renseigné, l'escalade en `Notable`
se produit-elle sur une entrée du catalogue et sur rien d'autre. **C'est déjà démontré, et sur
cette machine** : M5a a relevé 6 paquets provisionnés, M5b a confirmé 3 entrées via
`Get-AppxPackage` avec les PFN exacts et **zéro faux positif sur les 219 logiciels restants**.
Windows livre lui-même des paquets provisionnés — Xbox, Clipchamp, météo Bing. Aucune machine
OEM n'a jamais été nécessaire pour éprouver ce mécanisme.

**Le catalogue est-il complet ?** Aucune machine ne ferme cette question. C'est une question de
**données**, et une question de données ne se ferme pas : elle s'entretient. Le dépôt a déjà
tranché ce point une fois, pour LOLDrivers, et [ADR-002](ADR-002-mise-a-jour-des-donnees.md)
en est la réponse — un jeu de données typé, signé, rafraîchissable par un canal.

Traiter une question de données comme un test à passer une bonne fois est une erreur de
catégorie. C'est elle qui bloque, pas l'absence de matériel.

## Décision

### D18 — Le catalogue s'alimente d'une liste tierce épinglée, jamais d'une recopie manuelle

La source retenue est **[Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat)**,
fichier `Config/Apps.json`, épinglé par empreinte de commit et non par branche.

| Critère | Relevé le 2026-07-28 |
|---|---|
| Licence | **MIT** — `Copyright (c) 2020 Raphire`, compatible avec la nôtre, attribution requise |
| Adoption | **54 011 étoiles, 2 260 forks** |
| Vivante | poussée le **2026-07-26** |
| Format | données structurées **séparées du code**, 38 Ko |
| Contenu | **141 entrées** : `AppId`, `Description`, `Recommendation`, `RemovalMethod` |
| Constructeurs | **25 entrées** — HP 20, Dell 3, Lenovo 2 |
| Méthodes | Appx 138, WinGet 3 |

Deux autres listes ont été examinées et écartées comme source **principale** :
[SysAdminDoc/Debloat-Win11](https://github.com/SysAdminDoc/Debloat-Win11) et
[tomytate/Win-Debloat7](https://github.com/tomytate/Win-Debloat7), MIT toutes les deux, mais à
3 et 4 étoiles, avec leurs listes noyées dans du PowerShell impératif. Pour un jeu de données
de sécurité, une liste qu'aucune communauté n'a éprouvée ne vaut pas mieux que la nôtre.

La première couvre en revanche **ASUS, Acer, MSI et Razer**, absents de Win11Debloat. Elle est
retenue comme source **secondaire, pour les identifiants uniquement**.

> **Rectification du 2026-07-28, en suivant le chemin.** Cette phrase était fausse à l'endroit
> exact qu'elle désigne, et c'est la troisième fois que ce registre l'apprend de la même
> manière : `Modules/OEM.ps1` de la source secondaire **ne porte aucun identifiant de paquet**.
> Il travaille par suppression de dossiers et de clés — 9 `Remove-Item`, 11
> `Remove-ItemProperty`, 3 `Stop-Service` — et sa couverture constructeur est une **regex sur
> les noms d'affichage**, doublée d'une contre-regex `Intel.*Driver|Realtek.*Driver` pour
> défaire son propre sur-appariement. Un outil qui supprime sur ordre explicite peut se le
> permettre ; un outil qui **accuse** ne le peut pas, et `BloatwareMatch.Name` est un
> `Contains` sans forme négative. Voir D23.
>
> La phrase sur la machine de développement était fausse aussi : `StartCN` et `StartDVR`
> avaient été attribuées à MSI Center par déduction, jamais vérifiées. La capture de ce poste
> ne porte aucun logiciel de ces marques.

### D19 — L'amont fournit des faits, le dépôt fournit le jugement, et la jointure échoue sur une entrée non jugée

`fetch-bloatware` ne régénère pas le catalogue : il **joint** deux fichiers.

- **Amont**, récupéré à une révision épinglée : l'identifiant, la méthode de suppression, la
  recommandation. Des faits, vérifiables, et la partie fastidieuse.
- **Dépôt**, versionné et relu : `Category`, `Risk`, `Impact`. Le jugement.
- **Sortie** : le `BloatwareCatalogFile` que l'éditeur signe, et le socle embarqué de D12. Une
  seule chaîne de production, deux destinations — dupliquer serait refaire l'erreur que
  DET-RECPROV et DET-SCRIPTS ont chacune coûté une fois.

Quand l'amont ajoute une entrée, la jointure trouve un identifiant sans jugement et **la
commande refuse d'émettre**, en nommant ce qui manque. La règle que porte déjà le commentaire
de `BloatwareEntry` — *« an entry without an impact note does not get in »* — cesse d'être une
phrase pour devenir un échec de commande.

Le sens de l'échec est délibéré. Émettre l'entrée sans note serait livrer une accusation sans
sa contrepartie ; l'ignorer en silence serait perdre une entrée sans le dire. Les deux sont
des formes que ce dépôt a déjà payées.

### D20 — Une note d'impact déclare sa provenance

Écrire 141 notes d'impact, c'est écrire 141 affirmations sur des logiciels que personne ici
n'a vu tourner. Ce que casse la suppression de `HPPrinterControl` ne peut être que déduit
d'une ligne écrite par un tiers.

C'est le mode d'échec que ce projet s'est infligé trois fois : les libellés DISM tirés de la
documentation plutôt que d'une exécution élevée (DET-DISM), les `windowsDefault` devinés
(DET-WINDEFAULT), et les deux règles retirées parce qu'elles reposaient sur une supposition
(`WIN-DEF-009`, `WIN-FW-006`). La note d'impact est ce qui distingue ce catalogue d'une liste
de debloat ; la remplir de prose plausible la viderait de son sens.

Chaque entrée porte donc la **provenance de sa note** : décrite en amont, ou vérifiée ici sur
une machine. Une note non vérifiée reste utilisable — le logiciel est remonté — mais le
rapport dit d'où elle vient. C'est le même principe que « plage dynamique relevée sur la
machine » contre « plage par défaut de Windows, faute d'avoir pu lire celle de la machine » :
mêmes mots, pas la même affirmation.

Les descriptions d'amont sont d'ailleurs écrites pour un outil de suppression, et certaines
sont inutilisables telles quelles — *« Do not remove if you launched Win11Debloat from Windows
Terminal »* décrit un risque propre à leur script, pas au logiciel.

### D21 — Le critère de sortie M5 est découpé

- **Partie mécanisme : atteinte**, avec les preuves déjà au dossier (6 paquets provisionnés,
  3 entrées confirmées, zéro faux positif sur 219 logiciels).
- **Partie couverture du catalogue : sort des critères de sortie de v1** et devient ce qu'elle
  est — une entrée de données vivante, alimentée par l'import puis par les signalements.

Ce découpage est écrit ici plutôt que appliqué en silence à la feuille de route. Un critère de
sortie qu'on modifie parce qu'il gêne est un critère qu'on n'avait pas ; celui-ci est modifié
parce qu'il posait une question de données sous la forme d'un test, et la raison doit survivre
à la décision.

### D22 — Un identifiant peut être jugé **et** écarté du catalogue — ajouté le 2026-07-28

Trouvé en écrivant les notes, pas en concevant le format, et c'est une lacune de D19 telle
qu'elle était écrite. La jointure n'offrait que deux issues : cataloguer, ou faire échouer la
commande. Or **la liste amont est « ce qu'un outil de debloat propose de retirer », ce qui
n'est pas « ce que Rempart doit appeler bloatware »**. Huit de ses entrées sont le Microsoft
Store, le terminal Windows, le navigateur par défaut, le fournisseur d'identité Xbox et deux
cadriciels dont d'autres logiciels dépendent.

Les cataloguer poserait un constat sur presque chaque machine auditée — précisément le fait de
crier au loup que ce projet refuse depuis M1, et qui a déjà fait retirer deux règles.

Un jugement peut donc porter `"catalogue": false`, avec un `"reason"` **obligatoire**. La
symétrie est le point : cataloguer coûte une note d'impact, écarter coûte un motif. Un écart
silencieux serait la manière dont un identifiant disparaît sans que personne puisse dire
pourquoi un an plus tard. Un identifiant écarté compte comme **jugé** : sans quoi la commande
continuerait de le nommer comme manquant, et la seule façon de la faire taire serait de le
cataloguer à tort.

### D23 — Le dépôt catalogue aussi sans amont, et seulement par nom de produit — ajouté le 2026-07-28

Conséquence de la rectification ci-dessus. Aucune liste maintenue ne porte d'identifiants
exacts pour ASUS, Acer, MSI et Razer : ces applications varient selon le modèle et la région,
et l'usage communautaire pour ces marques est l'appariement par nom.

Le fichier de jugement porte donc un tableau **`additions`** : des entrées que le dépôt
catalogue sans identifiant amont derrière. Elles vivent là, et non ajoutées à la main au
catalogue produit, pour que relancer la jointure ne les efface pas — un fichier généré que
quelqu'un édite à la main est exactement la forme que DET-RECPROV désignait. Elles sont tenues
aux **mêmes règles** qu'une entrée importée : sans note d'impact, la commande refuse.

**On n'y met que des noms de produits, jamais des noms de marques nues.** `Armoury Crate`,
`MyASUS`, `Dragon Center`, `Mystic Light`, `Acer Care`, `Razer Synapse`, `Razer Cortex` — sept
entrées, toutes citées par la source secondaire. Un motif `ASUS` ou `MSI` attraperait les
pilotes du constructeur et signalerait comme indésirable ce qui fait fonctionner la machine.

L'asymétrie qui autorise ce compromis mérite d'être écrite : un motif trop précis **rate** une
installation, un motif trop large **accuse** à tort. Rater est acceptable, accuser ne l'est
pas. C'est pourquoi les sept portent le nom complet du produit, au risque de manquer une
variante de libellé.

## Options considérées

### Option A — Continuer à la main, machine par machine

| Dimension | Évaluation |
|---|---|
| Complexité | Faible |
| Coût | Élevé et récurrent — une machine par constructeur |
| Couverture | Très faible : 5 entrées après un lot entier |
| Bloque v1 | Oui, indéfiniment |

**Pour :** chaque entrée est vérifiée sur du réel, ce qui est la valeur du projet.
**Contre :** ne passe pas à l'échelle, et n'a produit que 5 entrées. Le critère reste ouvert
pour une raison que le clavier ne ferme pas.

### Option B — Importer une liste tierce, verdicts compris

| Dimension | Évaluation |
|---|---|
| Complexité | Faible |
| Coût | Très faible |
| Couverture | 141 entrées immédiatement |
| Bloque v1 | Non |

**Pour :** rapide, large, et l'amont est éprouvé par des dizaines de milliers d'utilisateurs.
**Contre :** rédhibitoire. Les listes de debloat sont **agressives par construction** — leur
promesse est « enlève tout ». Sept entrées y sont marquées `unsafe`, dont le Microsoft Store et
le terminal Windows. Importer leurs verdicts, ce serait livrer des accusations sans savoir ce
que chacune casse, c'est-à-dire exactement ce que le projet refuse depuis M1.

### Option C — Importer les identifiants, écrire le jugement — **retenue**

| Dimension | Évaluation |
|---|---|
| Complexité | Moyenne — une jointure, un fichier de jugement, trois pièges à traiter |
| Coût | 141 notes d'impact à rédiger, une fois |
| Couverture | 141 entrées dont 25 constructeur |
| Bloque v1 | Non |

**Pour :** récupère la partie fastidieuse et vérifiable, garde la partie qui a de la valeur.
Le travail se déplace vers le seul endroit qui distingue cet outil d'un script de debloat.
**Contre :** le mur des 141 notes est réel, et D20 est l'aveu qu'elles ne seront pas toutes
vérifiées.

## Trois pièges relevés dans les données, avant d'écrire une ligne de code

Ils sont consignés ici parce que chacun produit une panne silencieuse, et qu'aucun ne se voit
en lisant les README.

### 1. Les niveaux de risque ne se correspondent pas — axes orthogonaux

Il est tentant de mapper `Recommendation` sur `BloatwareRisk`. **Ce serait faux.**

- `BloatwareRisk` = `{Unwanted, SecurityRelevant}` répond à *pourquoi cette entrée est au
  catalogue*.
- `Recommendation` = `{safe, optional, unsafe}` répond à *ce que ça casse de l'enlever*.

`Microsoft.WindowsStore` est `unsafe` chez eux — dangereux à retirer — et n'a rien de
« security relevant ». À l'inverse, une application de télémétrie peut être `safe` à retirer et
pleinement pertinente pour la sécurité. **`Recommendation` alimente `Impact`, jamais `Risk`.**

### 2. Une entrée n'a pas le schéma des 140 autres

`Microsoft Edge` porte un `AppId` **tableau** là où les autres ont une chaîne — et les deux
valeurs ne sont pas du même espace de noms : `Microsoft.Edge` est un nom de paquet,
`XPFFTQ037JWMHS` un identifiant produit du Microsoft Store. Un import naïf produit une entrée
cassée sans rien signaler.

### 3. Le plus grave : l'appariement ne matcherait rien, en silence

`BloatwareMatch.Pfn` compare par **égalité exacte** (`string.Equals`) contre l'identifiant du
logiciel installé, et le socle actuel stocke des PFN **complets** :
`Microsoft.XboxGamingOverlay_8wekyb3d8bbwe`. L'amont, lui, ne donne que le **nom de paquet**,
sans le condensat d'éditeur : `AD2F1837.HPSupportAssistant`.

Importer tel quel donnerait **141 entrées et zéro détection**, sans qu'aucun test existant ne
rougisse : le catalogue se chargerait, annoncerait son compte, et n'apparierait rien. C'est la
forme de silence que les phases 2 et 3 ont éliminée cinq fois ailleurs.

Le condensat d'éditeur n'est pas dérivable du nom — c'est un condensat de l'identité de
l'éditeur, que l'amont ne porte pas. La correction est donc dans le schéma, pas dans les
données : un mode d'appariement sur le **nom de paquet**, c'est-à-dire le segment qui précède
le `_`. Il faudra en plus un garde qui refuse un catalogue qui n'apparie rien du tout, parce
que cette panne-ci ne se voit pas.

## Conséquences

**Ce qui devient plus facile.** Le catalogue passe de 5 à 141 entrées sans acheter de matériel
ni attendre. M5 cesse de bloquer 1.0.0. Le rafraîchissement devient une commande, sur le patron
déjà éprouvé de `fetch-loldrivers`.

**Ce qui devient plus difficile.** Le dépôt prend une dépendance de données sur un projet tiers,
et hérite de son rythme. Une entrée ajoutée en amont fait échouer `fetch-bloatware` jusqu'à ce
que quelqu'un écrive sa note — voulu, mais c'est une charge d'entretien qui n'existait pas.
`BloatwareMatch` gagne un mode, donc le socle embarqué et les fixtures qui s'y réfèrent devront
être relus.

**Ce qu'il faudra revoir.** La provenance des notes de D20 est un aveu de faiblesse assumé, pas
une fin : chaque capture réelle reçue peut faire passer une note de « décrite en amont » à
« vérifiée ». C'est le même mouvement que DET-WINDEFAULT, et il se mesure — le nombre de notes
vérifiées est un chiffre que le registre de dette peut suivre.

**Ce que cela ne règle pas.** L'état **provisionné** d'une image d'usine reste inobservable
ici : `survives_feature_update` continue de se renseigner sur ce que Windows provisionne
lui-même, jamais sur ce qu'un constructeur ajoute à son image. Aucune liste tierce ne porte
cette information, parce qu'elle dépend de l'image et non du logiciel.

## Actions

1. [ ] Ajouter un mode d'appariement par **nom de paquet** à `BloatwareMatch`, avec le garde
       qui refuse un catalogue n'appariant rien (piège 3)
2. [ ] Écrire le fichier de jugement versionné, indexé par identifiant
3. [ ] `fetch-bloatware` : récupération à révision épinglée, jointure, échec nommé sur entrée
       non jugée, attribution MIT dans le champ `Source`
4. [ ] Traiter le `AppId` tableau comme deux identifiants d'espaces distincts, avec un test
       (piège 2)
5. [ ] Rédiger les 141 notes d'impact, chacune avec sa provenance (D20)
6. [ ] Reprendre le socle embarqué depuis la même jointure, et relire les fixtures qui s'y
       réfèrent
7. [ ] Source secondaire pour ASUS, Acer, MSI et Razer — identifiants seulement
8. [ ] Mettre à jour [ROADMAP.md](../ROADMAP.md) : M5 découpé selon D21
