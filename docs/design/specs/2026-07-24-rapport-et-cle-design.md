# Design — Rapport & packaging clé (M6)

> État : implémenté le 2026-07-24. Un point reste ouvert et il est nommé en fin de
> document : le lecteur de la sortie DISM n'a pas encore été confronté à une exécution
> élevée réelle.

## Contexte

Jusqu'ici la sortie de `rempart scan` était un texte de console et un `--json`. Ni l'un
ni l'autre ne se transmet : on n'envoie pas un terminal, et un JSON de 370 Ko ne se lit
pas. M6 produit l'artefact qu'on remet à quelqu'un, et range la clé USB qui le produit.

## Le rendu est une fonction pure

`ScanResult → texte`, dans `Rempart.Core/Reports/`. Aucun accès au système de fichiers,
aucune horloge, aucune dépendance Windows. Trois conséquences :

- les rendus se testent par propriétés, sans VM ni navigateur ;
- `rempart report` tourne sur n'importe quelle machine, y compris la CI Linux ;
- deux rendus successifs donnent les mêmes octets, ce qu'un test vérifie — sans quoi
  aucune référence versionnée ne tiendrait.

`ReportView` porte la vue dérivée (tris, regroupements, filtres) que **les deux** rendus
consomment. Deux générateurs filtrant les constats chacun de leur côté finiraient par
diverger, et la divergence se présenterait comme un constat visible dans un rapport et
absent de l'autre — le pire défaut possible pour un outil d'audit.

## Trois formats, trois lecteurs

| Format | Pour qui | Contenu |
|---|---|---|
| HTML | celui qui ouvre le rapport | résumé + constats signalés, constats bénins repliés |
| Markdown | celui qui colle dans un ticket | même contenu, sans rien de replié — le texte brut se lit aussi |
| JSON | l'outil suivant | **complet**, constats bénins compris ; source de `report` et de `diff` (M7) |

Le Markdown n'est pas un HTML dégradé. Il est lu en texte brut aussi souvent que rendu,
donc rien n'y est masqué derrière un repli : ce qu'on replierait en HTML n'a simplement
pas sa place dans ce format, et reste au JSON.

## Ce que la machine auditée choisit

Un rapport est fabriqué avec des lignes de commande, des chemins et des noms
d'extensions — des chaînes que choisit qui se trouve sur la machine auditée.

**En HTML**, un service nommé `<script>` doit s'afficher, pas s'exécuter chez la personne
qui lit l'audit. C'est le seul endroit du projet où une erreur de formatage devient une
vulnérabilité. D'où `Escape` sur *chaque* interpolation, guillemets compris, et un test
qui plante la même charge dans tous les champs influençables.

**Le script en ligne ne reçoit aucune donnée.** Il bascule un thème et masque des nœuds
déjà présents dans le document. Sérialiser les constats dans du JavaScript aurait ouvert
une seconde voie d'injection, avec ses propres règles d'échappement, juste à côté de
celle qui compte. Il n'y a rien à se tromper ici parce qu'il n'y a rien ici.

**En Markdown**, le danger est différent : un pipe dans un chemin de service ne casse pas
le rendu, il décale toutes les colonnes suivantes d'un cran. La ligne reste plausible et
attribue une valeur au mauvais champ. D'où l'échappement des pipes, et l'absence
d'accents graves autour des valeurs machine dans les tableaux — un span de code qui ne se
referme pas déborde sur la cellule voisine.

### Autonome veut dire sans référence, pas sans URL

Le HTML n'a ni `<link>`, ni `<img>`, ni `src=`, ni `href=`, ni `@import`, ni `url(`, et
son script n'appelle ni `fetch` ni `XMLHttpRequest`. Une seule référence externe ferait
de l'ouverture du rapport un appel réseau depuis la machine du lecteur, et signalerait
qu'il a été ouvert.

En revanche les URL **trouvées sur la machine** — permissions d'hôtes d'une extension,
adresse d'un PAC, proxy — s'affichent : les masquer viderait le rapport de son objet.
Elles restent du texte inerte, jamais un lien. Le premier test écrit interdisait la
sous-chaîne `://` ; il est tombé au premier scan réel, sur les permissions d'uBlock
Origin. Il visait la mauvaise propriété.

## Les notes de provenance vivent dans le résultat

`ScanResult` porte `UpdateNote`, `IntegrityNote` et `RulesNote`. Elles répondent à la
même question sous trois formes : *ce rapport est-il comparable à un autre ?*

Le choix de les porter dans le résultat plutôt que de les passer au rendu vient de
`rempart report --from` : une note vivant à côté du résultat disparaîtrait du rapport
re-fabriqué, et « la mise à jour a été refusée » est précisément la phrase qui ne doit
jamais manquer (ADR-002, D14 et D17).

## Le sceau de la clé

`rempart seal` produit un manifeste **signé** par la clé d'éditeur d'ADR-002 — même
ancre de confiance, même clé publique épinglée, même vérificateur.

**Pourquoi signé.** Une liste d'empreintes posée à côté des fichiers qu'elle décrit ne
protège de rien : qui modifie un fichier recalcule la ligne. La signature demande une
clé privée hors ligne.

**Ce qu'il ne fait pas, et ça compte.** Un binaire qui se vérifie lui-même prouve peu :
un `rempart.exe` remplacé peut annoncer que tout va bien. Le contrôle vaut lancé *depuis
une copie sûre* contre une clé dont on doute ; sur la clé elle-même, c'est une détection
d'erreur, pas une protection. Le dire est l'essentiel — un sceau présenté comme une
garantie qu'il n'apporte pas est pire que pas de sceau.

**Ce qui en est exclu.** `reports/` et `rempart-data/` changent à l'usage normal, et un
sceau perpétuellement rompu cesse d'être lu. Le magasin n'y perd rien : D13 le revérifie
déjà contre son propre manifeste signé à chaque scan.

**Un fichier ajouté est signalé** au même titre qu'un fichier modifié. Poser une DLL à
côté de l'exécutable, trouvée avant la copie système, est le vecteur ; un contrôle qui ne
regarderait que les noms qu'il connaît déjà ne le verrait jamais.

Le sceau réutilise l'enveloppe signée du canal de mise à jour plutôt que d'en créer une
seconde, via un type de jeu de données `binary`. `UpdateStore` le refuse explicitement et
par son nom : un sceau déposé par erreur dans le magasin doit dire ce qu'il est, pas
renvoyer vers une version plus récente qui n'y changerait rien.

## Espace récupérable

Le seul fournisseur du projet qui lance un autre programme. Il n'y a pas d'API : les
chiffres viennent de `DISM /Cleanup-Image /AnalyzeComponentStore`, et mesurer `WinSxS`
depuis le système de fichiers compterait plusieurs fois les mêmes octets — l'essentiel du
magasin est lié en dur dans l'installation Windows vivante.

Quatre précautions :

- **Verbe d'analyse uniquement.** `/StartComponentCleanup`, qui supprime, est sur le même
  outil, à un mot près. Un test épingle la liste d'arguments : c'est la différence entre
  une v1 qui n'écrit rien et une v1 qui écrit.
- **Chemin absolu**, pris dans le répertoire système. Résoudre `dism.exe` par le `PATH`
  laisserait un fichier déposé dans le dossier courant décider de ce que lance un outil
  d'audit — sur les machines mêmes qu'il est là pour suspecter.
- **`/English`**, pour que le lecteur affronte un seul jeu de libellés. Sans ça les
  chiffres seraient lus correctement sur une machine en anglais et nulle part ailleurs,
  et l'échec serait silencieux.
- **Opt-in** (`--analyze-store`) : des dizaines de secondes de réponse, et l'élévation
  exigée. Même raisonnement que `--probe-dns`, pour un coût local au lieu d'un coût réseau.

Le découpage par couche *est* le livrable. La part partagée avec Windows fait l'essentiel
du magasin et n'est pas récupérable : le conseil courant de « vider WinSxS » cite un
chiffre composé surtout des fichiers sur lesquels le système tourne.

**Le lecteur refuse plutôt que de deviner.** Libellés absents, format changé, langue
passée au travers : le résultat est une lecture en échec portant ce qui a été vu, jamais
un jeu de zéros. « Zéro octet récupérable » est une réponse ; « la sortie ne l'a pas dit »
en est une autre, et un rapport ne doit pas imprimer la première quand il veut dire la
seconde.

## Vérifié sur machine réelle (2026-07-24)

- Scan réel avec `--report` : 759 constats, 44 échecs, rapport HTML de 172 Ko ouvert dans
  un navigateur, thèmes clair et sombre, filtre par sévérité mesuré dans le DOM (21
  lignes « élevée » masquées sur 44).
- Re-rendu depuis le JSON : **octet pour octet identique** au HTML du scan.
- Jauges mesurées après correction : piste de 144 px, 67 % → 96 px, 88 % → 127 px,
  92 % → 132 px, 100 % → 144 px.
- `dism.exe` non élevé : code 740 immédiat, y compris sur `/?`. `diagnose-store` le rend
  en `AccessDenied` avec la marche à suivre.
- `rules/` posé à côté du binaire : 83 règles au lieu de 82, empreinte changée, dossier
  nommé dans l'en-tête.
- Sceau absent : rien dans l'en-tête. Sceau non signé par une clé connue : ligne
  « intégrité » disant qu'il ne prouve rien ici.

## Reste ouvert

**Les libellés DISM viennent de la documentation, pas d'une machine.** Aucune exécution
élevée n'a encore confronté `ComponentStoreParser` à une vraie sortie — le poste de
développement refuse l'élévation. Ce qui est garanti aujourd'hui : le lecteur refuse
proprement au lieu d'inventer, et `rempart diagnose-store --raw` existe pour trancher en
une exécution. Tant que ce n'est pas fait, la mesure d'espace récupérable est du code
livré mais non éprouvé, au sens où l'entend CONTRIBUTING pour les règles.
