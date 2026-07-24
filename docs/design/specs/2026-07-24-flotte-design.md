# Design — Flotte : diff, baseline et page de parc (M7)

> État : implémenté le 2026-07-24, à la suite de M6 dont il consomme le JSON.

## Contexte

M6 a fait du rapport JSON l'artefact complet. M7 s'en sert : comparer deux postures ne
demande plus qu'aucune des deux machines soit présente, ni même que l'outil tourne sous
Windows.

Le critère de sortie annoncé — « l'écart de posture entre deux machines est lisible d'un
coup d'œil » — est ce qui a piloté toutes les décisions ci-dessous. Un diff qui montre du
mouvement à chaque exécution cesse d'être lu, et le bruit s'est révélé le vrai adversaire
du lot.

## Trois concepts, trois comparaisons

Les collecteurs de champs, les règles et les constats ne se comparent pas de la même
façon, parce qu'ils ne répondent pas à la même question.

| Concept | Clé | Ce qu'on en tire |
|---|---|---|
| Verdicts | identifiant de règle | comment le verdict a bougé, classé |
| Constats | (famille, source, cible) | apparu, disparu, modifié — et en quoi |
| Champs | nom du champ | contexte, moins les volatils |

### Un verdict devenu illisible n'est pas un verdict qui échoue

C'est la distinction pour laquelle tout le classement existe. Un contrôle qui passe de
`Pass` à `Unknown` ne signale pas une machine dégradée : il signale un **audit devenu
aveugle**, typiquement parce que le scan n'était pas élevé. La réponse est de relancer en
administrateur, pas de corriger quoi que ce soit.

Les fondre dans « régression » enterrerait le cas sous des dizaines d'autres — et c'est
précisément celui que personne ne remarquerait autrement, puisque rien dans le rapport ne
le crie. D'où sept catégories : régression, correction, visibilité perdue, visibilité
retrouvée, règle apparue, règle disparue, changement de périmètre.

### L'empreinte, le signal le plus fort d'un diff

Un constat gardant la même famille, la même source et la même cible mais dont le
`sha256` a changé, c'est : *même clé de démarrage, même chemin, un autre binaire
derrière*. Aucune autre ligne d'un rapport ne dit cela aussi platement, et une
comparaison qui ne regarderait que les sévérités le laisserait passer en silence — rien
du jugement n'a bougé.

### Fusion des redirections

Une clé `Run` repointée ailleurs produirait sinon une disparition et une apparition sans
lien apparent, à charge pour le lecteur de recoller. Les deux sont fusionnées en un seul
changement de cible — **mais seulement quand la source ne désigne qu'une chose de chaque
côté**. Certaines familles partagent une source unique pour tout ce qu'elles énumèrent :
tous les pilotes chargés viennent de `Win32_SystemDriver`, et là, un pilote retiré et un
autre ajouté n'ont rien à voir. Inventer ce lien serait pire que ne pas fusionner.

## Le bruit : trois transitoires, dont un imprévu

La roadmap en annonçait deux depuis M3. Le troisième n'est apparu qu'en lançant la
commande.

### RunOnce — annoncé

Windows exécute l'entrée au démarrage suivant puis la supprime. Deux scans de part et
d'autre d'un redémarrage diffèrent sans qu'il se soit rien passé.

### Tâches supprimées après expiration — annoncé, mais mal formulé

La roadmap parlait de « tâches à déclenchement unique ». Ce n'est pas la bonne condition :
une tâche à déclencheur unique **reste listée** après avoir tiré. Windows ne la supprime
que si `Settings/DeleteExpiredTaskAfter` est renseigné **et** qu'un déclencheur porte une
`EndBoundary`. Les deux ensemble, sinon rien.

`ScheduledTask` porte donc désormais ces deux faits bruts, lus dans le XML de définition,
et le jugement reste dans Core — un fournisseur décrit, il ne conclut pas.

**Pas de cas positif réel.** La machine de test porte 196 tâches et aucune n'a l'un ou
l'autre réglage, confirmé indépendamment par `Get-ScheduledTask`. Le zéro a été vérifié,
pas supposé, mais cette branche n'est couverte que par fixture fabriquée.

### Ports éphémères — trouvé en exécutant

Deux scans à quatorze secondes d'écart différaient de trois sockets UDP de Chrome, et de
rien d'autre. Les ports de la plage dynamique (49152–65535, relevé par
`netsh int ipv4 show dynamicport` sur la machine de test) sont renumérotés à chaque
ouverture.

**Ce n'est pas le même phénomène, et la distinction est structurante.** Une entrée
`RunOnce` qui *apparaît* est une nouvelle — c'est ainsi qu'on fait exécuter du code au
prochain démarrage. Un port éphémère qui disparaît et un qui apparaît sont le **même
fait sous un autre numéro**. N'excuser que la disparition aurait divisé le bruit par deux
en laissant le rapport faux.

D'où deux clés de détail :

| Clé | Ce que ça veut dire | Ce que ça excuse |
|---|---|---|
| `transitoire` | le système le retire de lui-même | la disparition seule |
| `éphémère` | son identité change par conception | les deux sens |

Deux garde-fous. Les marqueurs sont posés **par les collecteurs**, qui connaissent le
mécanisme, jamais devinés par le diff à partir d'un chemin de source — un futur
collecteur énumérant quelque chose d'auto-effaçant est traité correctement sans que le
diff apprenne quoi que ce soit. Et ils ne s'appliquent **qu'aux constats déjà jugés
bénins** : un binaire non attesté joignable sur un port haut est une nouvelle à chaque
fois. Ces clés font taire du bruit, jamais un jugement.

La plage dynamique est une constante, non lue depuis la configuration : une machine
l'ayant personnalisée obtient une comparaison un peu plus bruyante, jamais une
affirmation fausse.

## Catalogues différents : comparer quand même

Refuser de comparer deux rapports d'empreintes de règles différentes rendrait la commande
inutilisable dès le lendemain d'une mise à jour — c'est-à-dire la plupart des jours. La
comparaison est faite, l'écart est dit très visiblement, et les règles n'existant que
d'un côté sont listées comme telles plutôt que comptées comme des changements de posture.

## Baseline et page de parc

`baseline.json` posé à côté du binaire tient le même rôle que `rempart-data/` et
`rules/` : la clé se branche et sait à quoi comparer. `rempart diff <rapport.json>` sans
second argument s'y réfère.

La page de parc répond à « quelle machine ensuite ». L'ordre **est** la réponse : score
le plus bas d'abord, et un rapport sans score en tête — une machine qu'on n'a pas pu
noter n'est pas une machine saine. Les rapports issus de catalogues différents sont
signalés, leurs pourcentages n'étant pas sur la même échelle.

## Vérifié sur machine réelle (2026-07-24)

- Deux scans consécutifs, avant marquage des ports : trois lignes de sockets Chrome.
  Après : « Aucun écart de posture. 4 mouvements attendus. »
- Plage dynamique relevée : 49152, 16384 ports, TCP et UDP.
- 196 tâches planifiées, zéro auto-supprimée, recoupé par `Get-ScheduledTask`.
- Trois entrées `RunOnce` réellement marquées (binaires de mise à jour Windows en cache,
  nettoyage Edge).
- `rempart index` sur un dossier de deux rapports : page écrite, lignes ordonnées.

## Reste ouvert

- La branche « tâche supprimée après expiration » n'a pas de cas positif sur machine
  réelle. Suivi en `DET-TACHE-EXPIREE`.
- La plage dynamique est constante plutôt que lue : suffisant tant qu'aucune machine
  auditée ne la personnalise, à reprendre si le cas se présente.
