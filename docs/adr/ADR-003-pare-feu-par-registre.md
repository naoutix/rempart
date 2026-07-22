# ADR-003 : Lire le pare-feu par le registre plutôt que par COM

**Statut :** Accepté — 2026-07-22
**Date :** 2026-07-22
**Complète :** [ADR-001](ADR-001-stack-et-perimetre.md), décisions D1 (binaire AOT autonome) et D5 (providers abstraits)

---

## Contexte

La règle croisée de M4 — un port en écoute exposé **et** autorisé en entrée sur le profil
Public est réellement joignable, là où un port bloqué par le pare-feu ne l'est pas — exige
de connaître les règles du pare-feu Windows et l'état des profils.

Deux façons de les obtenir :

- **L'interface COM `INetFwPolicy2`** (`HNetCfg.FwPolicy2`) — l'API officielle. Elle rend
  des objets `INetFwRule` riches, résout les mots-clés de port dynamiques (RPC), et reflète
  la politique effective.
- **Le registre** — `…\SharedAccess\Parameters\FirewallPolicy\FirewallRules` (règles
  locales) et `…\Policies\Microsoft\WindowsFirewall` (stratégie de groupe), où chaque règle
  est une chaîne `Clé=Valeur`, plus les réglages de profil sous `PublicProfile`.

Deux contraintes de l'ADR-001 pèsent. **D1** : le livrable est un binaire Native AOT
autonome. **D5** : un instantané doit se rejouer hors-ligne à l'identique, sans la machine.

## Décision

**On lit le pare-feu par le registre**, à travers `IRegistryProvider` (via un
`LiveFirewallProvider` dédié), et on analyse les chaînes de règles dans le cœur
(`FirewallRule.Parse`, `FirewallState`).

## Options considérées

### Option A — Interface COM `INetFwPolicy2`

| Dimension | Évaluation |
|---|---|
| Complexité | Moyenne — énumération d'une collection COM, nombreuses propriétés par règle |
| AOT | Fragile — encore une surface COM à décrire par `GeneratedComInterface`, sans garantie que toutes les propriétés se marshalent |
| Rejouabilité | **Nulle sans effort supplémentaire** — l'objet COM interroge la machine vivante ; il faudrait le convertir en données pour le capturer |
| Fidélité | Haute — mots-clés de port résolus, politique effective |

**Pour :** l'API officielle, la plus fidèle. **Contre :** une seconde dépendance COM sous
AOT, et surtout aucune rejouabilité gratuite — il faudrait de toute façon sérialiser un
modèle de données, donc réintroduire une couche d'analyse.

### Option B — Registre (retenue)

| Dimension | Évaluation |
|---|---|
| Complexité | Faible — lecture de valeurs, analyse d'une chaîne `Clé=Valeur` |
| AOT | Aucune dépendance nouvelle — `IRegistryProvider` existe déjà |
| Rejouabilité | **Native** — les lectures registre sont déjà capturées et rejouées |
| Fidélité | Bonne, à un angle mort près : les **mots-clés de port dynamiques** (`RPC`, `RPC-EPMap`) ne se résolvent pas depuis le registre |

**Pour :** rejouabilité et testabilité gratuites, zéro dépendance COM, analyse pure dans le
cœur. **Contre :** l'angle mort des ports dynamiques, et une reconstitution manuelle de la
sémantique (précédence blocage > autorisation, profil par défaut, portée par application).

## Analyse du compromis

L'arbitrage se joue entre **fidélité** (COM) et **rejouabilité + simplicité AOT**
(registre). Le projet est tout entier bâti sur la rejouabilité (D5) : un audit doit se
rejouer hors-ligne, et chaque machine auditée devient une fixture. Une source de vérité qui
n'existe que sur la machine vivante contredit ce principe. Le registre, lui, passe par le
provider déjà capturé — la règle croisée se teste alors sur un état donné, sans toucher au
pare-feu.

Le prix est assumé : les règles à mot-clé de port dynamique ne sont pas rapprochées d'un
port précis, et on ne prétend pas qu'elles autorisent — on préfère taire une exposition
qu'en inventer une. C'est cohérent avec la ligne du projet : ne pas confondre l'absence de
donnée avec l'absence de menace.

## Conséquences

- Le pare-feu est capturé et rejoué comme le reste ; la règle croisée est testable hors
  ligne (`FirewallReachabilityTests`).
- Angle mort documenté : mots-clés de port dynamiques (`RPC`) non résolus, règles d'app
  empaquetées (`PFN`) non rapprochées d'un chemin. Conservateur par conception.
- L'expansion des variables d'environnement dans les chemins d'application est faite à la
  main (table figée), pour ne pas dépendre de l'hôte du rejeu.
- À revisiter si un besoin de fidélité sur les ports dynamiques émerge : on pourrait alors
  compléter le registre par une lecture COM **au moment de la capture uniquement**, dont le
  résultat serait sérialisé — sans jamais lire COM au rejeu.
