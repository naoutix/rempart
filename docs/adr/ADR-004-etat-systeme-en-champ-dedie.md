# ADR-004 : État système volumineux en champ de snapshot dédié, omis du synthétique

**Statut :** Accepté — 2026-07-22
**Date :** 2026-07-22
**Complète :** [ADR-001](ADR-001-stack-et-perimetre.md), décision D5 (providers abstraits, rejeu hors-ligne)

---

## Contexte

À partir de M3, les surfaces auditées ont cessé d'être des valeurs connues d'avance
(clés de registre lues par leur nom) pour devenir des **inventaires** : pilotes chargés,
processus en cours, ports en écoute, état du pare-feu, résolveurs DNS, fichier hosts.

Ces surfaces partagent trois traits qui les distinguent des lectures registre :

1. **Volumineuses** — une machine saine charge ~190 pilotes, tient des dizaines de ports.
2. **Volatiles** — la liste change d'un instant à l'autre.
3. **Structurées** — ce ne sont pas des paires clé/valeur, mais des enregistrements typés.

Deux mécanismes du projet devaient les accueillir : le **snapshot** (ce qu'une capture
enregistre pour le rejeu) et les **fixtures synthétiques** (`synthesise`, qui fabrique des
instantanés versionnés en faisant varier la configuration jugée par les règles).

## Décision

Chaque surface d'état système volumineuse obtient :

1. **Un provider dédié** (`IDriverProvider`, `IListeningPortProvider`, `IFirewallProvider`,
   `IDnsProvider`, `IHostsFileProvider`…), avec ses variantes `Live` / `Recording` /
   `Snapshot`, sur le modèle de `IRegistryProvider` (D5).
2. **Un champ propre dans `MachineSnapshot`** (`Drivers`, `ListeningPorts`, `Firewall`…),
   nullable — le `null` distingue « pas encore capturé » de « rien trouvé ».
3. **L'omission des fixtures synthétiques** : `SyntheticSnapshot.Build` ne recopie que la
   configuration jugée par les règles (registre, services, politique, WMI, tâches,
   signatures). Les inventaires d'état ne sont pas repris.

Le jugement de ces surfaces (un pilote non signé, un port exposé et joignable) est donc
couvert par **des tests unitaires ciblés à base de fakes**, et par le **rejeu d'une capture
réelle locale** (`tests/fixtures/local/`, hors dépôt), pas par les fixtures synthétiques
versionnées.

## Options considérées

### Option A — Tout dans le snapshot ET dans le synthétique

Recopier pilotes/ports/pare-feu dans les fixtures synthétiques versionnées, pour que le
rejeu golden les exerce.

**Contre :** les fixtures gonfleraient de centaines d'entrées bénignes (190 pilotes tous
signés, 40 ports système) sans rien prouver de plus que des tests unitaires ciblés ; le
dépôt étant public, une capture réelle d'inventaire y ferait entrer des chemins et des
adresses d'une machine donnée, que l'anonymisation ne couvre pas tous ; et le volume noierait
la lisibilité — une fixture doit rester un objet qu'on peut lire.

### Option B — Champ dédié, omis du synthétique (retenue)

L'inventaire est capturé (donc rejouable localement), typé (donc sérialisable proprement),
mais absent des fixtures versionnées. Le jugement est testé par des unités et par la capture
locale réelle.

**Pour :** fixtures synthétiques lisibles et sans donnée machine ; jugement testé là où c'est
le plus net (unités déterministes + une vraie machine « sale ») ; snapshot rejouable à
l'identique. **Contre :** les collecteurs d'inventaire « tournent à vide » en rejeu
synthétique — il faut donc que le rejeu bout-en-bout câble les providers snapshot et qu'une
capture réelle locale existe pour les exercer (corrigé en Phase 1 de dette : les 14 providers
sont câblés dans `FixtureReplayTests`).

## Conséquences

- Les fixtures synthétiques restent petites, lisibles, sans donnée d'une machine réelle.
- Le rejeu d'une capture réelle locale est le seul endroit où les collecteurs d'inventaire
  s'exercent bout-en-bout ; ce rejeu **doit** câbler leurs providers snapshot, sans quoi ils
  tournent sur les no-op par défaut et la référence fige « rien trouvé » (le piège corrigé en
  Phase 1 de dette).
- Ajouter une surface impose la mécanique complète : interface + 3 variantes de provider +
  champ de snapshot + câblage aux trois sites `ProviderSet`. Répétitif et assumé ; une
  généralisation par génériques reste une dette ouverte, à traiter si elle freine.
- Le versionnage du schéma de snapshot se fait par **nullité de champ**, pas par
  `SchemaVersion` : un champ absent d'une capture ancienne est traité comme « non collecté »
  et le rejeu reste possible.
