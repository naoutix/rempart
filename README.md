# Rempart

Audit et durcissement de postes Windows, en un binaire unique exécutable depuis une clé USB.

> **État : M0 terminé.** Le socle tourne — `rempart scan` et `rempart capture` sur un
> binaire unique de 2,6 Mo, sans installation. L'évaluation des règles arrive en M1 ;
> aucune remédiation avant M9.

## Ce que c'est

Un outil d'audit pour préparer plusieurs machines Windows 11 en configuration durcie,
de façon reproductible et traçable. Il inspecte la posture de sécurité, la surface
d'exécution, le réseau, les logiciels installés et l'hygiène système, puis produit un
rapport et un score comparables d'une machine à l'autre.

## Ce que ce n'est pas

- **Pas un « PC optimizer ».** Pas de nettoyage de registre : Microsoft ne le supporte pas,
  le gain est nul et le risque réel.
- **Pas un antivirus ni un outil de défense temps réel.** Il constate, il ne protège pas.
- **Pas un scanner réseau.** Il audite la machine sur laquelle il tourne, rien d'autre.

## Principes

| Principe | Conséquence concrète |
|---|---|
| Audit et remédiation séparés | La v1 n'implémente aucun provider en écriture — l'impossibilité d'écrire est structurelle |
| Hors-ligne par défaut | Tout enrichissement externe est opt-in par exécution ; aucune donnée machine ne sort sans demande |
| Les règles sont des données | Contrôles et catalogues en YAML — un ajout ne demande pas de recompilation |
| Composants critiques intouchables | Edge/WebView2, Store, App Installer et Windows Update sont protégés par une liste codée en dur, vérifiée en CI |
| Jamais d'échec silencieux | Sans les droits nécessaires, un collecteur le signale plutôt que d'omettre |
| Réversibilité explicite | Chaque action de remédiation portera sa classe de réversibilité ; les actions irréversibles n'entrent dans aucun profil |

## Documentation

- [ADR-001](docs/adr/ADR-001-stack-et-perimetre.md) — stack, périmètre v1, principes de sécurité
- [Architecture](docs/ARCHITECTURE.md) — schémas, arborescence, format des règles, stratégie de test
- [Plan d'attaque](docs/ROADMAP.md) — M0 à M12, avec critères de sortie
- [Compiler](docs/BUILD.md) — prérequis, publication AOT, pièges

## Prérequis de développement

- .NET SDK 10
- Windows 11 (l'outil cible Windows ; le développement aussi)
- Hyper-V pour les tests de remédiation (post-v1)

## Licence

[MIT](LICENSE).

L'outil est fourni sans garantie. Il inspecte et, à terme, modifie la configuration
d'un système : la responsabilité de son usage revient à celui qui l'exécute.
