# Fixtures locales — non versionnées

Les captures de machines réelles vivent ici et **ne sont pas versionnées**.

Le dépôt est public. Une capture réelle porte le modèle de carte mère, la version de
BIOS, l'inventaire logiciel et — à partir de M2 — la posture de sécurité de la machine,
faiblesses comprises. C'est une cartographie de points faibles rattachée à une identité
GitHub publique. L'anonymisation masque le hostname et les numéros de série, pas ça.

Les fixtures versionnées, aux valeurs fabriquées, sont dans [`../synthetic/`](../synthetic/).

## Produire une capture locale

```powershell
rempart capture --out tests/fixtures/local/<nom>.capture.json
```

Elle sera rejouée par la suite de tests au même titre que les synthétiques — c'est là
tout l'intérêt : les machines réelles contiennent les cas que personne n'aurait pensé
à fabriquer, à commencer par le bloatware OEM qu'aucune VM ne reproduit.

La première exécution écrit un fichier `.expected.json` de référence, à relire avant
de s'y fier.

## Ce fichier

Seul `README.md` est versionné dans ce répertoire, pour que `tests/fixtures/local/`
existe dans une copie fraîche du dépôt. Un test échoue s'il disparaît.
