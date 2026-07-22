# Compiler Rempart

## Prérequis

| | |
|---|---|
| .NET SDK 10 | `winget install Microsoft.DotNet.SDK.10` |
| Build Tools C++ | Requis **uniquement** pour la publication Native AOT (voir plus bas) |

Deux suites, deux régimes :

| Projet | Portée | Où |
|---|---|---|
| `Rempart.Tests.Unit` | `Rempart.Core` seul, rejeu d'instantanés | Partout, sans Windows |
| `Rempart.Tests.Windows` | Vrai registre, API systèmes, scan de bout en bout | Windows uniquement |

```bash
dotnet test                              # les deux
dotnet test tests/Rempart.Tests.Unit     # la partie portable
```

## Publication du binaire

```bash
dotnet publish src/Rempart.Cli -c Release
# → src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe
```

Native AOT exige le linker MSVC, fourni par la charge de travail « Développement Desktop
en C++ » :

```powershell
winget install Microsoft.VisualStudio.BuildTools --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" --accept-package-agreements --accept-source-agreements
```

Lancer cette commande depuis un PowerShell **normal**, pas administrateur : winget
déclenche lui-même l'élévation, et le contexte élevé utilise un cache de sources distinct
qui échoue souvent sur `0x8a15000f : Data required by the source is missing`.

### `vswhere.exe` doit être dans le PATH

Les cibles du compilateur AOT invoquent `vswhere.exe` sans chemin absolu. L'installeur
Visual Studio ne l'ajoute pas au `PATH`, d'où un échec tardif — après plusieurs minutes
de compilation — sur `MSB3073 ... code 123`, alors même que `link.exe` a bien été localisé.

```powershell
$env:PATH += ";${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
```

Ou de façon permanente, via les variables d'environnement utilisateur.

## Smart App Control

Sur une machine où Smart App Control est actif, les assemblys fraîchement compilées
peuvent être **refusées au chargement** :

```
System.IO.FileLoadException: Une stratégie de contrôle d'application a bloqué ce
fichier. (0x800711C7)
```

Le refus se lit dans le journal `Microsoft-Windows-CodeIntegrity/Operational`,
événement 3077 : *did not meet the Enterprise signing level requirements*.

Vérifier l'état de la protection :

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
    -Name VerifiedAndReputablePolicyState   # 0 inactif · 1 actif · 2 évaluation
```

**Ce comportement n'est pas prévisible localement.** Smart App Control soumet chaque
empreinte au service de réputation Microsoft ; certains fichiers passent, d'autres non,
et ni recompiler ni attendre ne constitue une méthode fiable.

### La désactiver : ce qu'on gagne et ce qu'on perd

Ce document affirmait qu'elle **ne se réactive qu'en réinstallant Windows**. C'est
faux, et la correction vaut d'être notée : la
[FAQ Microsoft](https://support.microsoft.com/en-us/windows/smart-app-control-frequently-asked-questions-285ea03d-fa88-4d56-882e-6698afdb7003)
indique que les mises à jour récentes permettent de la réactiver sans installation
propre. L'affirmation venait de l'ancien comportement, longtemps exact, écrit ici de
mémoire au lieu d'être vérifiée.

Observé sur une machine de développement : la désactivation prend effet **sans
redémarrage**, et `VerifiedAndReputablePolicyState` passe à `0` en conservant
`SAC_PreviousState` — Windows garde trace de l'état antérieur.

L'arbitrage reste réel, mais il n'est pas irréversible :

- **la garder active** — les binaires fraîchement compilés seront bloqués de façon
  imprévisible ; la CI valide à votre place ;
- **la désactiver** — le poste de développement devient moins protégé que les postes
  qu'on prépare avec cet outil ;
- **signer le code** — seul correctif qui vaut pour les deux. Un certificat EV a de la
  réputation immédiatement. Point resté ouvert dans l'ADR-001.

Conséquences pratiques :

- **La CI fait foi** sur une machine protégée par Smart App Control. Ses runners
  n'appliquent pas cette stratégie, et y exécutent `rempart diagnose-wmi` et
  `rempart diagnose-tasks` contre le binaire publié : un bug d'interop COM ne se voit
  pas en JIT.
- `verify.ps1` consulte le journal d'intégrité et distingue ce refus d'un échec de
  test — le message de xUnit, lui, ressemble à une régression.
- La signature de code est le seul correctif durable. Point resté ouvert dans
  l'ADR-001, à trancher le jour d'une distribution.

## Rejouer la CI en local

```powershell
./scripts/verify.ps1              # tout
./scripts/verify.ps1 -SkipPublish # sans l'etape AOT, pour une boucle rapide
```

Le script valide la syntaxe des workflows, lance les tests, publie en AOT et vérifie
que le binaire fonctionne **seul** dans un répertoire temporaire. Il applique de lui-même
le correctif `PATH` pour `vswhere.exe`.

`act` rejouerait les workflows plus fidèlement, en conteneur, mais exige Docker — lourd
sur une machine qu'on cherche à garder propre. Ce script exécute les mêmes commandes
directement, ce qui couvre l'essentiel du risque.

La validation de syntaxe demande [`actionlint`](https://github.com/rhysd/actionlint),
optionnel — le script le signale et poursuit sans lui :

```powershell
winget install rhysd.actionlint
```

Il vaut le détour : un workflow invalide échoue au démarrage, **sans job et sans log
consultable**. Diagnostiquer à l'aveugle coûte cher.

## Vérifier le livrable

Le binaire doit fonctionner **seul**, sorti de son dossier de build — c'est la promesse
tenue par la clé USB :

```powershell
Copy-Item ...\publish\rempart.exe $env:TEMP\test\
cd $env:TEMP\test
.\rempart.exe scan
.\rempart.exe capture --out t.json
.\rempart.exe scan --from t.json
```

Taille attendue : environ 9,4 Mo (elle croît avec les surfaces auditées ; 2,6 Mo au
jalon M0). Les `.pdb` du dossier `publish` sont des symboles de débogage et ne sont pas
nécessaires à l'exécution.
