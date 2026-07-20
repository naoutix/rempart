# Compiler Rempart

## Prérequis

| | |
|---|---|
| .NET SDK 10 | `winget install Microsoft.DotNet.SDK.10` |
| Build Tools C++ | Requis **uniquement** pour la publication Native AOT (voir plus bas) |

Les tests ne demandent que le SDK : ils ne touchent que `Rempart.Core` et rejouent des
instantanés, sans Windows ni linker.

```bash
dotnet test
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

Taille attendue : environ 2,6 Mo. Les `.pdb` du dossier `publish` sont des symboles de
débogage et ne sont pas nécessaires à l'exécution.
