<#
.SYNOPSIS
    Rejoue localement ce que fait la CI.

.DESCRIPTION
    Ne remplace pas GitHub Actions : `act` le ferait fidèlement, mais exige Docker.
    Ce script exécute les mêmes commandes, sur cette machine, sans conteneur.

    Ce qu'il couvre en plus de la CI : la vérification que le binaire fonctionne
    réellement seul, hors de son dossier de build — la promesse de la clé USB.

.PARAMETER SkipPublish
    Saute la publication AOT, qui exige les Build Tools C++ et prend plusieurs minutes.
    Utile pour une boucle rapide pendant le développement.

.EXAMPLE
    ./scripts/verify.ps1
    ./scripts/verify.ps1 -SkipPublish
#>
[CmdletBinding()]
param(
    [switch]$SkipPublish
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root

$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

# Les cibles du compilateur AOT invoquent vswhere.exe sans chemin absolu et
# l'installeur Visual Studio ne l'ajoute pas au PATH. Sans cela, la publication
# échoue après plusieurs minutes sur un message qui accuse à tort link.exe.
$vsInstaller = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
if ((Test-Path "$vsInstaller\vswhere.exe") -and ($env:PATH -notlike "*$vsInstaller*")) {
    $env:PATH += ";$vsInstaller"
}

$steps = [ordered]@{}

function Step {
    param([string]$Name, [scriptblock]$Body)

    Write-Host ""
    Write-Host "-- $Name " -NoNewline -ForegroundColor Cyan
    Write-Host ('-' * [Math]::Max(0, 60 - $Name.Length)) -ForegroundColor DarkGray

    try {
        & $Body
        $script:steps[$Name] = 'ok'
    }
    catch {
        $script:steps[$Name] = "ECHEC : $($_.Exception.Message)"
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

Step 'Workflows' {
    if (-not (Get-Command actionlint -ErrorAction SilentlyContinue)) {
        Write-Host "actionlint absent — installer avec : winget install rhysd.actionlint" -ForegroundColor Yellow
        Write-Host "(la validation de syntaxe des workflows est sautée)"
        return
    }

    actionlint
    if ($LASTEXITCODE -ne 0) { throw "actionlint a signale des problemes" }
    Write-Host "syntaxe des workflows valide"
}

Step 'Tests' {
    dotnet test --configuration Release --nologo --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw "des tests ont echoue" }
}

if (-not $SkipPublish) {
    Step 'Publication AOT' {
        dotnet publish src/Rempart.Cli --configuration Release --nologo --verbosity quiet
        if ($LASTEXITCODE -ne 0) { throw "la publication a echoue" }

        $exe = Join-Path $root 'src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe'
        if (-not (Test-Path $exe)) { throw "binaire absent : $exe" }

        $size = [math]::Round((Get-Item $exe).Length / 1MB, 2)
        Write-Host "rempart.exe = $size Mo"
    }

    Step 'Binaire isole' {
        # Le coeur de la promesse : un exe seul, sans runtime ni fichier voisin.
        $exe = Join-Path $root 'src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe'
        $sandbox = Join-Path $env:TEMP "rempart-verify-$PID"

        New-Item -ItemType Directory $sandbox -Force | Out-Null
        try {
            Copy-Item $exe $sandbox
            Push-Location $sandbox
            try {
                & .\rempart.exe version | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart version a echoue" }

                & .\rempart.exe scan | Out-Null
                # 0 = succes, 3 = droits insuffisants — acceptable hors elevation.
                if ($LASTEXITCODE -notin @(0, 3)) { throw "rempart scan a echoue ($LASTEXITCODE)" }

                & .\rempart.exe capture --out t.capture.json | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart capture a echoue" }

                & .\rempart.exe scan --from t.capture.json | Out-Null
                if ($LASTEXITCODE -notin @(0, 3)) { throw "le rejeu a echoue ($LASTEXITCODE)" }

                Write-Host "scan, capture et rejeu fonctionnent sans dependance"
            }
            finally { Pop-Location }
        }
        finally { Remove-Item $sandbox -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host ""
Write-Host ('-' * 62) -ForegroundColor DarkGray
$failed = $false
foreach ($name in $steps.Keys) {
    $result = $steps[$name]
    if ($result -eq 'ok') {
        Write-Host ("  {0,-20} ok" -f $name) -ForegroundColor Green
    }
    else {
        Write-Host ("  {0,-20} {1}" -f $name, $result) -ForegroundColor Red
        $failed = $true
    }
}
Write-Host ""

Pop-Location
if ($failed) { exit 1 } else { exit 0 }
