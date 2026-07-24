<#
.SYNOPSIS
    Replays locally what CI does.

.DESCRIPTION
    Does not replace GitHub Actions: `act` would do that faithfully, but requires Docker.
    This script runs the same commands, on this machine, without a container.

    What it covers beyond CI: checking that the binary actually works on its own,
    outside its build folder — the USB-stick promise.

.PARAMETER SkipPublish
    Skips the AOT publish, which requires the C++ Build Tools and takes several minutes.
    Useful for a fast loop during development.

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

# The AOT compiler targets invoke vswhere.exe without an absolute path and the
# Visual Studio installer does not add it to PATH. Without this, the publish fails
# after several minutes with a message that wrongly blames link.exe.
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
    # Windows PowerShell 5.1 turns a native executable's stderr output into a
    # terminating error whenever ErrorActionPreference is Stop. Without this
    # save-and-restore, the script stops on the first line xUnit writes and never
    # reaches the diagnostic below.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        dotnet test --configuration Release --nologo --verbosity quiet
    }
    finally {
        $ErrorActionPreference = $previous
    }

    if ($LASTEXITCODE -eq 0) { return }

    # Smart App Control rejects unsigned assemblies based on a reputation verdict
    # issued by Microsoft for each hash. There is no way to predict or force it
    # locally: some files pass, others do not. The Code Integrity log states it
    # unambiguously, whereas the xUnit message looks like a regression.
    $blocked = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' `
        -MaxEvents 40 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 3077 -and $_.Message -like '*Rempart*' } |
        Select-Object -First 1

    if ($blocked) {
        throw "Smart App Control a bloque une assembly Rempart non signee ($($blocked.TimeCreated)). " +
              "Ce n'est pas une regression du code : la verification revient a la CI, " +
              "dont les runners n'appliquent pas cette strategie. Voir docs/BUILD.md."
    }

    throw "des tests ont echoue"
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

        # The core of the promise: a standalone exe, no runtime, no neighboring files.
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
                # 0 = success, 3 = insufficient rights — acceptable without elevation.
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
