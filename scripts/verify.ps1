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

.PARAMETER Coverage
    Collects line coverage for Rempart.Core and prints the same summary CI prints. Off by
    default: instrumentation lengthens the very loop this script exists to shorten, and the
    local figure is not comparable to the one CI reports — this workstation replays the
    captures in tests/fixtures/local/, which is gitignored.

.EXAMPLE
    ./scripts/verify.ps1
    ./scripts/verify.ps1 -SkipPublish
    ./scripts/verify.ps1 -Coverage
#>
[CmdletBinding()]
param(
    [switch]$SkipPublish,
    [switch]$Coverage
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
        $arguments = @('test', '--configuration', 'Release', '--nologo', '--verbosity', 'quiet')
        if ($Coverage) {
            # No inner quotes: PowerShell 5.1 quotes an argument containing spaces on its
            # own, and adding them here reaches dotnet with the quotes still attached.
            $arguments += @(
                '--collect:XPlat Code Coverage',
                '--settings', 'tests/coverage.runsettings',
                '--results-directory', 'artifacts/coverage')
        }

        dotnet @arguments
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

if ($Coverage) {
    Step 'Couverture' {
        # The same script CI calls, deliberately: DET-SCRIPTS is about this file drifting
        # from the workflow, and a second implementation of the parsing would be that drift.
        & (Join-Path $PSScriptRoot 'coverage-summary.ps1') `
            -ResultsDirectory (Join-Path $root 'artifacts/coverage')
    }
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
                # 0 = tout vu, 3 = un collecteur refuse, 5 = un controle non verifiable.
                # Les trois sont acceptables ici : ce script controle que le binaire tourne
                # sans dependance, pas la posture de la machine qui l'execute. Le 5 est le
                # cas ORDINAIRE et non le cas de bord -- WIN-ENC-001 (BitLocker) revient
                # non verifiable meme en console elevee quand la classe WMI est absente.
                if ($LASTEXITCODE -notin @(0, 3, 5)) { throw "rempart scan a echoue ($LASTEXITCODE)" }

                & .\rempart.exe capture --out t.capture.json | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart capture a echoue" }

                & .\rempart.exe scan --from t.capture.json | Out-Null
                # Le rejeu relit la capture qui vient d'etre prise ici : il porte donc les
                # memes controles non verifiables, et rend le meme code.
                if ($LASTEXITCODE -notin @(0, 3, 5)) { throw "le rejeu a echoue ($LASTEXITCODE)" }

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
