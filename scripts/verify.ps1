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
    Collects line coverage for Rempart.Core and Rempart.Windows and prints the same two
    summaries CI prints. Off by default: instrumentation lengthens the very loop this script
    exists to shorten, and the local figure is not comparable to the one CI reports — this
    workstation replays the captures in tests/fixtures/local/, which is gitignored.

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

# CI runs the two suites as two jobs, under two coverage configurations, because the Linux
# job cannot compile Rempart.Windows. Iterating over the same pairs here is what keeps this
# script a replay of CI rather than a second thing that resembles it: one solution-wide run
# under a single --settings would file the Windows results under the Rempart.Core filter and
# publish a report measuring nothing.
$suites = @(
    @{
        Project  = 'tests/Rempart.Tests.Unit'
        Settings = 'tests/coverage.runsettings'
        Results  = 'artifacts/coverage'
        Package  = 'Rempart.Core'
    },
    @{
        Project  = 'tests/Rempart.Tests.Windows'
        Settings = 'tests/coverage.windows.runsettings'
        Results  = 'artifacts/coverage-windows'
        Package  = 'Rempart.Windows'
    }
)

# The commands the publish-aot job runs against the published binary, replayed below against
# the same artifact. Written as a list rather than four typed-out lines because
# BuildChainParityTests reads this array by name and holds it against ci.yml: DET-SCRIPTS is
# this script drifting from the workflow, and the drift it has already produced once was
# nobody noticing that a list existed in only one of the two files.
$aotDiagnostics = @('diagnose-wmi', 'diagnose-tasks', 'diagnose-drivers', 'diagnose-processes')

# What release.yml assembles into the stick, and therefore what the isolated run below must
# be given. Declared as a list, by name, for the same reason $aotDiagnostics is:
# BuildChainParityTests reads it and holds it against the workflow's Copy-Item calls.
#
# The absence of 'rules' here is a fact this list exists to keep: the 82 shipped rules are
# compiled into the binary, and a rules/ folder beside the executable is read as an external
# catalogue. v1.0.0-rc.2 shipped one, every identifier collided, and nothing caught it
# because this step used to copy the executable alone -- proving a shape no user receives.
$stickContents = @('rempart.exe', 'README.md', 'LICENSE')

$steps = [ordered]@{}

# The outcomes a step can have. Three, and the third is the point: this script knew only two
# and wrote the passing one for a check that had not run. The workflow step returns early
# whenever actionlint is absent -- deliberately, it is optional and BUILD.md says so -- and
# the final table then showed a green line indistinguishable from a real success. « Pas pu
# verifier » rendered as « verifie » is the one thing this tool refuses to do about a machine;
# the script that verifies the tool was doing it. Declared here rather than spelled at each
# site because BuildChainParityTests reads this map by name and holds the table below
# against it.
$stepStates = [ordered]@{ passed = 'ok'; skipped = 'saute'; failed = 'echec' }

function Step {
    param([string]$Name, [scriptblock]$Body)

    Write-Host ""
    Write-Host "-- $Name " -NoNewline -ForegroundColor Cyan
    Write-Host ('-' * [Math]::Max(0, 60 - $Name.Length)) -ForegroundColor DarkGray

    $script:skipped = $null
    try {
        & $Body
        $script:steps[$Name] = if ($null -ne $script:skipped) {
            [pscustomobject]@{ State = $stepStates.skipped; Detail = $script:skipped }
        } else {
            [pscustomobject]@{ State = $stepStates.passed; Detail = '' }
        }
    }
    catch {
        $script:steps[$Name] = [pscustomobject]@{ State = $stepStates.failed; Detail = $_.Exception.Message }
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# Declares the running step as not run, with the reason the table will carry. A step that
# returns early without calling this is one whose check is written down as having passed.
function Skip-Step {
    param([string]$Reason)

    # Said here as well as in the table: the section is where a reader is looking when it
    # happens, the table is what they read at the end.
    Write-Host $Reason -ForegroundColor Yellow
    $script:skipped = $Reason
}

Step 'Workflows' {
    if (-not (Get-Command actionlint -ErrorAction SilentlyContinue)) {
        Skip-Step "actionlint absent — installer avec : winget install rhysd.actionlint"
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
    $broken = @()
    try {
        foreach ($suite in $suites) {
            $arguments = @('test', $suite.Project,
                '--configuration', 'Release', '--nologo', '--verbosity', 'quiet')
            if ($Coverage) {
                # No inner quotes: PowerShell 5.1 quotes an argument containing spaces on its
                # own, and adding them here reaches dotnet with the quotes still attached.
                $arguments += @(
                    '--collect:XPlat Code Coverage',
                    '--settings', $suite.Settings,
                    '--results-directory', $suite.Results)
            }

            dotnet @arguments

            # Both suites run even when the first one fails, deliberately: stopping here
            # would hide a Windows-layer failure behind a Core one and turn a single run
            # into two, which is how a fast loop stops being fast.
            if ($LASTEXITCODE -ne 0) { $broken += $suite.Project }
        }
    }
    finally {
        $ErrorActionPreference = $previous
    }

    if ($broken.Count -eq 0) { return }

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

    throw "des tests ont echoue : $($broken -join ', ')"
}

if ($Coverage) {
    Step 'Couverture' {
        # The same script CI calls, deliberately: DET-SCRIPTS is about this file drifting
        # from the workflow, and a second implementation of the parsing would be that drift.
        # Two summaries, as CI publishes two: Rempart.Core from the Linux job,
        # Rempart.Windows from the Windows one.
        foreach ($suite in $suites) {
            & (Join-Path $PSScriptRoot 'coverage-summary.ps1') `
                -ResultsDirectory (Join-Path $root $suite.Results) `
                -Package $suite.Package
        }
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

    Step 'Cle assemblee' {

        # The core of the promise: a standalone exe with no runtime -- checked in the exact
        # layout release.yml ships, not on the executable alone. Those were the same thing
        # until they were not, and the day they diverged the released stick could not run a
        # single scan while this step stayed green.
        $publish = Join-Path $root 'src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish'
        $sandbox = Join-Path $env:TEMP "rempart-verify-$PID"

        New-Item -ItemType Directory $sandbox -Force | Out-Null
        try {
            foreach ($item in $stickContents) {
                # The binary comes from the publish output, the rest from the repository --
                # the same two origins release.yml copies from.
                $source = if ($item -eq 'rempart.exe') {
                    Join-Path $publish $item
                } else {
                    Join-Path $root $item
                }

                if (-not (Test-Path $source)) { throw "absent de la disposition : $source" }
                Copy-Item $source $sandbox
            }

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

                # La promotion d'une reference, sur le binaire. Le jugement est une fonction
                # pure de Core que BaselinePromotionTests eprouve ; ce qu'aucune suite ne peut
                # atteindre est le fichier lui-meme -- ni Rempart.Tests.Unit ni
                # Rempart.Tests.Windows ne referencent Rempart.Cli. Or c'est exactement ce que
                # l'issue #100 demande de prouver : qu'un fichier tronque ne remplace pas la
                # reference en place. L'ecriture passe par un fichier temporaire deplace sur
                # la cible, donc meme une coupure laisse l'ancienne entiere.
                & .\rempart.exe scan --json | Set-Content t.rapport.json -Encoding utf8
                # Meme jeu que le scan ci-dessus, et pour la meme raison : 5 est le cas
                # ORDINAIRE sur une machine non elevee. L'exiger a 0 rendrait cette sonde
                # rouge sur toute machine qui n'est pas la plus favorable.
                if ($LASTEXITCODE -notin @(0, 3, 5)) { throw "rempart scan --json a echoue ($LASTEXITCODE)" }

                & .\rempart.exe baseline t.rapport.json | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "la reference n'a pas ete installee ($LASTEXITCODE)" }
                if (-not (Test-Path baseline.json)) { throw "rempart baseline n'a rien ecrit" }
                $installed = (Get-FileHash baseline.json).Hash

                # Le refus, puis la seule chose qui prouve qu'il a servi a quelque chose :
                # l'octet pres, la reference en place n'a pas bouge.
                Set-Content t.tronque.json -Value '{ "toolVersion": "1.1.0", "start' -Encoding utf8
                & .\rempart.exe baseline t.tronque.json | Out-Null
                if ($LASTEXITCODE -ne 1) { throw "un rapport tronque a ete promu ($LASTEXITCODE)" }
                if ((Get-FileHash baseline.json).Hash -ne $installed) {
                    throw "la reference a bouge alors que la promotion etait refusee"
                }

                # DET-OPTION-INCONNUE, sur le binaire. Usage.Check est une fonction pure de
                # Core que toute la suite eprouve ; ce qui la relie a une ligne de commande
                # tient en quelques jetons de Program.cs, que le job Linux ne compile pas. Deux
                # mutations d'un seul jeton y rouvrent le defaut de bout en bout avec la suite
                # verte : supprimer le « return » de la branche de refus, et passer au controle
                # le mot de commande exempte. Aucune garde textuelle ne remplace le fait de
                # lancer le binaire.
                #
                # Ces sondes n'abaissent pas $ErrorActionPreference, et ce paragraphe est la
                # pour qu'on ne le reintroduise pas : mesure sous « powershell.exe -NoProfile
                # -File », PSVersion 5.1.26100.8875, dans la forme exacte de cette etape --
                # les six appels passent et l'etape finit OK. Le travers 5.1 est reel mais ne
                # se declenche que quand la sortie d'erreur du natif est redirigee ou
                # fusionnee : la meme ligne ecrite avec « 2>&1 » et capturee leve bien
                # NativeCommandError. « | Out-Null » ne redirige que la sortie standard.
                #
                # D'abord ce qui ne doit PAS etre refuse. Depuis que le mot de commande l'est,
                # cette moitie du contrat tient a « WordAt(args, 0) ?? Usage.Fallback » dans
                # Program.cs, et rien ne la regardait : ecrire « ?? args[0] » a la place
                # fait rendre 6 a « rempart --help » avec la suite entierement verte. Les
                # quatre facons de demander l'aide sont celles qu'une personne tape. « -h »
                # en est une par decision : elle rendait 0 faute que quiconque la lise,
                # exactement comme « -scan », et elle est declaree dans CommandSurface pour
                # que les deux cessent d'etre le meme cas. Chaque orthographe declaree est
                # lancee ici, ce que BuildChainParityTests exige de cette declaration et
                # jamais d'une liste ecrite dans le test.
                & .\rempart.exe | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart seul n'imprime plus l'aide ($LASTEXITCODE)" }

                & .\rempart.exe --help | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart --help n'imprime plus l'aide ($LASTEXITCODE)" }

                & .\rempart.exe -h | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart -h n'imprime plus l'aide ($LASTEXITCODE)" }

                & .\rempart.exe help | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "rempart help n'imprime plus l'aide ($LASTEXITCODE)" }

                # Puis ce qui doit l'etre, une sonde par branche du refus. D'abord l'option qui
                # n'existe pas -- l'option de rejeu est « --from » --
                & .\rempart.exe scan --replay t.capture.json | Out-Null
                if ($LASTEXITCODE -ne 6) { throw "une option inconnue n'a pas ete refusee ($LASTEXITCODE)" }

                # ... le chemin de la capture tape sans son option ...
                & .\rempart.exe scan t.capture.json | Out-Null
                if ($LASTEXITCODE -ne 6) { throw "un argument nu n'a pas ete refuse ($LASTEXITCODE)" }

                # ... et le mot de commande lui-meme. « rempart scna --replay <capture> »
                # imprimait l'aide et rendait 0 : la faute de frappe emportait avec elle
                # une option qui n'existe pas, et l'ordonnanceur qui ne lit que le code de
                # sortie voyait une reussite. Le mot part maintenant a la porte du refus et
                # non au bras par defaut du dispatch, et c'est ici que ce changement de
                # porte se constate : la porte est dans Rempart.Cli, qu'aucun test du job
                # Linux ne compile.
                & .\rempart.exe scna --replay t.capture.json | Out-Null
                if ($LASTEXITCODE -ne 6) { throw "un mot de commande inconnu n'a pas ete refuse ($LASTEXITCODE)" }

                # ... et le meme mot portant un tiret, qui echappait au refus ci-dessus faute
                # de le rencontrer : WordAt repond « aucun mot de commande » des le premier
                # tiret, si bien que « rempart -scan --from t.json » retombait sur l'aide
                # exemptee et sortait 0 -- mesure sur le binaire publie au tour precedent.
                # La porte est dans Rempart.Cli, qu'aucun test du job Linux ne compile.
                & .\rempart.exe -scan --from t.capture.json | Out-Null
                if ($LASTEXITCODE -ne 6) { throw "un mot de commande a tiret n'a pas ete refuse ($LASTEXITCODE)" }

                # Les memes commandes que le job publish-aot passe au binaire publie, et
                # pour la meme raison : la suite Windows tourne sous JIT, ou l'interop COM
                # ne se comporte pas pareil. Un defaut d'interop a deja laisse WMI mort
                # dans le binaire publie, avec un scan qui sortait 0 et tous les controles
                # WMI « non verifiables ». Ce script pretendait rejouer la CI sans passer
                # ces quatre appels : c'est exactement l'ecart que DET-SCRIPTS decrit.
                foreach ($command in $aotDiagnostics) {
                    & .\rempart.exe $command | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        throw "$command a echoue depuis le binaire AOT ($LASTEXITCODE)"
                    }
                }

                # Parentheses around the concatenation: -f binds tighter than +, so without
                # them the operator applies to the second string alone and the {0} of the
                # first one prints literally. Measured, not guessed -- it did.
                Write-Host (("scan, capture, rejeu et {0} diagnostics fonctionnent sans dependance, " +
                             "depuis la disposition livree ({1} fichiers)") -f $aotDiagnostics.Count, $stickContents.Count)
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
    $step = $steps[$name]

    # The state is printed as it was recorded, never recomputed here: the table cannot say
    # « ok » about a step that did not run, because it prints what Step wrote down.
    $line = if ($step.Detail) {
        "  {0,-20} {1} : {2}" -f $name, $step.State, $step.Detail
    } else {
        "  {0,-20} {1}" -f $name, $step.State
    }

    if ($step.State -eq $stepStates.passed) {
        Write-Host $line -ForegroundColor Green
    }
    elseif ($step.State -eq $stepStates.skipped) {
        # Not counted as a failure, and not counted as a success either. actionlint is
        # optional by design; what was wrong was writing « ok » about it.
        Write-Host $line -ForegroundColor Yellow
    }
    else {
        # Anything this loop does not recognise lands here, red: an unnamed state is a state
        # nobody decided, and this is the safe side to be wrong on.
        Write-Host $line -ForegroundColor Red
        $failed = $true
    }
}
Write-Host ""

Pop-Location
if ($failed) { exit 1 } else { exit 0 }
