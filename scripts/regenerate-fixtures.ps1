<#
.SYNOPSIS
    Régénère les fixtures synthétiques à partir d'une capture réelle.

.DESCRIPTION
    À lancer après tout changement du catalogue de règles : une règle ajoutée lit une
    clé que les fixtures existantes ne contiennent pas, et le rejeu échoue.

    La substitution s'appuie sur les règles chargées par le moteur lui-même. Un script
    antérieur reparsait le YAML en expressions régulières — une seconde implémentation
    du chargeur, ni versionnée ni testée, que personne d'autre ne pouvait rejouer.

.PARAMETER Source
    Capture réelle servant de base. Par défaut la première trouvée dans
    tests/fixtures/local/, hors dépôt.

.EXAMPLE
    ./scripts/regenerate-fixtures.ps1
    ./scripts/regenerate-fixtures.ps1 -Source tests/fixtures/local/portable-hp.capture.json
#>
[CmdletBinding()]
param(
    [string]$Source
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root

$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

try {
    if (-not $Source) {
        $found = Get-ChildItem 'tests/fixtures/local' -Filter '*.capture.json' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $found) {
            throw "Aucune capture dans tests/fixtures/local/. En produire une avec : rempart capture --out tests/fixtures/local/<nom>.capture.json"
        }
        $Source = $found.FullName
    }

    Write-Host "Base : $Source"

    dotnet build src/Rempart.Cli --configuration Release --nologo --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'La compilation a echoue.' }

    $cli = 'src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/rempart.dll'
    $out = 'tests/fixtures/synthetic'

    # Poste durci. Joint a un domaine pour que les regles conditionnees le soient aussi
    # et se retrouvent reellement evaluees.
    dotnet $cli synthesise --from $Source --out "$out/hardened-win11.capture.json" `
        --profile hardened --name 'anon:000000000001' --domain-joined

    # Aucune cle de durcissement posee : exerce la semantique des defauts Windows,
    # le cas le plus repandu en parc reel.
    dotnet $cli synthesise --from $Source --out "$out/default-win11.capture.json" `
        --profile defaults --name 'anon:000000000002'

    # Scan non eleve : les cles LSA sont hors de portee.
    dotnet $cli synthesise --from $Source --out "$out/restricted-access.capture.json" `
        --profile hardened --name 'anon:000000000003' --domain-joined --not-elevated --deny 'Control\Lsa'

    # Les references sont reecrites par la suite de tests, qui echoue une fois pour
    # forcer leur relecture avant versionnement.
    Remove-Item "$out/*.expected.json" -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host 'Fixtures regenerees. Lancer « dotnet test » : les references seront'
    Write-Host 'reecrites et le test echouera une fois, pour que vous les relisiez.'
}
finally {
    Pop-Location
}
