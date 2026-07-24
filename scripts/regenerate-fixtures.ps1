<#
.SYNOPSIS
    Regenerates the synthetic fixtures from a real capture.

.DESCRIPTION
    Run after any change to the rule catalog: an added rule reads a key that the
    existing fixtures do not contain, and the replay fails.

    The substitution relies on the rules loaded by the engine itself. An earlier
    script re-parsed the YAML with regular expressions — a second implementation
    of the loader, neither versioned nor tested, that nobody else could replay.

.PARAMETER Source
    Real capture used as the base. Defaults to the first one found in
    tests/fixtures/local/, kept out of the repository.

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

    # Hardened workstation. Domain-joined so that domain-conditioned rules are too,
    # and actually get evaluated.
    dotnet $cli synthesise --from $Source --out "$out/hardened-win11.capture.json" `
        --profile hardened --name 'anon:000000000001' --domain-joined

    # No hardening key set: exercises the Windows-defaults semantics, the most
    # common case in a real fleet.
    dotnet $cli synthesise --from $Source --out "$out/default-win11.capture.json" `
        --profile defaults --name 'anon:000000000002'

    # Non-elevated scan: the LSA keys are out of reach.
    dotnet $cli synthesise --from $Source --out "$out/restricted-access.capture.json" `
        --profile hardened --name 'anon:000000000003' --domain-joined --not-elevated --deny 'Control\Lsa'

    # The expected references are rewritten by the test suite, which fails once to
    # force their review before they are committed.
    Remove-Item "$out/*.expected.json" -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host 'Fixtures regenerees. Lancer « dotnet test » : les references seront'
    Write-Host 'reecrites et le test echouera une fois, pour que vous les relisiez.'
}
finally {
    Pop-Location
}
