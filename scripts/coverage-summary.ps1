<#
.SYNOPSIS
    Turns the Cobertura report into a readable summary. Never fails a build.

.DESCRIPTION
    Coverage is an indicator here, not a gate (docs/DEBT.md, DET-COUVERTURE). This script
    prints what the file says and stops there: no threshold, no non-zero exit.

    On GitHub Actions the summary goes to $GITHUB_STEP_SUMMARY, the channel the release
    workflow already uses. Locally it goes to the console. Readable by Windows PowerShell
    5.1 as well as pwsh 7: verify.ps1 calls it on a workstation, CI calls it on Linux.

.PARAMETER ResultsDirectory
    Where `dotnet test --results-directory` put the report.

.PARAMETER Worst
    How many least-covered files to list.

.EXAMPLE
    ./scripts/coverage-summary.ps1 -ResultsDirectory artifacts/coverage
#>
[CmdletBinding()]
param(
    [string]$ResultsDirectory = 'artifacts/coverage',
    [int]$Worst = 12
)

# The source paths come out of the PDBs, so they are Linux-style when the report was
# produced in CI and Windows-style when it was produced here. Split-Path and
# [System.IO.Path] would each get one of the two wrong, which is the same reason
# Rempart.Core is forbidden from using System.IO.Path on captured paths.
function Get-ShortPath([string]$path) {
    $normalised = $path.Replace('\', '/')
    $marker = 'src/Rempart.Core/'
    $index = $normalised.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
    if ($index -ge 0) { return $normalised.Substring($index + $marker.Length) }
    return $normalised
}

function Get-Count([string]$value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    return [long]::Parse($value, [System.Globalization.CultureInfo]::InvariantCulture)
}

# Invariant culture on purpose: a summary that reads 87,2 % on the maintainer's machine
# and 87.2 % in CI invites a comparison between two numbers that were never comparable
# anyway (this checkout replays fixtures CI does not have).
function Format-Ratio($covered, $total) {
    if ($null -eq $covered -or $null -eq $total -or $total -eq 0) { return 'n/a' }
    return [string]::Format(
        [System.Globalization.CultureInfo]::InvariantCulture,
        '{0} / {1} ({2:N1} %)', $covered, $total, (100 * $covered / $total))
}

try {
    $report = Get-ChildItem -Path $ResultsDirectory -Recurse -Filter 'coverage.cobertura.xml' `
        -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $report) {
        Write-Host "Aucun rapport Cobertura sous $ResultsDirectory - couverture non mesuree." `
            -ForegroundColor Yellow
        return
    }

    [xml]$cobertura = Get-Content -Path $report.FullName -Raw
    $root = $cobertura.coverage

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('## Code coverage - Rempart.Core')
    $lines.Add('')
    $lines.Add('| | Covered |')
    $lines.Add('|---|---|')
    $lines.Add(('| Lines | {0} |' -f (Format-Ratio (Get-Count $root.'lines-covered') (Get-Count $root.'lines-valid'))))
    $lines.Add(('| Branches | {0} |' -f (Format-Ratio (Get-Count $root.'branches-covered') (Get-Count $root.'branches-valid'))))
    $lines.Add('')
    $lines.Add('No threshold: this is an indicator, not a gate.')
    $lines.Add('')

    # A report that does not contain Rempart.Core is the visible symptom of a broken
    # Include filter or a friendlyName that stopped matching. Say so; do not fail.
    $packages = @($root.packages.package | ForEach-Object { [string]$_.name })
    if ($packages -notcontains 'Rempart.Core') {
        $lines.Add(('**Rempart.Core is absent from this report** — packages measured: {0}. ' -f ($packages -join ', ')) +
            'The coverage filter is no longer doing what it says.')
        $lines.Add('')
    }

    $lines.Add('Measured on the fixtures present in this checkout. `tests/fixtures/local/` is gitignored, ' +
        'so a workstation run replays more captures than CI and reports a different figure (DET-FIXTURE-LOCALE).')

    # Aggregated per file rather than per class: a partial or nested class would otherwise
    # be split across several rows that each look like a separate file.
    $perFile = @{}
    foreach ($package in $root.packages.package) {
        foreach ($class in $package.classes.class) {
            $key = [string]$class.filename
            if (-not $perFile.ContainsKey($key)) {
                $perFile[$key] = [pscustomobject]@{ Covered = 0; Total = 0 }
            }

            foreach ($line in $class.lines.line) {
                $perFile[$key].Total++
                if ([long]$line.hits -gt 0) { $perFile[$key].Covered++ }
            }
        }
    }

    if ($perFile.Count -gt 0) {
        $lines.Add('')
        $lines.Add('### Least covered files')
        $lines.Add('')
        $lines.Add('| File | Covered | Total | Uncovered |')
        $lines.Add('|---|---|---|---|')

        $rows = $perFile.GetEnumerator() | ForEach-Object {
            [pscustomobject]@{
                File      = Get-ShortPath $_.Key
                Covered   = $_.Value.Covered
                Total     = $_.Value.Total
                Uncovered = $_.Value.Total - $_.Value.Covered
            }
        } | Sort-Object -Property Uncovered -Descending | Select-Object -First $Worst

        foreach ($row in $rows) {
            $lines.Add(('| `{0}` | {1} | {2} | {3} |' -f $row.File, $row.Covered, $row.Total, $row.Uncovered))
        }
    }

    $text = ($lines -join "`n")

    if ($env:GITHUB_STEP_SUMMARY) {
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $text -Encoding utf8
    }

    Write-Host $text
}
catch {
    Write-Host "Resume de couverture indisponible : $($_.Exception.Message)" -ForegroundColor Yellow
    return
}
