<#
.SYNOPSIS
    Turns the Cobertura report into a readable summary. Never fails a build.

.DESCRIPTION
    Coverage is an indicator here, not a gate (docs/DEBT.md, DET-COUVERTURE). This script
    prints what the file says and stops there: no threshold, no non-zero exit.

    On GitHub Actions the summary goes to $GITHUB_STEP_SUMMARY, the channel the release
    workflow already uses. Locally it goes to the console. Readable by Windows PowerShell
    5.1 as well as pwsh 7: verify.ps1 calls it on a workstation, CI calls it on Linux.

    That last promise is why this file is saved as UTF-8 *with* a BOM, as verify.ps1 already
    was. Windows PowerShell 5.1 reads a BOM-less file as ANSI, and the em dash below then
    decodes to three characters whose last one is U+201D — a closing double quote, which
    PowerShell accepts as a string delimiter. Measured: the same line inside single quotes
    merely prints mojibake, inside double quotes it makes the whole script fail to parse.
    A guard in BuildChainParityTests keeps every script here from losing the mark.

.PARAMETER ResultsDirectory
    Where `dotnet test --results-directory` put the report.

.PARAMETER Package
    Which assembly the report is expected to be about. Two jobs call this script: the Linux
    one measures Rempart.Core, the Windows one measures Rempart.Windows, which the Linux job
    cannot compile. A second script for the second job is exactly the duplication
    DET-SCRIPTS is about, so the difference is a parameter.

.PARAMETER Worst
    How many least-covered files to list.

.EXAMPLE
    ./scripts/coverage-summary.ps1 -ResultsDirectory artifacts/coverage
    ./scripts/coverage-summary.ps1 -ResultsDirectory artifacts/coverage-windows -Package Rempart.Windows
#>
[CmdletBinding()]
param(
    [string]$ResultsDirectory = 'artifacts/coverage',
    [string]$Package = 'Rempart.Core',
    [int]$Worst = 12
)

# The source paths come out of the PDBs, so they are Linux-style when the report was
# produced in CI and Windows-style when it was produced here. Split-Path and
# [System.IO.Path] would each get one of the two wrong, which is the same reason
# Rempart.Core is forbidden from using System.IO.Path on captured paths.
function Get-ShortPath([string]$path) {
    $normalised = $path.Replace('\', '/')
    $marker = "src/$Package/"
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
    $lines.Add("## Code coverage - $Package")
    $lines.Add('')
    $lines.Add('| | Covered |')
    $lines.Add('|---|---|')
    $lines.Add(('| Lines | {0} |' -f (Format-Ratio (Get-Count $root.'lines-covered') (Get-Count $root.'lines-valid'))))
    $lines.Add(('| Branches | {0} |' -f (Format-Ratio (Get-Count $root.'branches-covered') (Get-Count $root.'branches-valid'))))
    $lines.Add('')
    $lines.Add('No threshold: this is an indicator, not a gate.')
    $lines.Add('')

    # A report that does not contain the expected assembly is the visible symptom of a
    # broken Include filter or a friendlyName that stopped matching. Say so; do not fail.
    $packages = @($root.packages.package | ForEach-Object { [string]$_.name })
    if ($packages -notcontains $Package) {
        $lines.Add(("**$Package is absent from this report** — packages measured: {0}. " -f ($packages -join ', ')) +
            'The coverage filter is no longer doing what it says.')
        $lines.Add('')
    }

    # Both figures move for reasons that have nothing to do with the code, and each moves
    # for its own reason. Saying which one applies is the difference between a caveat and a
    # sentence a reader learns to skip.
    if ($Package -eq 'Rempart.Core') {
        $lines.Add('Measured on the fixtures present in this checkout. `tests/fixtures/local/` is gitignored, ' +
            'so a workstation run replays more captures than CI and reports a different figure (DET-FIXTURE-LOCALE).')
    }
    else {
        $lines.Add('Measured against the machine that ran the suite. Several tests first probe whether the ' +
            'system answers at all and assert nothing when it does not (DET-WMI-FLAKY), so a host with a ' +
            'silent WMI covers fewer lines without anything having regressed.')
    }

    # Aggregated per file rather than per class: a partial or nested class would otherwise
    # be split across several rows that each look like a separate file.
    #
    # The loop variable is NOT called $package, and that is not a style preference.
    # PowerShell variables are case-insensitive, so $package and the $Package parameter above
    # are one variable — and that parameter is declared [string], so the type constraint
    # follows it: every XmlElement assigned by the loop was silently converted to its string
    # representation, $measured.classes came back $null, and this table disappeared from both
    # summaries while the percentages above it stayed correct. It was found by noticing a
    # missing section, not by any error: nothing threw, nothing was logged.
    $perFile = @{}
    foreach ($measured in $root.packages.package) {
        foreach ($class in $measured.classes.class) {
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

    # An empty aggregation over a report that measured something is the symptom above, said
    # out loud. A section that quietly stops being printed is indistinguishable from a
    # section nobody scrolled to.
    if ($perFile.Count -eq 0 -and $packages.Count -gt 0) {
        $lines.Add('')
        $lines.Add('**Per-file breakdown unavailable** - the report names ' +
            "$($packages.Count) package(s) but no class could be read from it.")
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
