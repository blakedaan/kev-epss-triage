#Requires -Version 7.0
<#
.SYNOPSIS
    Prioritizes a vulnerability scanner export using CISA KEV + FIRST EPSS.

.DESCRIPTION
    Reads any flat CSV of findings, enriches each CVE with known-exploited status
    and exploitation probability, assigns a priority, and writes a per-asset
    detail file plus a deduplicated remediation summary.

.PARAMETER InputCsv
    Scanner export. Column names are auto-detected; override with -ColumnMap.

.PARAMETER OutDir
    Destination for the generated CSVs. Created if missing.

.PARAMETER EpssThreshold
    EPSS probability at or above which a non-KEV CVE is escalated to P1-Watch.

.PARAMETER ColumnMap
    Explicit header overrides, e.g. @{ Cve = 'cve_ids'; Asset = 'hostname' }.

.PARAMETER KevPath
    Use a local KEV JSON file instead of fetching from CISA (offline/air-gapped).

.PARAMETER EpssPath
    Use a local EPSS JSON file instead of querying FIRST.org.

.PARAMETER DryRun
    Print the summary to the console without writing any files.

.EXAMPLE
    .\Invoke-VulnTriage.ps1 -InputCsv .\samples\sample-findings.csv -DryRun

.EXAMPLE
    .\Invoke-VulnTriage.ps1 -InputCsv .\export.csv -OutDir .\output -EpssThreshold 0.3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$InputCsv,

    [string]$OutDir = 'output',
    [ValidateRange(0.0, 1.0)][double]$EpssThreshold = 0.5,
    [hashtable]$ColumnMap = @{},
    [string[]]$EscalateSeverity = @('Critical', 'High'),
    [string]$KevPath,
    [string]$EpssPath,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'src' 'VulnTriage.psm1') -Force

Write-Host "`n[1/4] Reading findings..." -ForegroundColor Cyan
$findings = @(Import-Csv -LiteralPath $InputCsv)
if ($findings.Count -eq 0) { Write-Warning "No rows in $InputCsv."; exit 1 }

$header = $findings[0].PSObject.Properties.Name
$map    = Resolve-ColumnMap -Header $header -ColumnMap $ColumnMap
Write-Host ("      {0} rows | columns -> {1}" -f $findings.Count,
    (($map.GetEnumerator() | Where-Object Value | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')) -ForegroundColor Green

Write-Host "[2/4] Loading CISA KEV catalog..." -ForegroundColor Cyan
$kev = if ($KevPath) { Get-KevCatalog -Path $KevPath } else { Get-KevCatalog }
Write-Host "      $($kev.Count) known-exploited CVEs." -ForegroundColor Green

Write-Host "[3/4] Scoring with EPSS..." -ForegroundColor Cyan
$allCves = $findings |
    ForEach-Object { Get-CveFromText $(if ($map['Cve'] -and $_.PSObject.Properties[$map['Cve']]) { [string]$_.($map['Cve']) }) } |
    Select-Object -Unique
$epss = if ($EpssPath) { Get-EpssScore -Path $EpssPath } else { Get-EpssScore -Cve $allCves }
Write-Host "      $($epss.Count) of $(@($allCves).Count) unique CVEs scored." -ForegroundColor Green

Write-Host "[4/4] Prioritizing..." -ForegroundColor Cyan
$records = Invoke-VulnTriage -Finding $findings -ColumnMap $map -Kev $kev -Epss $epss `
    -EpssThreshold $EpssThreshold -EscalateSeverity $EscalateSeverity
$summary = @(Get-TriageSummary -Record $records)

$counts = $records | Group-Object Priority | Sort-Object Name
Write-Host "`n=== Triage result ===" -ForegroundColor Cyan
Write-Host ("  Records: {0}  |  Unique vulns: {1}" -f $records.Count, $summary.Count) -ForegroundColor Green
foreach ($c in $counts) {
    $color = switch ($c.Name) { 'P1' { 'Red' } 'P1-Watch' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  {0,-9} {1}" -f $c.Name, $c.Count) -ForegroundColor $color
}
$overdue = @($summary | Where-Object KevOverdue)
if ($overdue.Count) { Write-Host "  KEV past due: $($overdue.Count)" -ForegroundColor Red }
$ransom = @($summary | Where-Object KnownRansomware)
if ($ransom.Count) { Write-Host "  Ransomware-linked: $($ransom.Count)" -ForegroundColor Red }

Write-Host "`nTop priorities:" -ForegroundColor Cyan
$summary | Select-Object -First 10 Priority, Cve, Severity, MaxEpssScore, AssetCount, OnCisaKev |
    Format-Table -AutoSize | Out-String | Write-Host

if ($DryRun) { Write-Host "Dry run — no files written.`n" -ForegroundColor Yellow; exit 0 }

if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailPath = Join-Path $OutDir "triage_detail_$stamp.csv"
$sumPath    = Join-Path $OutDir "triage_summary_$stamp.csv"

$records | Export-Csv -LiteralPath $detailPath -NoTypeInformation -Encoding UTF8
$summary | Export-Csv -LiteralPath $sumPath    -NoTypeInformation -Encoding UTF8

Write-Host "Wrote:" -ForegroundColor Green
Write-Host "  $detailPath"
Write-Host "  $sumPath`n"
