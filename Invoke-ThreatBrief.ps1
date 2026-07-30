[CmdletBinding()]
param(
    [string]$DataPath,
    [string]$CatalogPath,
    [string]$CatalogUri = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    [ValidateRange(1, 3650)]
    [int]$RecentDays = 7
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($DataPath)) {
    $DataPath = Join-Path $PSScriptRoot 'data'
}

Import-Module (Join-Path $PSScriptRoot 'src/ThreatBrief.PowerShell/ThreatBrief.psd1') -Force

$parameters = @{
    DataPath  = $DataPath
    CatalogUri = $CatalogUri
    RecentDays = $RecentDays
}

if ($CatalogPath) {
    $parameters.CatalogPath = $CatalogPath
}

try {
    $result = Invoke-ThreatBriefRefresh @parameters
    Write-Host ("ThreatBrief refresh complete using {0}." -f $PSVersionTable.PSEdition)
    Write-Host ("Catalog records: {0}; new: {1}; changed: {2}" -f
        $result.Summary.TotalRecords,
        $result.Summary.NewRecords,
        $result.Summary.ChangedRecords)
    Write-Host ("Markdown report: {0}" -f $result.Output.MarkdownReport)
    exit 0
}
catch {
    Write-Error ("ThreatBrief refresh failed: {0}" -f $_.Exception.Message)
    exit 1
}
