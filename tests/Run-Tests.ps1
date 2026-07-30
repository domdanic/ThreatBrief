[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'src/ThreatBrief.PowerShell/ThreatBrief.psd1'
$fixtureV1 = Join-Path $PSScriptRoot 'fixtures/cisa-kev-v1.json'
$fixtureV2 = Join-Path $PSScriptRoot 'fixtures/cisa-kev-v2.json'
$testDataPath = Join-Path ([IO.Path]::GetTempPath()) ('ThreatBrief.Tests.' + [Guid]::NewGuid().ToString('N'))
$failures = New-Object Collections.Generic.List[string]
$assertions = 0

function Assert-Equal {
    param(
        [Parameter(Mandatory)][object]$Expected,
        [Parameter(Mandatory)][object]$Actual,
        [Parameter(Mandatory)][string]$Because
    )

    $script:assertions++
    if ($Expected -ne $Actual) {
        $script:failures.Add("$Because. Expected '$Expected', got '$Actual'.")
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Value,
        [Parameter(Mandatory)][string]$Because
    )

    $script:assertions++
    if (-not $Value) {
        $script:failures.Add("$Because.")
    }
}

try {
    Import-Module $modulePath -Force

    $catalog = Get-CisaKevCatalog -CatalogPath $fixtureV1
    $records = @(ConvertFrom-CisaKevCatalog -Catalog $catalog)
    Assert-Equal 2 $records.Count 'The fixture should normalize both records'
    Assert-Equal 'CVE-2026-10002' $records[0].Id 'Newest records should sort first'
    Assert-True $records[1].KnownExploited 'Every KEV record should be marked known exploited'
    Assert-True $records[1].RansomwareAssociated 'Known ransomware use should normalize to true'
    Assert-Equal 'CWE-78' $records[1].Cwes[0] 'CWE values should be preserved'

    $baseline = Invoke-ThreatBriefRefresh -DataPath $testDataPath -CatalogPath $fixtureV1
    Assert-True $baseline.Summary.IsBaseline 'The first refresh should establish a baseline'
    Assert-Equal 0 $baseline.Summary.NewRecords 'Historical baseline records should not be announced as new'
    Assert-Equal 2 $baseline.Summary.RecentRecords 'Recent baseline records should remain readable'
    Assert-True (Test-Path -LiteralPath $baseline.Output.MarkdownReport) 'The baseline Markdown report should exist'
    Assert-True (Test-Path -LiteralPath $baseline.Output.JsonReport) 'The baseline JSON report should exist'
    $baselineMarkdown = [IO.File]::ReadAllText($baseline.Output.MarkdownReport)
    Assert-True ($baselineMarkdown.Contains('CVE-2026-10001')) 'The report should include recent CVE details'
    Assert-True ($baselineMarkdown.Contains('remote code execution vulnerability')) 'The report should include the threat description'

    $second = Invoke-ThreatBriefRefresh -DataPath $testDataPath -CatalogPath $fixtureV2
    Assert-True (-not $second.Summary.IsBaseline) 'The second refresh should compare with saved state'
    Assert-Equal 1 $second.Summary.NewRecords 'One newly added record should be detected'
    Assert-Equal 'CVE-2026-10003' $second.NewRecords[0].Id 'The correct new CVE should be returned'
    Assert-Equal 1 $second.Summary.ChangedRecords 'One changed record should be detected'
    Assert-Equal 'CVE-2026-10001' $second.ChangedRecords[0].Id 'The correct changed CVE should be returned'

    $third = Invoke-ThreatBriefRefresh -DataPath $testDataPath -CatalogPath $fixtureV2
    Assert-Equal 0 $third.Summary.NewRecords 'An unchanged refresh should have no new records'
    Assert-Equal 0 $third.Summary.ChangedRecords 'An unchanged refresh should have no changed records'

    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) {
            Write-Error $failure
        }
        exit 1
    }

    Write-Host ("PASS: {0} assertions on PowerShell {1} ({2})." -f
        $assertions,
        $PSVersionTable.PSVersion,
        $PSVersionTable.PSEdition)
    exit 0
}
finally {
    if (Test-Path -LiteralPath $testDataPath) {
        Remove-Item -LiteralPath $testDataPath -Recurse -Force
    }
}
