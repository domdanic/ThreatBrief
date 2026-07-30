Set-StrictMode -Version 2.0

$script:CisaKevSourceUrl = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'

function ConvertTo-UtcDateString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsed)) {
        throw "Invalid date value '$Value'."
    }

    return $parsed.ToUniversalTime().ToString('yyyy-MM-dd')
}

function ConvertTo-RecordFingerprint {
    param([Parameter(Mandatory)][object]$Record)

    $canonical = @(
        $Record.Id,
        $Record.Vendor,
        $Record.Product,
        $Record.Title,
        $Record.DateAdded,
        $Record.DueDate,
        $Record.Description,
        $Record.RecommendedAction,
        $Record.RansomwareAssociated,
        $Record.Notes
    ) -join [char]31

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertFrom-CisaKevCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object]$Catalog)

    process {
        if ($null -eq $Catalog.vulnerabilities) {
            throw 'The CISA KEV catalog is missing its vulnerabilities collection.'
        }

        $records = foreach ($item in @($Catalog.vulnerabilities)) {
            if ([string]::IsNullOrWhiteSpace([string]$item.cveID)) {
                throw 'A CISA KEV entry is missing cveID.'
            }

            [PSCustomObject][ordered]@{
                SchemaVersion         = 1
                Id                    = [string]$item.cveID
                Title                 = [string]$item.vulnerabilityName
                Vendor                = [string]$item.vendorProject
                Product               = [string]$item.product
                Severity              = $null
                Cvss                  = $null
                Published             = $null
                DateAdded             = ConvertTo-UtcDateString $item.dateAdded
                DueDate               = ConvertTo-UtcDateString $item.dueDate
                KnownExploited        = $true
                RansomwareAssociated  = ([string]$item.knownRansomwareCampaignUse -eq 'Known')
                RansomwareStatus      = [string]$item.knownRansomwareCampaignUse
                Description           = [string]$item.shortDescription
                RecommendedAction     = [string]$item.requiredAction
                Notes                 = [string]$item.notes
                Cwes                  = @($item.cwes)
                Source                = 'CISA KEV'
                SourceUrl             = $script:CisaKevSourceUrl
            }
        }

        return @($records | Sort-Object DateAdded, Id -Descending)
    }
}

function Get-CisaKevCatalog {
    [CmdletBinding()]
    param(
        [string]$CatalogPath,
        [string]$CatalogUri = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    )

    if ($CatalogPath) {
        $resolvedPath = (Resolve-Path -LiteralPath $CatalogPath -ErrorAction Stop).Path
        $json = [IO.File]::ReadAllText($resolvedPath, [Text.Encoding]::UTF8)
    }
    else {
        $invokeParameters = @{
            Uri         = $CatalogUri
            Method      = 'Get'
            ErrorAction = 'Stop'
        }

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $invokeParameters.UseBasicParsing = $true
        }

        $response = Invoke-WebRequest @invokeParameters
        $json = $response.Content
    }

    try {
        return $json | ConvertFrom-Json
    }
    catch {
        throw "CISA KEV returned invalid JSON: $($_.Exception.Message)"
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function New-ThreatBriefMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $lines = New-Object Collections.Generic.List[string]
    $lines.Add('# Threat Intelligence Brief')
    $lines.Add('')
    $lines.Add(('Generated: {0}' -f $Result.GeneratedAt))
    $lines.Add('')
    $lines.Add('## CISA KEV summary')
    $lines.Add('')
    $lines.Add(('- Catalog records: **{0}**' -f $Result.Summary.TotalRecords))
    $lines.Add(('- Newly added: **{0}**' -f $Result.Summary.NewRecords))
    $lines.Add(('- Changed: **{0}**' -f $Result.Summary.ChangedRecords))
    $lines.Add(('- Added in the last {0} days: **{1}**' -f
        $Result.Summary.RecentWindowDays,
        $Result.Summary.RecentRecords))
    $lines.Add(('- Ransomware-associated: **{0}**' -f $Result.Summary.RansomwareAssociated))

    if ($Result.Summary.IsBaseline) {
        $lines.Add('')
        $lines.Add('This refresh established the initial baseline. No historical entries are marked as new.')
    }

    $lines.Add('')
    $lines.Add('## Newly added vulnerabilities')
    $lines.Add('')

    if (@($Result.NewRecords).Count -eq 0) {
        $lines.Add('No newly added KEV records were detected.')
    }
    else {
        foreach ($record in @($Result.NewRecords)) {
            $lines.Add(('### {0} - {1}' -f $record.Id, $record.Title))
            $lines.Add('')
            $lines.Add(('- Vendor/product: {0} / {1}' -f $record.Vendor, $record.Product))
            $lines.Add(('- Added by CISA: {0}' -f $record.DateAdded))
            $lines.Add(('- Remediation due: {0}' -f $record.DueDate))
            $lines.Add(('- Ransomware use: {0}' -f $record.RansomwareStatus))
            $lines.Add(('- Required action: {0}' -f $record.RecommendedAction))
            $lines.Add('')
            $lines.Add($record.Description)
            $lines.Add('')
        }
    }

    $lines.Add(('## Recent KEV additions - last {0} days' -f $Result.Summary.RecentWindowDays))
    $lines.Add('')
    if (@($Result.RecentRecords).Count -eq 0) {
        $lines.Add('No KEV entries fall within this reporting window.')
    }
    else {
        foreach ($record in @($Result.RecentRecords)) {
            $lines.Add(('### {0} - {1}' -f $record.Id, $record.Title))
            $lines.Add('')
            $lines.Add(('- Vendor/product: {0} / {1}' -f $record.Vendor, $record.Product))
            $lines.Add(('- Added by CISA: {0}' -f $record.DateAdded))
            $lines.Add(('- Remediation due: {0}' -f $record.DueDate))
            $lines.Add(('- Ransomware use: {0}' -f $record.RansomwareStatus))
            $lines.Add(('- Required action: {0}' -f $record.RecommendedAction))
            $lines.Add('')
            $lines.Add($record.Description)
            $lines.Add('')
        }
    }

    $lines.Add('## Changed vulnerabilities')
    $lines.Add('')
    if (@($Result.ChangedRecords).Count -eq 0) {
        $lines.Add('No existing KEV records changed.')
    }
    else {
        foreach ($record in @($Result.ChangedRecords)) {
            $lines.Add(('- **{0}** - {1}' -f $record.Id, $record.Title))
        }
    }

    $lines.Add('')
    $lines.Add(('Source: [CISA Known Exploited Vulnerabilities Catalog]({0})' -f $script:CisaKevSourceUrl))
    return $lines -join [Environment]::NewLine
}

function Invoke-ThreatBriefRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataPath,
        [string]$CatalogPath,
        [string]$CatalogUri = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        [ValidateRange(1, 3650)]
        [int]$RecentDays = 7
    )

    $stateDirectory = Join-Path $DataPath 'state'
    $normalizedDirectory = Join-Path $DataPath 'normalized'
    $reportDirectory = Join-Path $DataPath 'reports'

    foreach ($directory in @($stateDirectory, $normalizedDirectory, $reportDirectory)) {
        if (-not (Test-Path -LiteralPath $directory)) {
            $null = New-Item -ItemType Directory -Path $directory -Force
        }
    }

    $statePath = Join-Path $stateDirectory 'cisa-kev-state.json'
    $normalizedPath = Join-Path $normalizedDirectory 'cisa-kev-latest.json'
    $jsonReportPath = Join-Path $reportDirectory 'ThreatBrief-Latest.json'
    $markdownReportPath = Join-Path $reportDirectory 'ThreatBrief-Latest.md'

    $catalogParameters = @{ CatalogUri = $CatalogUri }
    if ($CatalogPath) {
        $catalogParameters.CatalogPath = $CatalogPath
    }

    $catalog = Get-CisaKevCatalog @catalogParameters
    $records = @(ConvertFrom-CisaKevCatalog -Catalog $catalog)
    $recentCutoff = [DateTimeOffset]::UtcNow.Date.AddDays(-($RecentDays - 1))
    $recentRecords = @($records | Where-Object {
        $_.DateAdded -and ([DateTimeOffset]::ParseExact(
            $_.DateAdded,
            'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture).Date -ge $recentCutoff)
    })
    $isBaseline = -not (Test-Path -LiteralPath $statePath)
    $previousFingerprints = @{}

    if (-not $isBaseline) {
        $previousState = [IO.File]::ReadAllText($statePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        foreach ($entry in @($previousState.Records)) {
            $previousFingerprints[[string]$entry.Id] = [string]$entry.Fingerprint
        }
    }

    $newRecords = New-Object Collections.Generic.List[object]
    $changedRecords = New-Object Collections.Generic.List[object]
    $stateRecords = New-Object Collections.Generic.List[object]

    foreach ($record in $records) {
        $fingerprint = ConvertTo-RecordFingerprint -Record $record
        $stateRecords.Add([PSCustomObject][ordered]@{
            Id          = $record.Id
            Fingerprint = $fingerprint
        })

        if (-not $isBaseline) {
            if (-not $previousFingerprints.ContainsKey($record.Id)) {
                $newRecords.Add($record)
            }
            elseif ($previousFingerprints[$record.Id] -ne $fingerprint) {
                $changedRecords.Add($record)
            }
        }
    }

    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $result = [PSCustomObject][ordered]@{
        SchemaVersion  = 1
        GeneratedAt    = $generatedAt
        Collector      = 'CISA KEV'
        CatalogVersion = [string]$catalog.catalogVersion
        CatalogDate    = [string]$catalog.dateReleased
        Summary        = [PSCustomObject][ordered]@{
            IsBaseline            = $isBaseline
            TotalRecords          = $records.Count
            NewRecords            = $newRecords.Count
            ChangedRecords        = $changedRecords.Count
            RecentWindowDays       = $RecentDays
            RecentRecords          = $recentRecords.Count
            RansomwareAssociated  = @($records | Where-Object RansomwareAssociated).Count
        }
        NewRecords     = $newRecords.ToArray()
        ChangedRecords = $changedRecords.ToArray()
        RecentRecords  = $recentRecords
        Output         = [PSCustomObject][ordered]@{
            NormalizedCatalog = [IO.Path]::GetFullPath($normalizedPath)
            JsonReport        = [IO.Path]::GetFullPath($jsonReportPath)
            MarkdownReport    = [IO.Path]::GetFullPath($markdownReportPath)
        }
    }

    $state = [PSCustomObject][ordered]@{
        SchemaVersion = 1
        RefreshedAt   = $generatedAt
        CatalogVersion = [string]$catalog.catalogVersion
        Records       = $stateRecords.ToArray()
    }

    Write-Utf8NoBom -Path $normalizedPath -Content ($records | ConvertTo-Json -Depth 8)
    Write-Utf8NoBom -Path $jsonReportPath -Content ($result | ConvertTo-Json -Depth 8)
    Write-Utf8NoBom -Path $markdownReportPath -Content (New-ThreatBriefMarkdown -Result $result)
    Write-Utf8NoBom -Path $statePath -Content ($state | ConvertTo-Json -Depth 5)

    return $result
}

Export-ModuleMember -Function @(
    'ConvertFrom-CisaKevCatalog',
    'Get-CisaKevCatalog',
    'Invoke-ThreatBriefRefresh',
    'New-ThreatBriefMarkdown'
)
