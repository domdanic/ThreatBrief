@{
    RootModule        = 'ThreatBrief.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'd52839d1-70de-49ac-9884-592fc6e596d9'
    Author            = 'ThreatBrief'
    Description       = 'PowerShell collectors and report generation for ThreatBrief.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'ConvertFrom-CisaKevCatalog',
        'Get-CisaKevCatalog',
        'Invoke-ThreatBriefRefresh',
        'New-ThreatBriefMarkdown'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}

