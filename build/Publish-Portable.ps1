[CmdletBinding()]
param(
    [string]$Runtime = 'win-x64',
    [string]$VersionLabel = 'v1.1.4'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot "dist\ThreatBrief-$VersionLabel-$Runtime"
$resolvedDist = [IO.Path]::GetFullPath((Join-Path $projectRoot 'dist'))
$resolvedOutput = [IO.Path]::GetFullPath($outputPath)

if (-not $resolvedOutput.StartsWith(
        $resolvedDist + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to publish outside the project dist directory: $resolvedOutput"
}

if (Test-Path -LiteralPath $resolvedOutput) {
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}

dotnet publish (Join-Path $projectRoot 'src\ThreatBrief.Desktop') `
    --configuration Release `
    --runtime $Runtime `
    --self-contained true `
    --output $resolvedOutput

Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') `
    -Destination (Join-Path $resolvedOutput 'README.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') `
    -Destination (Join-Path $resolvedOutput 'LICENSE')

$configPath = Join-Path $resolvedOutput 'data\config'
New-Item -ItemType Directory -Force -Path $configPath | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'defaults\watchlist.json') `
    -Destination (Join-Path $configPath 'watchlist.json')
Copy-Item -LiteralPath (Join-Path $projectRoot 'defaults\secrets.local.example.json') `
    -Destination (Join-Path $configPath 'secrets.local.example.json')

$archivePath = "$resolvedOutput.zip"
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
Compress-Archive -LiteralPath $resolvedOutput -DestinationPath $archivePath
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumPath = "$archivePath.sha256"
[IO.File]::WriteAllText(
    $checksumPath,
    "$hash  $([IO.Path]::GetFileName($archivePath))$([Environment]::NewLine)")

Write-Host "Portable package created at $resolvedOutput"
Write-Host "Release archive created at $archivePath"
Write-Host "Checksum created at $checksumPath"
