#requires -Version 7.4
<#
.SYNOPSIS
    DER v1 package-manifest generator.

.DESCRIPTION
    Builds the protected-file inventory from frozen package bytes. It is part of the trust-chain generation sequence and must never be used to certify a source tree that is still being edited.

.NOTES
    Keep safety boundaries, evidence semantics, and operator-facing behavior explicit
    when editing this tool.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)


# Maintenance notes
# Responsibility: Generates the protected-file manifest from final source bytes; it must not be used to bless a still-changing tree.
# Safety: Tooling must honor its documented no-tenant/no-write boundary.
# Evidence: Output should be deterministic, explicit about PASS/FAIL semantics, and must not describe static checks as runtime/Pester success.
# Packaging: Generate trust/release material only from final source bytes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$packageDir = Join-Path $ProjectRoot 'Definitions\Package'
$manifestPath = Join-Path $packageDir 'DER-PackageManifest.json'
$updatePath = Join-Path $packageDir 'DER-UpdateManifest.json'
$parentPath = Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
$sumsPath = Join-Path $ProjectRoot 'SHA256SUMS.txt'

if (-not (Test-Path -LiteralPath $updatePath)) { throw 'DER update manifest is missing.' }
if (-not (Test-Path -LiteralPath $parentPath)) { throw 'DER parent launcher is missing.' }
$update = Get-Content -LiteralPath $updatePath -Raw | ConvertFrom-Json -Depth 100

function Get-DERManifestRole {
    param([string]$RelativePath)
    if ($RelativePath -like 'Core/*') { return 'Core' }
    if ($RelativePath -like 'Workloads/*') { return 'Workload' }
    if ($RelativePath -like 'Definitions/Schema/*') { return 'Schema' }
    if ($RelativePath -like 'Definitions/*') { return 'Definition' }
    if ($RelativePath -like 'Templates/*') { return 'Template' }
    if ($RelativePath -like 'Tests/*') { return 'Test' }
    if ($RelativePath -like 'Tools/*') { return 'Tool' }
    if ($RelativePath -like 'Docs/*') { return 'Documentation' }
    if ($RelativePath -in @('BUILD-STATUS.md','PROJECT-STRUCTURE.txt')) { return 'Metadata' }
    return 'Other'
}

$exclusions = @(
    'Start-DERIntuneBuilder.ps1',
    'Definitions/Package/DER-PackageManifest.json',
    'SHA256SUMS.txt'
)

$protected = foreach ($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Sort-Object FullName) {
    $relative = [IO.Path]::GetRelativePath($ProjectRoot, $file.FullName).Replace('\','/')
    if ($relative -in $exclusions -or $relative -match '\.(zip|sha256)$') { continue }
    [ordered]@{
        path = $relative
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        bytes = [long]$file.Length
        role = Get-DERManifestRole -RelativePath $relative
    }
}

$manifest = [ordered]@{
    schemaVersion = '1.0'
    packageVersion = [string]$update.packageVersion
    buildNumber = [int]$update.buildNumber
    channel = [string]$update.channel
    engineVersion = [string]$update.engineVersion
    baselineVersion = [string]$update.baselineVersion
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    hashAlgorithm = 'SHA256'
    trustAnchor = [ordered]@{
        relativePath = 'Start-DERIntuneBuilder.ps1'
        manifestHashConstant = 'DERPackageManifestSHA256'
        design = 'The parent launcher pins this manifest hash. Release packages Authenticode-sign the parent after this hash is embedded; the manifest then pins all protected child/package content.'
    }
    protectedFiles = @($protected)
}

New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()

$parent = Get-Content -LiteralPath $parentPath -Raw
$pattern = '(?m)^\$script:DERPackageManifestSHA256\s*=\s*''[0-9a-fA-F]{64}''\s*$'
$replacement = '$script:DERPackageManifestSHA256   = ''{0}''' -f $manifestHash
$updated = [regex]::Replace($parent, $pattern, $replacement, 1)
if ($updated -eq $parent) { throw 'Could not update DERPackageManifestSHA256 in the parent launcher.' }
$updated | Set-Content -LiteralPath $parentPath -Encoding utf8

$sumLines = foreach ($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Sort-Object FullName) {
    $relative = [IO.Path]::GetRelativePath($ProjectRoot, $file.FullName).Replace('\','/')
    if ($relative -eq 'SHA256SUMS.txt' -or $relative -match '\.(zip|sha256)$') { continue }
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant(), $relative
}
$sumLines | Set-Content -LiteralPath $sumsPath -Encoding utf8

[pscustomobject]@{
    PackageVersion = [string]$update.packageVersion
    BuildNumber = [int]$update.buildNumber
    Channel = [string]$update.channel
    ProtectedFiles = @($protected).Count
    ManifestPath = $manifestPath
    ManifestSHA256 = $manifestHash
    SHA256SUMS = $sumsPath
}
