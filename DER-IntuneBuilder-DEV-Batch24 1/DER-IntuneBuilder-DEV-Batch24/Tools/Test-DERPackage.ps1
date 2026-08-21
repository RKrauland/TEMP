#requires -Version 7.4
<#
.SYNOPSIS
    DER v1 package-integrity validator.

.DESCRIPTION
    Validates the parent trust anchor, protected-file manifest, update/dependency/signing contracts, checksums, inventory, and optional Authenticode requirements without authenticating to a tenant.

.NOTES
    Keep safety boundaries, evidence semantics, and operator-facing behavior explicit
    when editing this tool.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$RequireSigned
)


# Maintenance notes
# Responsibility: Validates package inventory, hashes, signatures/posture, and parent trust-anchor consistency without tenant access.
# Safety: Tooling must honor its documented no-tenant/no-write boundary.
# Evidence: Output should be deterministic, explicit about PASS/FAIL semantics, and must not describe static checks as runtime/Pester success.
# Packaging: Generate trust/release material only from final source bytes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$parentPath = Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
$manifestPath = Join-Path $ProjectRoot 'Definitions\Package\DER-PackageManifest.json'
$updatePath = Join-Path $ProjectRoot 'Definitions\Package\DER-UpdateManifest.json'
$dependencyPath = Join-Path $ProjectRoot 'Definitions\Package\DER-DependencyLock.json'
$signingPath = Join-Path $ProjectRoot 'Definitions\Package\DER-SigningPolicy.json'
$sumsPath = Join-Path $ProjectRoot 'SHA256SUMS.txt'

foreach ($required in @($parentPath,$manifestPath,$updatePath,$dependencyPath,$signingPath,$sumsPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw ('Required package file missing: {0}' -f $required) }
}

$parent = Get-Content -LiteralPath $parentPath -Raw
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 100
$update = Get-Content -LiteralPath $updatePath -Raw | ConvertFrom-Json -Depth 100
$dependencyLock = Get-Content -LiteralPath $dependencyPath -Raw | ConvertFrom-Json -Depth 100
$signing = Get-Content -LiteralPath $signingPath -Raw | ConvertFrom-Json -Depth 100

$hashMatch = [regex]::Match($parent, '(?m)^\$script:DERPackageManifestSHA256\s*=\s*''([0-9a-fA-F]{64})''\s*$')
if (-not $hashMatch.Success) { throw 'Parent trust-anchor manifest hash constant is missing.' }
$actualManifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
if ($actualManifestHash -ne $hashMatch.Groups[1].Value.ToLowerInvariant()) { throw 'Parent trust-anchor hash does not match DER-PackageManifest.json.' }

$expected = @{}
foreach ($entry in @($manifest.protectedFiles)) {
    $relative = ([string]$entry.path).Replace('\','/')
    $key = $relative.ToLowerInvariant()
    if ($expected.ContainsKey($key)) { throw ('Duplicate protected path: {0}' -f $relative) }
    $expected[$key] = $true
    $path = Join-Path $ProjectRoot ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Protected file missing: {0}' -f $relative) }
    if ((Get-Item -LiteralPath $path).Length -ne [long]$entry.bytes) { throw ('Protected file length mismatch: {0}' -f $relative) }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne ([string]$entry.sha256).ToLowerInvariant()) { throw ('Protected file hash mismatch: {0}' -f $relative) }
}

$special=@('start-derintunebuilder.ps1','definitions/package/der-packagemanifest.json','sha256sums.txt')
foreach ($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File) {
    $relative = [IO.Path]::GetRelativePath($ProjectRoot,$file.FullName).Replace('\','/')
    $key=$relative.ToLowerInvariant()
    if($key -in $special -or $relative -match '\.(zip|sha256)$'){continue}
    if (-not $expected.ContainsKey($key)) { throw ('Untracked package file: {0}' -f $relative) }
}

if ([string]$manifest.packageVersion -ne [string]$update.packageVersion -or [int]$manifest.buildNumber -ne [int]$update.buildNumber -or [string]$manifest.engineVersion -ne [string]$update.engineVersion -or [string]$manifest.baselineVersion -ne [string]$update.baselineVersion) {
    throw 'Package/update manifest versions are not aligned.'
}
$parentPackage = [regex]::Match($parent, '(?m)^\$script:DERPackageVersion\s*=\s*''([^'']+)''\s*$')
$parentBuild = [regex]::Match($parent, '(?m)^\$script:DERPackageBuildNumber\s*=\s*(\d+)\s*$')
$parentPinnedPowerShell = [regex]::Match($parent, '(?m)^\$script:DERPinnedPowerShell\s*=\s*''([^'']+)''\s*$')
if (-not $parentPackage.Success -or $parentPackage.Groups[1].Value -ne [string]$manifest.packageVersion) { throw 'Parent/package manifest version identity is not aligned.' }
if (-not $parentBuild.Success -or [int]$parentBuild.Groups[1].Value -ne [int]$manifest.buildNumber) { throw 'Parent/package manifest build identity is not aligned.' }
if (-not $parentPinnedPowerShell.Success -or $parentPinnedPowerShell.Groups[1].Value -ne [string]$update.runtime.bootstrapPowerShell) { throw 'Parent/update manifest PowerShell bootstrap pin is not aligned.' }
if ([string]$update.dependencies.lockVersion -ne [string]$dependencyLock.lockVersion) { throw 'Update manifest dependency-lock version is not aligned.' }

# The public/product identity remains v1 while internal builds continue to move.
# Every package-bound policy therefore has TWO identity requirements:
#   generatedForPackage = stable v1 Development package identity
#   generatedForBuild   = exact sealed internal build
# This prevents evidence/policies from an older v1 build from being accepted merely
# because the human-facing product version did not change.
$packageBoundPolicies = @(
    'Definitions\Integration\DER-TestTenantIntegrationPolicy.json',
    'Definitions\Canary\DER-CanaryPolicy.json',
    'Definitions\Pilot\DER-PilotPolicy.json',
    'Definitions\Validation\DER-WindowsValidationPolicy.json',
    'Definitions\Validation\DER-SchemaBindings.json',
    'Definitions\Release\DER-DevFreezePolicy.json'
)
foreach ($relativePolicy in $packageBoundPolicies) {
    $policyPath = Join-Path $ProjectRoot $relativePolicy
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw ('Package-bound policy is missing: {0}' -f $relativePolicy) }
    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$policy.generatedForPackage -ne [string]$manifest.packageVersion) {
        throw ('Package-bound policy version mismatch: {0}' -f $relativePolicy)
    }
    if ([int]$policy.generatedForBuild -ne [int]$manifest.buildNumber) {
        throw ('Package-bound policy internal-build mismatch: {0}' -f $relativePolicy)
    }
}
$graph = @($dependencyLock.dependencies | Where-Object name -eq 'Microsoft.Graph.Authentication') | Select-Object -First 1
if (-not $graph -or [string]$graph.version -ne '2.36.1' -or [guid]$graph.moduleGuid -ne [guid]'883916f2-9184-46ee-b1f8-b6a2fb784cee') { throw 'Pinned Graph dependency identity is not the expected tested contract.' }
if ($parent -notmatch '\bSave-PSResource\b' -or $parent -notmatch '-AuthenticodeCheck') { throw 'Parent no longer enforces authenticated dependency acquisition.' }
if ($parent -match '(?m)^\s*Save-Module\b') { throw 'Parent contains a legacy dependency acquisition path that does not perform the required Authenticode validation.' }

$sumEntries = Get-Content -LiteralPath $sumsPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
foreach ($line in $sumEntries) {
    if ($line -notmatch '^([0-9a-fA-F]{64})\s{2}(.+)$') { throw ('Invalid SHA256SUMS entry: {0}' -f $line) }
    $path = Join-Path $ProjectRoot ($Matches[2].Replace('/',[IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $path)) { throw ('SHA256SUMS file missing: {0}' -f $Matches[2]) }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne $Matches[1].ToLowerInvariant()) { throw ('SHA256SUMS mismatch: {0}' -f $Matches[2]) }
}

$strict = [bool]$RequireSigned -or ([string]$manifest.channel -eq 'Release')
$allowed = @($signing.release.allowedCertificateThumbprints | ForEach-Object { ([string]$_).Replace(' ','').ToUpperInvariant() })
if ($strict -and [bool]$signing.release.blockIfThumbprintListEmpty -and $allowed.Count -eq 0) { throw 'Release signing is required but the signing-policy thumbprint allowlist is empty.' }
$runtimeFiles = @($parentPath) + @(Get-ChildItem (Join-Path $ProjectRoot 'Core') -Filter '*.psm1' -File | ForEach-Object FullName) + @(Get-ChildItem (Join-Path $ProjectRoot 'Workloads') -Filter '*.psm1' -File | ForEach-Object FullName)
$signed = 0; $unsigned = 0
foreach ($file in $runtimeFiles) {
    $sig = Get-AuthenticodeSignature -LiteralPath $file
    if ([string]$sig.Status -eq 'Valid') {
        $signed++
        if ($strict) {
            $thumb = ([string]$sig.SignerCertificate.Thumbprint).Replace(' ','').ToUpperInvariant()
            if ($thumb -notin $allowed) { throw ('Unapproved DER signer: {0}' -f $file) }
            if ([bool]$signing.release.timestampRequired -and -not $sig.TimeStamperCertificate) { throw ('Missing DER release timestamp: {0}' -f $file) }
        }
    }
    elseif ([string]$sig.Status -eq 'NotSigned') {
        $unsigned++
        if ($strict) { throw ('Unsigned runtime file in release-mode package: {0}' -f $file) }
    }
    else { throw ('Invalid Authenticode status {0}: {1}' -f $sig.Status,$file) }
}

[pscustomobject]@{
    Status='PASS'
    PackageVersion=[string]$manifest.packageVersion
    BuildNumber=[int]$manifest.buildNumber
    Channel=[string]$manifest.channel
    ManifestSHA256=$actualManifestHash
    ProtectedFiles=@($manifest.protectedFiles).Count
    SHA256SUMSEntries=@($sumEntries).Count
    RuntimeSigned=$signed
    RuntimeUnsigned=$unsigned
    StrictSigning=$strict
}
