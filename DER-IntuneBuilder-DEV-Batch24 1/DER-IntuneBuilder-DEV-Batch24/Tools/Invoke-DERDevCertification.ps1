#requires -Version 7.4
<#
.SYNOPSIS
    DER v1 development certification gate.

.DESCRIPTION
    Aggregates package, Windows smoke, and optional disposable-tenant evidence into a current-state development certification report. It does not authorize customer-tenant writes or declare a production release.

.NOTES
    Keep safety boundaries, evidence semantics, and operator-facing behavior explicit
    when editing this tool.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$RuntimeRoot,
    [string]$OutputDirectory,
    [switch]$InstallTestDependencies,
    [switch]$RequireSignedPackage,
    [string]$NoWriteEvidencePath,
    [string]$CanaryEvidencePath,
    [string]$PilotEvidencePath
)


# Maintenance notes
# Responsibility: Aggregates Development-gate evidence; certification does not authorize tenant mutation or declare production readiness.
# Safety: Tooling must honor its documented no-tenant/no-write boundary.
# Evidence: Output should be deterministic, explicit about PASS/FAIL semantics, and must not describe static checks as runtime/Pester success.
# Packaging: Generate trust/release material only from final source bytes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)

$freezePath = Join-Path $ProjectRoot 'Definitions\Release\DER-DevFreezePolicy.json'
$manifestPath = Join-Path $ProjectRoot 'Definitions\Package\DER-PackageManifest.json'
$certSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-DevCertification.schema.json'
if (-not (Test-Path -LiteralPath $freezePath -PathType Leaf)) { throw 'DER development freeze policy is missing.' }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'DER package manifest is missing.' }
if (-not (Test-Path -LiteralPath $certSchemaPath -PathType Leaf)) { throw 'DER development certification schema is missing.' }

$freeze = Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json -Depth 100
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 100
$manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()

if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    if ($env:ProgramData) { $RuntimeRoot = Join-Path $env:ProgramData 'DER\IntuneBuilder' }
    elseif ($env:LOCALAPPDATA) { $RuntimeRoot = Join-Path $env:LOCALAPPDATA 'DER\IntuneBuilder' }
    else { $RuntimeRoot = Join-Path ([IO.Path]::GetTempPath()) 'DER\IntuneBuilder' }
}
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RuntimeRoot ('Reports\Certification\{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$gates = New-Object System.Collections.Generic.List[object]
function Add-DERCertificationGate {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','NOT-PROVIDED')][string]$Status,
        [Parameter(Mandatory)][string]$Message
    )
    $gates.Add([pscustomobject]@{id=$Id;status=$Status;message=$Message})
}

function Get-DEREvidenceDocument {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SchemaRelativePath
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ('Evidence file not found: {0}' -f $Path) }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $schema = Join-Path $ProjectRoot ($SchemaRelativePath.Replace('/',[IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $schema -PathType Leaf)) { throw ('Evidence schema is missing: {0}' -f $SchemaRelativePath) }
    if (-not (Test-Json -LiteralPath $resolved -SchemaFile $schema -ErrorAction Stop)) { throw ('Evidence does not validate against {0}.' -f $SchemaRelativePath) }
    $doc = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -Depth 100
    [pscustomobject]@{
        Path = $resolved
        SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToLowerInvariant()
        Document = $doc
    }
}

$packageStatus = 'FAIL'
$smokeStatus = 'FAIL'
try {
    $packageTestArguments = @{ProjectRoot=$ProjectRoot}
    if ($RequireSignedPackage) { $packageTestArguments.RequireSigned=$true }
    $pkg = & (Join-Path $ProjectRoot 'Tools\Test-DERPackage.ps1') @packageTestArguments
    if (-not $pkg -or [string]$pkg.Status -ne 'PASS') { throw 'Package validator did not return PASS.' }
    if ([string]$pkg.PackageVersion -ne [string]$freeze.generatedForPackage) { throw 'Package validator returned a different package version than the freeze policy.' }
    if ([int]$pkg.BuildNumber -ne [int]$freeze.generatedForBuild) { throw 'Package validator returned a different internal build than the freeze policy.' }
    if ([string]$pkg.ManifestSHA256 -ne $manifestHash) { throw 'Package validator manifest hash does not match the current package manifest.' }
    $packageStatus = 'PASS'
    Add-DERCertificationGate -Id 'PackageIntegrity' -Status PASS -Message ('Package integrity passed: {0} protected files.' -f $pkg.ProtectedFiles)
}
catch {
    Add-DERCertificationGate -Id 'PackageIntegrity' -Status FAIL -Message $_.Exception.Message
}

try {
    $smokeArgs = @{
        ProjectRoot=$ProjectRoot
        RuntimeRoot=$RuntimeRoot
        OutputDirectory=(Join-Path $OutputDirectory 'WindowsSmoke')
        SkipPackageCheck=$true
    }
    if ($InstallTestDependencies) { $smokeArgs.InstallTestDependencies=$true }
    if ($RequireSignedPackage) { $smokeArgs.RequireSignedPackage=$true }
    $smoke = & (Join-Path $ProjectRoot 'Tools\Invoke-DERWindowsSmokeTest.ps1') @smokeArgs
    if (-not $smoke -or [string]$smoke.Status -ne 'PASS') { throw 'Windows smoke test did not return PASS.' }
    if ([string]$smoke.Package -ne [string]$freeze.generatedForPackage) { throw 'Smoke-test package identity does not match the freeze policy.' }
    if ([int]$smoke.BuildNumber -ne [int]$freeze.generatedForBuild) { throw 'Smoke-test internal build does not match the freeze policy.' }
    $smokeStatus = 'PASS'
    Add-DERCertificationGate -Id 'WindowsSmoke' -Status PASS -Message ('Windows smoke passed with {0} warning(s).' -f $smoke.Warnings)
}
catch {
    Add-DERCertificationGate -Id 'WindowsSmoke' -Status FAIL -Message $_.Exception.Message
}

$evidenceInputs = @($NoWriteEvidencePath,$CanaryEvidencePath,$PilotEvidencePath)
$providedCount = @($evidenceInputs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
$externalProvided = ($providedCount -gt 0)
$externalComplete = $false
$tenantId = $null

if ($providedCount -eq 0) {
    Add-DERCertificationGate -Id 'TenantNoWrite' -Status NOT-PROVIDED -Message 'No-write evidence was not supplied; local certification only.'
    Add-DERCertificationGate -Id 'TenantCanary' -Status NOT-PROVIDED -Message 'Canary evidence was not supplied; local certification only.'
    Add-DERCertificationGate -Id 'TenantPilot' -Status NOT-PROVIDED -Message 'Pilot evidence was not supplied; local certification only.'
}
elseif ($providedCount -ne 3) {
    Add-DERCertificationGate -Id 'TenantNoWrite' -Status FAIL -Message 'For full certification, supply all three evidence files together: no-write, canary, and pilot.'
    Add-DERCertificationGate -Id 'TenantCanary' -Status FAIL -Message 'External evidence set is incomplete.'
    Add-DERCertificationGate -Id 'TenantPilot' -Status FAIL -Message 'External evidence set is incomplete.'
}
else {
    try {
        $nw = Get-DEREvidenceDocument -Path $NoWriteEvidencePath -SchemaRelativePath 'Definitions/Schema/DER-NoWriteEvidence.schema.json'
        $n = $nw.Document
        if ([string]$n.packageVersion -ne [string]$freeze.generatedForPackage) { throw 'No-write evidence is from a different package.' }
        if ([int]$n.buildNumber -ne [int]$freeze.generatedForBuild) { throw 'No-write evidence is from a different internal build.' }
        if (-not [bool]$n.passed -or @($n.failedChecks).Count -ne 0) { throw 'No-write evidence does not show PASS.' }
        if ([long]$n.graphAudit.TransportWriteCount -ne 0 -or [long]$n.graphAudit.BlockedWriteCount -ne 0) { throw 'No-write evidence contains a Graph mutation transport or blocked mutation attempt.' }
        if ([long]$n.authentication.audit.WriteSessionAttempts -ne 0 -or [long]$n.authentication.audit.WriteSessionsOpened -ne 0) { throw 'No-write evidence contains a write-authentication attempt/session.' }
        if ([string]$n.supportingHashes.packageManifestSHA256 -ne $manifestHash) { throw 'No-write evidence package-manifest hash does not match this package.' }
        $tenantId = [string]$n.tenantId
        Add-DERCertificationGate -Id 'TenantNoWrite' -Status PASS -Message ('No-write evidence passed for tenant {0}; SHA-256 {1}.' -f $tenantId,$nw.SHA256)
    }
    catch {
        Add-DERCertificationGate -Id 'TenantNoWrite' -Status FAIL -Message $_.Exception.Message
    }

    try {
        if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'No-write gate did not establish a trusted tenant ID.' }
        $can = Get-DEREvidenceDocument -Path $CanaryEvidencePath -SchemaRelativePath 'Definitions/Schema/DER-CanaryEvidence.schema.json'
        $c = $can.Document
        if ([string]$c.packageVersion -ne [string]$freeze.generatedForPackage) { throw 'Canary evidence is from a different package.' }
        if ([int]$c.buildNumber -ne [int]$freeze.generatedForBuild) { throw 'Canary evidence is from a different internal build.' }
        if ([string]$c.tenantId -ne $tenantId) { throw 'Canary evidence tenant does not match the no-write evidence tenant.' }
        if (-not [bool]$c.passed -or @($c.failures).Count -ne 0 -or -not [bool]$c.cleanupComplete) { throw 'Canary evidence does not show PASS with complete cleanup.' }
        if ([long]$c.graphDelta.post -ne 1 -or [long]$c.graphDelta.patch -ne 0 -or [long]$c.graphDelta.put -ne 0 -or [long]$c.graphDelta.delete -ne 2) { throw 'Canary mutation delta is not the exact 1 POST / 0 PATCH / 0 PUT / 2 DELETE contract.' }
        if ([string]$c.prerequisite.packageManifestSHA256 -ne $manifestHash) { throw 'Canary evidence package-manifest hash does not match this package.' }
        if ([string]$c.prerequisite.sha256 -ne $nw.SHA256) { throw 'Canary evidence is not chained to the exact no-write evidence file supplied.' }
        if ([bool]$c.controlledObject.activeObjectRemaining -or [bool]$c.controlledObject.deletedObjectRemaining) { throw 'Canary evidence indicates the controlled object or tombstone remains.' }
        Add-DERCertificationGate -Id 'TenantCanary' -Status PASS -Message ('Canary evidence passed with complete cleanup; SHA-256 {0}.' -f $can.SHA256)
    }
    catch {
        Add-DERCertificationGate -Id 'TenantCanary' -Status FAIL -Message $_.Exception.Message
    }

    try {
        if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'No-write gate did not establish a trusted tenant ID.' }
        $pil = Get-DEREvidenceDocument -Path $PilotEvidencePath -SchemaRelativePath 'Definitions/Schema/DER-PilotEvidence.schema.json'
        $p = $pil.Document
        if ([string]$p.packageVersion -ne [string]$freeze.generatedForPackage) { throw 'Pilot evidence is from a different package.' }
        if ([int]$p.buildNumber -ne [int]$freeze.generatedForBuild) { throw 'Pilot evidence is from a different internal build.' }
        if ([string]$p.tenantId -ne $tenantId) { throw 'Pilot evidence tenant does not match the prerequisite evidence tenant.' }
        if (-not [bool]$p.passed -or @($p.failures).Count -ne 0 -or -not [bool]$p.cleanupComplete) { throw 'Pilot evidence does not show PASS with complete cleanup.' }
        if ([long]$p.graphDelta.post -ne 1 -or [long]$p.graphDelta.patch -ne 0 -or [long]$p.graphDelta.put -ne 0 -or [long]$p.graphDelta.delete -ne 2) { throw 'Pilot mutation delta is not the exact 1 POST / 0 PATCH / 0 PUT / 2 DELETE contract.' }
        if ([string]$p.prerequisites.packageManifestSHA256 -ne $manifestHash) { throw 'Pilot evidence package-manifest hash does not match this package.' }
        if ([string]$p.prerequisites.noWrite.sha256 -ne $nw.SHA256) { throw 'Pilot evidence is not chained to the exact no-write evidence file supplied.' }
        if ([string]$p.prerequisites.canary.sha256 -ne $can.SHA256) { throw 'Pilot evidence is not chained to the exact canary evidence file supplied.' }
        if (-not [bool]$p.stateLifecycle.created -or -not [bool]$p.stateLifecycle.removedAfterRollback) { throw 'Pilot evidence does not prove DER state creation and removal.' }
        if ([bool]$p.controlledObject.activeObjectRemaining -or [bool]$p.controlledObject.deletedObjectRemaining) { throw 'Pilot evidence indicates the controlled object or tombstone remains.' }
        Add-DERCertificationGate -Id 'TenantPilot' -Status PASS -Message ('Workload pilot evidence passed with complete rollback/cleanup; SHA-256 {0}.' -f $pil.SHA256)
    }
    catch {
        Add-DERCertificationGate -Id 'TenantPilot' -Status FAIL -Message $_.Exception.Message
    }

    $externalComplete = (@($gates | Where-Object { $_.id -in @('TenantNoWrite','TenantCanary','TenantPilot') -and $_.status -eq 'PASS' }).Count -eq 3)
}

$localPass = ($packageStatus -eq 'PASS' -and $smokeStatus -eq 'PASS')
$anyFail = (@($gates | Where-Object status -eq 'FAIL').Count -gt 0)
$status = if ($anyFail -or -not $localPass) { 'FAIL' } elseif ($externalComplete) { 'FULL-PASS' } else { 'LOCAL-PASS' }

# FULL-PASS means every required Development gate passed;
# it does not convert an unsigned Development channel package into a production release.
$report = [ordered]@{
    schemaVersion='1.0'
    evidenceType='DER-Dev-Certification'
    packageVersion=[string]$freeze.generatedForPackage
    buildNumber=[int]$freeze.packageIdentity.buildNumber
    checkedUtc=(Get-Date).ToUniversalTime().ToString('o')
    status=$status
    productionReady=$false
    packageManifestSHA256=$manifestHash
    localValidation=[ordered]@{package=$packageStatus;smoke=$smokeStatus}
    externalEvidence=[ordered]@{provided=$externalProvided;complete=$externalComplete;tenantId=$tenantId}
    gates=@($gates)
}

$jsonPath = Join-Path $OutputDirectory 'DER-DevCertification.json'
$htmlPath = Join-Path $OutputDirectory 'DER-DevCertification.html'
$report | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $jsonPath -Encoding utf8
if (-not (Test-Json -LiteralPath $jsonPath -SchemaFile $certSchemaPath -ErrorAction Stop)) { throw 'Generated DER development certification evidence failed its schema.' }

function ConvertTo-DERCertHtml([object]$Value) {
    [Net.WebUtility]::HtmlEncode([string]$Value)
}
$rows = foreach ($gate in $gates) {
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-DERCertHtml $gate.id),(ConvertTo-DERCertHtml $gate.status),(ConvertTo-DERCertHtml $gate.message)
}
$html = @"
<!doctype html><html><head><meta charset="utf-8"><title>DER Development Certification</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:36px;color:#1f2937}h1{margin-bottom:4px}.meta{color:#4b5563}table{border-collapse:collapse;width:100%;margin-top:24px}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#f3f4f6}.note{padding:12px;background:#fff7ed;border:1px solid #fdba74;margin-top:20px}code{background:#f3f4f6;padding:2px 4px}</style></head><body>
<h1>DER Development Certification</h1>
<p class="meta">Package: $(ConvertTo-DERCertHtml $freeze.generatedForPackage) &nbsp;|&nbsp; Build: $($freeze.packageIdentity.buildNumber)<br>Checked: $(ConvertTo-DERCertHtml $report.checkedUtc)</p>
<h2>Status: $(ConvertTo-DERCertHtml $status)</h2>
<table><thead><tr><th>Gate</th><th>Status</th><th>Evidence</th></tr></thead><tbody>$($rows -join [Environment]::NewLine)</tbody></table>
<div class="note"><strong>ProductionReady = false.</strong> DER v1 is a Development-channel package. Even FULL-PASS still requires the approved signed Release packaging step before production use.</div>
<p>Package manifest SHA-256: <code>$manifestHash</code></p>
</body></html>
"@
$html | Set-Content -LiteralPath $htmlPath -Encoding utf8

Write-Host ('DER DEVELOPMENT CERTIFICATION: {0}' -f $status) -ForegroundColor $(if($status -eq 'FULL-PASS'){'Green'}elseif($status -eq 'LOCAL-PASS'){'Cyan'}else{'Red'})
Write-Host ('JSON: {0}' -f $jsonPath) -ForegroundColor DarkGray
Write-Host ('HTML: {0}' -f $htmlPath) -ForegroundColor DarkGray
if ($status -eq 'FULL-PASS') {
    Write-Host 'All development validation gates passed. This is still not a signed production Release package.' -ForegroundColor Yellow
}
return [pscustomobject]$report
