#requires -Version 7.4
<#
.SYNOPSIS
    DER v1 Windows execution smoke gate.

.DESCRIPTION
    Runs the no-tenant execution gates: AST parsing, package/schema validation, module import/entry-point checks, PSScriptAnalyzer, and Pester. Its report is runtime evidence, unlike source-only static scans.

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
    [switch]$SkipNetwork,
    [switch]$SkipPreflight,
    [switch]$SkipPackageCheck,
    [switch]$RequireSignedPackage
)


# Maintenance notes
# Responsibility: Runs AST parse, JSON/schema, imports/entry points, PSScriptAnalyzer, and Pester without tenant authentication.
# Safety: Tooling must honor its documented no-tenant/no-write boundary.
# Evidence: Output should be deterministic, explicit about PASS/FAIL semantics, and must not describe static checks as runtime/Pester success.
# Packaging: Generate trust/release material only from final source bytes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
if ($env:OS -ne 'Windows_NT') { throw 'DER Windows smoke testing must run on Windows.' }

$policyPath = Join-Path $ProjectRoot 'Definitions\Validation\DER-WindowsValidationPolicy.json'
$bindingPath = Join-Path $ProjectRoot 'Definitions\Validation\DER-SchemaBindings.json'
if (-not (Test-Path -LiteralPath $policyPath)) { throw 'DER Windows validation policy is missing.' }
if (-not (Test-Path -LiteralPath $bindingPath)) { throw 'DER schema-binding catalog is missing.' }
$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 100
$bindings = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json -Depth 100

if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    if ($env:ProgramData) { $RuntimeRoot = Join-Path $env:ProgramData 'DER\IntuneBuilder' }
    else { $RuntimeRoot = Join-Path $env:LOCALAPPDATA 'DER\IntuneBuilder' }
}
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RuntimeRoot ('Reports\SmokeTest\{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$stages = New-Object System.Collections.Generic.List[object]
function Add-DERSmokeStage {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('PASS','FAIL','WARN','INFO')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message,
        [object]$Details
    )
    $stages.Add([pscustomobject]@{id=$Id;status=$Status;message=$Message;details=$Details})
}

function Get-DERPinnedModuleManifest {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][version]$Version,
        [string]$SearchRoot
    )
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($SearchRoot -and (Test-Path -LiteralPath $SearchRoot)) {
        foreach ($f in Get-ChildItem -LiteralPath $SearchRoot -Recurse -Filter ("{0}.psd1" -f $Name) -File -ErrorAction SilentlyContinue) { $candidates.Add($f.FullName) }
    }
    foreach ($module in Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue) {
        if ($module.Path) { $candidates.Add($module.Path) }
    }
    foreach ($path in @($candidates | Select-Object -Unique)) {
        try {
            $info = Test-ModuleManifest -Path $path -ErrorAction Stop
            if ($info.Version -eq $Version) { return $path }
        }
        catch { Write-Verbose ('Ignoring unusable {0} manifest candidate {1}: {2}' -f $Name,$path,$_.Exception.Message) }
    }
    return $null
}

function Get-DERPester59Manifest {
    param([string]$SearchRoot)
    return Get-DERPinnedModuleManifest -Name 'Pester' -Version ([version][string]$policy.smokeTest.pester.preferredVersion) -SearchRoot $SearchRoot
}

function Get-DERPSScriptAnalyzerManifest {
    param([string]$SearchRoot)
    return Get-DERPinnedModuleManifest -Name 'PSScriptAnalyzer' -Version ([version][string]$policy.smokeTest.psScriptAnalyzer.preferredVersion) -SearchRoot $SearchRoot
}

# Preflight ---------------------------------------------------------------------------
if ($SkipPreflight) {
    Add-DERSmokeStage -Id 'Preflight' -Status INFO -Message 'Preflight was already completed by the parent launcher.'
}
else {
    try {
        $preflightTool = Join-Path $ProjectRoot 'Tools\Invoke-DERWindowsPreflight.ps1'
        $preflightArgs = @{ProjectRoot=$ProjectRoot;RuntimeRoot=$RuntimeRoot;OutputPath=(Join-Path $OutputDirectory 'Preflight.json')}
        if ($SkipNetwork) { $preflightArgs.SkipNetwork=$true }
        if ($SkipPackageCheck) { $preflightArgs.SkipPackageCheck=$true }
        if ($RequireSignedPackage) { $preflightArgs.RequireSignedPackage=$true }
        $preflight = & $preflightTool @preflightArgs
        if (-not $preflight -or [string]$preflight.Status -ne 'PASS') { throw 'DER preflight did not return PASS.' }
        Add-DERSmokeStage -Id 'Preflight' -Status PASS -Message 'Windows preflight passed.' -Details @{warnings=$preflight.Warnings}
    }
    catch {
        Add-DERSmokeStage -Id 'Preflight' -Status FAIL -Message $_.Exception.Message
    }
}

# Package integrity -------------------------------------------------------------------
if ($SkipPackageCheck) {
    Add-DERSmokeStage -Id 'PackageIntegrity' -Status INFO -Message 'Package integrity was already completed by the parent launcher.'
}
else {
    try {
        $packageArgs=@{ProjectRoot=$ProjectRoot}
        if($RequireSignedPackage){$packageArgs.RequireSigned=$true}
        $pkg=& (Join-Path $ProjectRoot 'Tools\Test-DERPackage.ps1') @packageArgs
        if(-not $pkg -or [string]$pkg.Status -ne 'PASS'){throw 'Package validator did not return PASS.'}
        Add-DERSmokeStage -Id 'PackageIntegrity' -Status PASS -Message ('Package validator passed ({0} protected files).' -f $pkg.ProtectedFiles)
    }
    catch { Add-DERSmokeStage -Id 'PackageIntegrity' -Status FAIL -Message $_.Exception.Message }
}

# Native PowerShell AST parser ---------------------------------------------------------
$parseErrors=New-Object System.Collections.Generic.List[object]
try {
    $sourceFiles=@(Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') })
    foreach($file in $sourceFiles){
        $tokens=$null;$errors=$null
        $null=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        foreach($err in @($errors)){
            $parseErrors.Add([pscustomobject]@{file=[IO.Path]::GetRelativePath($ProjectRoot,$file.FullName).Replace('\\','/');message=$err.Message;line=$err.Extent.StartLineNumber;column=$err.Extent.StartColumnNumber})
        }
    }
    if($parseErrors.Count -gt 0){throw ('PowerShell parser found {0} error(s).' -f $parseErrors.Count)}
    Add-DERSmokeStage -Id 'PowerShellParse' -Status PASS -Message ('PowerShell AST parser accepted {0} source files.' -f $sourceFiles.Count)
}
catch{
    Add-DERSmokeStage -Id 'PowerShellParse' -Status FAIL -Message $_.Exception.Message -Details @($parseErrors)
}

# JSON parse --------------------------------------------------------------------------
$jsonErrors=New-Object System.Collections.Generic.List[object]
try{
    $jsonFiles=@(Get-ChildItem -LiteralPath $ProjectRoot -Recurse -Filter '*.json' -File)
    foreach($file in $jsonFiles){
        try{$null=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -Depth 100 -ErrorAction Stop}
        catch{$jsonErrors.Add([pscustomobject]@{file=[IO.Path]::GetRelativePath($ProjectRoot,$file.FullName).Replace('\\','/');message=$_.Exception.Message})}
    }
    if($jsonErrors.Count -gt 0){throw ('JSON parser found {0} invalid file(s).' -f $jsonErrors.Count)}
    Add-DERSmokeStage -Id 'JsonParse' -Status PASS -Message ('JSON parser accepted {0} JSON files.' -f $jsonFiles.Count)
}
catch{Add-DERSmokeStage -Id 'JsonParse' -Status FAIL -Message $_.Exception.Message -Details @($jsonErrors)}

# JSON Schema -------------------------------------------------------------------------
$schemaFailures=New-Object System.Collections.Generic.List[object]
try{
    $validated=0
    foreach($binding in @($bindings.bindings)){
        $schemaFile=Join-Path $ProjectRoot (([string]$binding.schema).Replace('/',[IO.Path]::DirectorySeparatorChar))
        if(-not(Test-Path -LiteralPath $schemaFile)){throw ('Schema binding is missing schema: {0}' -f $binding.schema)}
        foreach($document in @($binding.documents)){
            $docFile=Join-Path $ProjectRoot (([string]$document).Replace('/',[IO.Path]::DirectorySeparatorChar))
            if(-not(Test-Path -LiteralPath $docFile)){throw ('Schema binding is missing document: {0}' -f $document)}
            try{
                $ok=Test-Json -LiteralPath $docFile -SchemaFile $schemaFile -ErrorAction Stop
                if(-not $ok){throw 'Test-Json returned false.'}
                $validated++
            }
            catch{$schemaFailures.Add([pscustomobject]@{binding=$binding.id;schema=$binding.schema;document=$document;message=$_.Exception.Message})}
        }
    }
    if($schemaFailures.Count -gt 0){throw ('JSON Schema validation found {0} failure(s).' -f $schemaFailures.Count)}
    Add-DERSmokeStage -Id 'JsonSchema' -Status PASS -Message ('JSON Schema validation passed for {0} bound document(s).' -f $validated)
}
catch{Add-DERSmokeStage -Id 'JsonSchema' -Status FAIL -Message $_.Exception.Message -Details @($schemaFailures)}

# Import exactly the modules the parent advertises; do not invoke workload entry points.
$importFailures=New-Object System.Collections.Generic.List[object]
try{
    $parentText=Get-Content -LiteralPath (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
    $rows=[regex]::Matches($parentText,"File = '([^']+)'\s*;\s*EntryPoint = '([^']+)'")
    if($rows.Count -lt 1){throw 'Parent module catalog is empty.'}
    foreach($row in $rows){
        $relative=$row.Groups[1].Value;$entry=$row.Groups[2].Value
        $path=Join-Path $ProjectRoot $relative
        try{
            Import-Module -Name $path -Force -ErrorAction Stop
            if(-not(Get-Command $entry -ErrorAction SilentlyContinue)){throw ('Expected exported entry point missing: {0}' -f $entry)}
        }
        catch{$importFailures.Add([pscustomobject]@{file=$relative;entryPoint=$entry;message=$_.Exception.Message})}
    }
    if($importFailures.Count -gt 0){throw ('Module import test found {0} failure(s).' -f $importFailures.Count)}
    Add-DERSmokeStage -Id 'ModuleImport' -Status PASS -Message ('Imported all {0} parent-advertised modules and resolved their entry points.' -f $rows.Count)
}
catch{Add-DERSmokeStage -Id 'ModuleImport' -Status FAIL -Message $_.Exception.Message -Details @($importFailures)}
finally{
    foreach($module in @(Get-Module | Where-Object { $_.Path -and $_.Path.StartsWith($ProjectRoot,[StringComparison]::OrdinalIgnoreCase) })){
        try{Remove-Module -Name $module.Name -Force -ErrorAction Stop}catch{Write-Warning ('DER smoke-test cleanup could not remove module {0}: {1}' -f $module.Name,$_.Exception.Message)}
    }
}

# PSScriptAnalyzer ---------------------------------------------------------------------
try {
    $validationDependencyRoot=Join-Path $RuntimeRoot 'ValidationDependencies'
    New-Item -ItemType Directory -Path $validationDependencyRoot -Force | Out-Null
    $analyzerManifest=Get-DERPSScriptAnalyzerManifest -SearchRoot $validationDependencyRoot
    if(-not $analyzerManifest -and $InstallTestDependencies){
        if(-not(Get-Command Save-PSResource -ErrorAction SilentlyContinue)){throw 'Save-PSResource is unavailable; cannot acquire pinned PSScriptAnalyzer dependency.'}
        Write-Host ('Acquiring pinned PSScriptAnalyzer {0} into DER validation cache...' -f $policy.smokeTest.psScriptAnalyzer.preferredVersion) -ForegroundColor Cyan
        Save-PSResource -Name PSScriptAnalyzer -Version ([string]$policy.smokeTest.psScriptAnalyzer.preferredVersion) -Repository PSGallery -Path $validationDependencyRoot -TrustRepository -ErrorAction Stop
        $analyzerManifest=Get-DERPSScriptAnalyzerManifest -SearchRoot $validationDependencyRoot
    }
    if(-not $analyzerManifest){
        throw ('Pinned PSScriptAnalyzer {0} is not available. Re-run with -InstallTestDependencies or install that exact version before smoke testing.' -f $policy.smokeTest.psScriptAnalyzer.preferredVersion)
    }
    Import-Module -Name $analyzerManifest -Force -ErrorAction Stop
    $loadedAnalyzer=Get-Module PSScriptAnalyzer | Select-Object -First 1
    if(-not $loadedAnalyzer -or $loadedAnalyzer.Version -ne [version][string]$policy.smokeTest.psScriptAnalyzer.preferredVersion){throw 'The exact pinned PSScriptAnalyzer version did not load.'}

    $analyzerResults=@(Invoke-ScriptAnalyzer -Path $ProjectRoot -Recurse -Severity Error,Warning -ErrorAction Stop)
    $analyzerRows=@($analyzerResults | ForEach-Object {
        [pscustomobject]@{
            ruleName=[string]$_.RuleName
            severity=[string]$_.Severity
            message=[string]$_.Message
            file=if($_.ScriptPath){[IO.Path]::GetRelativePath($ProjectRoot,[string]$_.ScriptPath).Replace('\','/')}else{''}
            line=[int]$_.Line
            column=[int]$_.Column
        }
    })
    ConvertTo-Json -InputObject @($analyzerRows) -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'PSScriptAnalyzer-Results.json') -Encoding utf8
    $failSeverities=@($policy.smokeTest.psScriptAnalyzer.failOnSeverity | ForEach-Object {[string]$_})
    $blocking=@($analyzerRows | Where-Object { [string]$_.severity -in $failSeverities })
    $warnings=@($analyzerRows | Where-Object { [string]$_.severity -eq 'Warning' })
    if($blocking.Count -gt 0){throw ('PSScriptAnalyzer reported {0} blocking diagnostic(s).' -f $blocking.Count)}
    if($warnings.Count -gt 0){
        Add-DERSmokeStage -Id 'PSScriptAnalyzer' -Status WARN -Message ('PSScriptAnalyzer {0} completed with {1} warning(s) and no blocking diagnostics.' -f $loadedAnalyzer.Version,$warnings.Count) -Details $analyzerRows
    }
    else {
        Add-DERSmokeStage -Id 'PSScriptAnalyzer' -Status PASS -Message ('PSScriptAnalyzer {0} completed with no Error/Warning diagnostics.' -f $loadedAnalyzer.Version)
    }
}
catch {
    Add-DERSmokeStage -Id 'PSScriptAnalyzer' -Status FAIL -Message $_.Exception.Message
}
finally {
    Remove-Module PSScriptAnalyzer -Force -ErrorAction SilentlyContinue
}

# Pester 5.x --------------------------------------------------------------------------
try{
    $validationDependencyRoot=Join-Path $RuntimeRoot 'ValidationDependencies'
    New-Item -ItemType Directory -Path $validationDependencyRoot -Force | Out-Null
    $pesterManifest=Get-DERPester59Manifest -SearchRoot $validationDependencyRoot
    if(-not $pesterManifest -and $InstallTestDependencies){
        if(-not(Get-Command Save-PSResource -ErrorAction SilentlyContinue)){throw 'Save-PSResource is unavailable; cannot acquire pinned Pester test dependency.'}
        Write-Host ('Acquiring pinned Pester {0} into DER validation cache...' -f $policy.smokeTest.pester.preferredVersion) -ForegroundColor Cyan
        Save-PSResource -Name Pester -Version ([string]$policy.smokeTest.pester.preferredVersion) -Repository PSGallery -Path $validationDependencyRoot -TrustRepository -ErrorAction Stop
        $pesterManifest=Get-DERPester59Manifest -SearchRoot $validationDependencyRoot
    }
    if(-not $pesterManifest){
        throw ('Pinned Pester {0} is not available. Re-run with -InstallTestDependencies or install that exact version before smoke testing.' -f $policy.smokeTest.pester.preferredVersion)
    }
    Import-Module -Name $pesterManifest -Force -ErrorAction Stop
    $loadedPester=Get-Module Pester | Select-Object -First 1
    if(-not $loadedPester -or $loadedPester.Version -ne [version][string]$policy.smokeTest.pester.preferredVersion){throw 'The exact pinned Pester version did not load.'}

    $config=New-PesterConfiguration
    $config.Run.Path = @(Join-Path $ProjectRoot 'Tests')
    $config.Run.PassThru = $true
    $config.Run.Throw = $false
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $OutputDirectory 'Pester-TestResults.xml'
    $config.TestResult.OutputFormat = 'NUnitXml'
    $pesterResult=Invoke-Pester -Configuration $config
    $pesterSummary=[ordered]@{
        version=$loadedPester.Version.ToString()
        result=[string]$pesterResult.Result
        totalCount=[int]$pesterResult.TotalCount
        passedCount=[int]$pesterResult.PassedCount
        failedCount=[int]$pesterResult.FailedCount
        skippedCount=[int]$pesterResult.SkippedCount
        duration=[string]$pesterResult.Duration
    }
    $pesterSummary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'Pester-Summary.json') -Encoding utf8
    if($pesterResult.FailedCount -gt 0){throw ('Pester reported {0} failed test(s).' -f $pesterResult.FailedCount)}
    Add-DERSmokeStage -Id 'Pester' -Status PASS -Message ('Pester {0}: {1}/{2} tests passed; skipped={3}.' -f $loadedPester.Version,$pesterResult.PassedCount,$pesterResult.TotalCount,$pesterResult.SkippedCount) -Details $pesterSummary
}
catch{Add-DERSmokeStage -Id 'Pester' -Status FAIL -Message $_.Exception.Message}

$required=@($policy.smokeTest.requiredStages)
$missing=@($required | Where-Object { $_ -notin @($stages.id) })
if($missing.Count -gt 0){
    foreach($id in $missing){Add-DERSmokeStage -Id ([string]$id) -Status FAIL -Message 'Required smoke-test stage did not execute.'}
}
$failCount=@($stages|Where-Object status -eq 'FAIL').Count
$warnCount=@($stages|Where-Object status -eq 'WARN').Count
$overall=if($failCount -eq 0){'PASS'}else{'FAIL'}
$report=[ordered]@{
    schemaVersion='1.0'
    policyVersion=[string]$policy.policyVersion
    package=[string]$policy.generatedForPackage
    buildNumber=[int]$policy.generatedForBuild
    checkedUtc=(Get-Date).ToUniversalTime().ToString('o')
    tenantBlind=$true
    graphAuthenticationPerformed=$false
    graphRequestPerformed=$false
    tenantMutationPerformed=$false
    status=$overall
    failures=$failCount
    warnings=$warnCount
    stages=@($stages)
}
$reportPath=Join-Path $OutputDirectory 'DER-WindowsSmokeTest.json'
$report|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $reportPath -Encoding utf8

if($overall -eq 'PASS'){
    Write-Host ('DER WINDOWS SMOKE TEST: PASS ({0} warning(s))' -f $warnCount) -ForegroundColor Green
    Write-Host ('Report: {0}' -f $reportPath) -ForegroundColor DarkGray
}
else{
    Write-Host ('DER WINDOWS SMOKE TEST: FAIL ({0} failure(s), {1} warning(s))' -f $failCount,$warnCount) -ForegroundColor Red
    Write-Host ('Report: {0}' -f $reportPath) -ForegroundColor DarkGray
}
return [pscustomobject]$report
