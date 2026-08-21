#requires -Version 7.4
<#
.SYNOPSIS
    DER v1 Windows preflight gate.

.DESCRIPTION
    Checks the local Windows/PowerShell/runtime/network prerequisites that must be satisfied before DER loads Graph dependencies or authenticates. The preflight is tenant-blind and performs no Microsoft Graph requests.

.NOTES
    Keep safety boundaries, evidence semantics, and operator-facing behavior explicit
    when editing this tool.
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$RuntimeRoot,
    [string]$OutputPath,
    [switch]$SkipNetwork,
    [switch]$SkipPackageCheck,
    [switch]$RequireSignedPackage
)


# Maintenance notes
# Responsibility: Validates Windows/runtime/network prerequisites without Graph authentication or tenant mutation.
# Safety: Tooling must honor its documented no-tenant/no-write boundary.
# Evidence: Output should be deterministic, explicit about PASS/FAIL semantics, and must not describe static checks as runtime/Pester success.
# Packaging: Generate trust/release material only from final source bytes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$policyPath = Join-Path $ProjectRoot 'Definitions\Validation\DER-WindowsValidationPolicy.json'
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw 'DER Windows validation policy is missing.' }
$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 100

if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    if ($env:ProgramData) { $RuntimeRoot = Join-Path $env:ProgramData 'DER\IntuneBuilder' }
    elseif ($env:LOCALAPPDATA) { $RuntimeRoot = Join-Path $env:LOCALAPPDATA 'DER\IntuneBuilder' }
    else { $RuntimeRoot = Join-Path ([IO.Path]::GetTempPath()) 'DER\IntuneBuilder' }
}
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportRoot = Join-Path $RuntimeRoot 'Reports\Preflight'
    New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
    $OutputPath = Join-Path $reportRoot ('DER-WindowsPreflight-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
else {
    $parent = Split-Path $OutputPath -Parent
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
}

$checks = New-Object System.Collections.Generic.List[object]
function Add-DERPreflightCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Remediation
    )
    $checks.Add([pscustomobject]@{
        id = $Id
        status = $Status
        message = $Message
        remediation = $Remediation
    })
}

function Test-DERPreflightEndpoint {
    param([Parameter(Mandatory = $true)][pscustomobject]$Endpoint)

    $checkType = [string]$Endpoint.checkType
    if ($checkType -eq 'Tls') {
        $client = $null
        $ssl = $null
        try {
            $hostName = [string]$Endpoint.host
            $port = [int]$Endpoint.port
            $client = [Net.Sockets.TcpClient]::new()
            $connectTask = $client.ConnectAsync($hostName, $port)
            if (-not $connectTask.Wait([TimeSpan]::FromSeconds(20))) {
                throw ('TCP connection to {0}:{1} timed out.' -f $hostName,$port)
            }
            $connectTask.GetAwaiter().GetResult()

            $ssl = [Net.Security.SslStream]::new($client.GetStream(), $false)
            $authTask = $ssl.AuthenticateAsClientAsync($hostName)
            if (-not $authTask.Wait([TimeSpan]::FromSeconds(20))) {
                throw ('TLS handshake with {0}:{1} timed out.' -f $hostName,$port)
            }
            $authTask.GetAwaiter().GetResult()
            if (-not $ssl.IsAuthenticated -or -not $ssl.IsEncrypted) {
                throw ('TLS session with {0}:{1} was not authenticated/encrypted.' -f $hostName,$port)
            }
            return [pscustomobject]@{ Reachable=$true; Detail=('TCP/TLS handshake completed with {0}:{1}; no HTTP request was sent.' -f $hostName,$port) }
        }
        catch {
            return [pscustomobject]@{ Reachable=$false; Detail=$_.Exception.Message }
        }
        finally {
            if ($ssl) { $ssl.Dispose() }
            if ($client) { $client.Dispose() }
        }
    }

    try {
        $null = Invoke-WebRequest -Uri ([string]$Endpoint.uri) -Method Get -TimeoutSec 20 -MaximumRedirection 5 -ErrorAction Stop
        return [pscustomobject]@{ Reachable=$true; Detail='HTTPS response received.' }
    }
    catch {
        if ($_.Exception.Response) {
            return [pscustomobject]@{ Reachable=$true; Detail=('HTTP response received ({0}).' -f $_.Exception.Response.StatusCode) }
        }
        return [pscustomobject]@{ Reachable=$false; Detail=$_.Exception.Message }
    }
}

# Host/platform checks ----------------------------------------------------------------
$isWindows = ($env:OS -eq 'Windows_NT')
if ($isWindows) { Add-DERPreflightCheck -Id 'OS' -Status PASS -Message 'Windows host detected.' }
else { Add-DERPreflightCheck -Id 'OS' -Status FAIL -Message 'DER v1 requires Windows.' -Remediation 'Run this package on a supported Windows workstation.' }

$arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -in @($policy.platform.architectures)) {
    Add-DERPreflightCheck -Id 'Architecture' -Status PASS -Message ('OS architecture {0} is supported.' -f $arch)
}
else {
    Add-DERPreflightCheck -Id 'Architecture' -Status FAIL -Message ('OS architecture {0} is not in the DER supported set.' -f $arch) -Remediation ('Use one of: {0}' -f (@($policy.platform.architectures) -join ', '))
}

$minimumPowerShell = [version][string]$policy.platform.minimumPowerShell
if ($PSVersionTable.PSVersion -ge $minimumPowerShell -and [string]$PSVersionTable.PSEdition -eq [string]$policy.platform.requiredPSEdition) {
    Add-DERPreflightCheck -Id 'PowerShell' -Status PASS -Message ('PowerShell {0} ({1}) meets DER minimum {2}.' -f $PSVersionTable.PSVersion,$PSVersionTable.PSEdition,$minimumPowerShell)
}
else {
    Add-DERPreflightCheck -Id 'PowerShell' -Status FAIL -Message ('PowerShell {0} ({1}) does not meet the DER host contract.' -f $PSVersionTable.PSVersion,$PSVersionTable.PSEdition) -Remediation ('Use PowerShell {0}+ with PSEdition Core. Preferred tested bootstrap: {1}.' -f $minimumPowerShell,$policy.platform.preferredPowerShell)
}

$languageMode = [string]$ExecutionContext.SessionState.LanguageMode
if ($languageMode -in @($policy.platform.allowedLanguageModes)) {
    Add-DERPreflightCheck -Id 'LanguageMode' -Status PASS -Message ('PowerShell language mode is {0}.' -f $languageMode)
}
else {
    Add-DERPreflightCheck -Id 'LanguageMode' -Status FAIL -Message ('PowerShell language mode {0} is not supported by DER.' -f $languageMode) -Remediation 'Run DER from an approved FullLanguage PowerShell 7 session; review AppLocker/WDAC policy if constrained.'
}

try {
    $ep = Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy
    $effective = Get-ExecutionPolicy
    $machine = @($ep | Where-Object Scope -eq 'MachinePolicy' | Select-Object -First 1)
    $user = @($ep | Where-Object Scope -eq 'UserPolicy' | Select-Object -First 1)
    $locked = @($machine + $user | Where-Object { $_ -and [string]$_.ExecutionPolicy -notin @('Undefined','Bypass','Unrestricted','RemoteSigned') })
    if ($locked.Count -gt 0) {
        Add-DERPreflightCheck -Id 'ExecutionPolicy' -Status WARN -Message ('Effective execution policy is {0}; a Group Policy scope may restrict unsigned development modules.' -f $effective) -Remediation 'Use the signed Release package or have the applicable PowerShell execution policy reviewed.'
    }
    else {
        Add-DERPreflightCheck -Id 'ExecutionPolicy' -Status PASS -Message ('Effective execution policy is {0}.' -f $effective)
    }
}
catch {
    Add-DERPreflightCheck -Id 'ExecutionPolicy' -Status WARN -Message ('Execution policy could not be inspected: {0}' -f $_.Exception.Message)
}

# Required command surface -------------------------------------------------------------
foreach ($commandName in @($policy.requiredCommands)) {
    if (Get-Command ([string]$commandName) -ErrorAction SilentlyContinue) {
        Add-DERPreflightCheck -Id ('Command:{0}' -f $commandName) -Status PASS -Message ('Required command is available: {0}' -f $commandName)
    }
    else {
        Add-DERPreflightCheck -Id ('Command:{0}' -f $commandName) -Status FAIL -Message ('Required command is unavailable: {0}' -f $commandName) -Remediation 'Repair/update the supported PowerShell 7 installation before running DER.'
    }
}

$testJson = Get-Command Test-Json -ErrorAction SilentlyContinue
if ($testJson -and $testJson.Parameters.ContainsKey('SchemaFile')) {
    Add-DERPreflightCheck -Id 'JsonSchemaSupport' -Status PASS -Message 'Test-Json -SchemaFile support is available.'
}
else {
    Add-DERPreflightCheck -Id 'JsonSchemaSupport' -Status FAIL -Message 'PowerShell JSON Schema validation support is unavailable.' -Remediation 'Use DER-supported PowerShell 7.4 or later.'
}

# Package trust check -----------------------------------------------------------------
if (-not $SkipPackageCheck) {
    $packageTool = Join-Path $ProjectRoot 'Tools\Test-DERPackage.ps1'
    try {
        $params = @{ ProjectRoot=$ProjectRoot }
        if ($RequireSignedPackage) { $params.RequireSigned = $true }
        $packageResult = & $packageTool @params
        if ($packageResult -and [string]$packageResult.Status -eq 'PASS') {
            Add-DERPreflightCheck -Id 'PackageIntegrity' -Status PASS -Message ('Package integrity PASS: {0} protected files.' -f $packageResult.ProtectedFiles)
        }
        else { throw 'Package validator did not return PASS.' }
    }
    catch {
        Add-DERPreflightCheck -Id 'PackageIntegrity' -Status FAIL -Message ('Package integrity validation failed: {0}' -f $_.Exception.Message) -Remediation 'Discard this copy and use a known-good DER package.'
    }
}
else {
    Add-DERPreflightCheck -Id 'PackageIntegrity' -Status INFO -Message 'Package integrity check was already completed by the parent launcher.'
}

# Writable runtime / disk checks -------------------------------------------------------
try {
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    foreach ($relative in @($policy.runtime.requiredSubdirectories)) {
        New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot ([string]$relative)) -Force | Out-Null
    }
    $probe = Join-Path $RuntimeRoot ('.der-preflight-{0}.tmp' -f $PID)
    Set-Content -LiteralPath $probe -Value 'DER' -Encoding ascii
    Remove-Item -LiteralPath $probe -Force
    Add-DERPreflightCheck -Id 'RuntimeWritable' -Status PASS -Message ('DER runtime root is writable: {0}' -f $RuntimeRoot)
}
catch {
    Add-DERPreflightCheck -Id 'RuntimeWritable' -Status FAIL -Message ('DER runtime root is not writable: {0}' -f $_.Exception.Message) -Remediation 'Grant write access to ProgramData DER runtime or use the LOCALAPPDATA fallback.'
}

try {
    $driveRoot = [IO.Path]::GetPathRoot($RuntimeRoot)
    $driveInfo = [IO.DriveInfo]::new($driveRoot)
    $freeMB = [math]::Floor($driveInfo.AvailableFreeSpace / 1MB)
    if ($freeMB -ge [int]$policy.platform.minimumFreeDiskMB) {
        Add-DERPreflightCheck -Id 'DiskSpace' -Status PASS -Message ('Runtime drive has {0} MB free (minimum {1} MB).' -f $freeMB,$policy.platform.minimumFreeDiskMB)
    }
    else {
        Add-DERPreflightCheck -Id 'DiskSpace' -Status FAIL -Message ('Runtime drive has only {0} MB free.' -f $freeMB) -Remediation ('Free at least {0} MB before running DER.' -f $policy.platform.minimumFreeDiskMB)
    }
}
catch {
    Add-DERPreflightCheck -Id 'DiskSpace' -Status WARN -Message ('Free-space check could not be completed: {0}' -f $_.Exception.Message)
}

try {
    $tempRoot = [IO.Path]::GetTempPath()
    $tempProbe = Join-Path $tempRoot ('.der-preflight-{0}.tmp' -f $PID)
    Set-Content -LiteralPath $tempProbe -Value 'DER' -Encoding ascii
    Remove-Item -LiteralPath $tempProbe -Force
    Add-DERPreflightCheck -Id 'TempWritable' -Status PASS -Message ('Temporary directory is writable: {0}' -f $tempRoot)
}
catch {
    Add-DERPreflightCheck -Id 'TempWritable' -Status FAIL -Message ('Temporary directory is not writable: {0}' -f $_.Exception.Message) -Remediation 'Repair the user/system TEMP path before running DER.'
}

# Mark-of-the-Web warning for development source --------------------------------------
if ($isWindows) {
    try {
        $motw = 0
        foreach ($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') }) {
            try {
                if (Get-Item -LiteralPath $file.FullName -Stream 'Zone.Identifier' -ErrorAction Stop) { $motw++ }
            }
            catch [System.Management.Automation.ItemNotFoundException] { continue }
        }
        if ($motw -gt 0) {
            Add-DERPreflightCheck -Id 'MarkOfTheWeb' -Status WARN -Message ('{0} PowerShell file(s) retain Zone.Identifier metadata.' -f $motw) -Remediation 'For an approved development package, use Unblock-File after independently validating the ZIP hash. Prefer signed Release packages for production.'
        }
        else { Add-DERPreflightCheck -Id 'MarkOfTheWeb' -Status PASS -Message 'No PowerShell source file retained Zone.Identifier metadata.' }
    }
    catch {
        Add-DERPreflightCheck -Id 'MarkOfTheWeb' -Status WARN -Message ('Mark-of-the-Web inspection was unavailable: {0}' -f $_.Exception.Message)
    }
}

# Network routing/TLS only --------------------------------------------------------------
if ($SkipNetwork) {
    Add-DERPreflightCheck -Id 'Network' -Status INFO -Message 'Network endpoint checks were explicitly skipped.'
}
else {
    foreach ($endpoint in @($policy.endpoints)) {
        $result = Test-DERPreflightEndpoint -Endpoint $endpoint
        if ($result.Reachable) {
            Add-DERPreflightCheck -Id ('Endpoint:{0}' -f $endpoint.id) -Status PASS -Message ('{0}: {1}' -f $endpoint.id,$result.Detail)
        }
        elseif ([bool]$endpoint.required) {
            $target = if ([string]$endpoint.checkType -eq 'Tls') { '{0}:{1}' -f $endpoint.host,$endpoint.port } else { [string]$endpoint.uri }
            Add-DERPreflightCheck -Id ('Endpoint:{0}' -f $endpoint.id) -Status FAIL -Message ('{0} is unreachable: {1}' -f $endpoint.id,$result.Detail) -Remediation ('Allow outbound access to {0} and verify proxy/TLS inspection settings.' -f $target)
        }
        else {
            Add-DERPreflightCheck -Id ('Endpoint:{0}' -f $endpoint.id) -Status WARN -Message ('{0} is unreachable: {1}' -f $endpoint.id,$result.Detail)
        }
    }
}

$failCount = @($checks | Where-Object status -eq 'FAIL').Count
$warnCount = @($checks | Where-Object status -eq 'WARN').Count
$overall = if ($failCount -eq 0) { 'PASS' } else { 'FAIL' }
$report = [ordered]@{
    schemaVersion='1.0'
    policyVersion=[string]$policy.policyVersion
    package=[string]$policy.generatedForPackage
    buildNumber=[int]$policy.generatedForBuild
    checkedUtc=(Get-Date).ToUniversalTime().ToString('o')
    computerName=$env:COMPUTERNAME
    powerShellVersion=$PSVersionTable.PSVersion.ToString()
    powerShellEdition=[string]$PSVersionTable.PSEdition
    architecture=$arch
    runtimeRoot=$RuntimeRoot
    tenantBlind=$true
    graphAuthenticationPerformed=$false
    graphRequestPerformed=$false
    tenantMutationPerformed=$false
    status=$overall
    failures=$failCount
    warnings=$warnCount
    checks=@($checks)
}
$report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding utf8

if ($overall -eq 'PASS') {
    Write-Host ('DER WINDOWS PREFLIGHT: PASS ({0} warning(s))' -f $warnCount) -ForegroundColor Green
    Write-Host ('Report: {0}' -f $OutputPath) -ForegroundColor DarkGray
}
else {
    Write-Host ('DER WINDOWS PREFLIGHT: FAIL ({0} failure(s), {1} warning(s))' -f $failCount,$warnCount) -ForegroundColor Red
    Write-Host ('Report: {0}' -f $OutputPath) -ForegroundColor DarkGray
}

return [pscustomobject]$report
