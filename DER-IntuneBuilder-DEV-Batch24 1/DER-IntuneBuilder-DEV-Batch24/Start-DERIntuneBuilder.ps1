<#
.SYNOPSIS
    DER Intune / Entra Environment Builder - Parent Launcher

.DESCRIPTION
    Parent/orchestrator for the DER Intune / Entra Environment Builder.

    This launcher intentionally owns only the minimum bootstrap/orchestration work:
      - Verify/boot into supported PowerShell 7
      - Install PowerShell 7 from the official Microsoft PowerShell release when required
      - Verify package integrity before child-module load
      - Verify/download the pinned Microsoft.Graph.Authentication dependency with publisher validation
      - Create the DER local runtime workspace
      - Discover and load child modules in dependency order
      - Execute the validated child-module workflow in deterministic dependency order

    The tenant build logic belongs in child modules, not in this parent script.

.NOTES
    DER Engine Version   : 1.0.0-dev
    DER Baseline Version : 1.0.0
    DER Package Version  : 1.0.0-dev
    PowerShell target    : 7.4+ (bootstrap package pinned to 7.6.4)
    Graph Auth target    : Microsoft.Graph.Authentication 2.36.1

    No DER branding is written into a customer Microsoft 365 tenant.
#>

[CmdletBinding()]
param(
    [switch]$BootstrapInstall,
    [switch]$RelaunchedFromBootstrap,
    [string]$ImportStatePath,
    [ValidateSet('Prompt','Merge','Replace')][string]$StateImportMode='Prompt',
    [string]$ExportStatePath,
    [ValidateSet('Prompt','FileOnly','Disabled')][string]$AdoptionMode='Prompt',
    [string]$AdoptionDecisionPath,
    [ValidateSet('Prompt','Analyze','ResumeSafe','Reconcile','Stop')][string]$RecoveryMode='Prompt',
    [switch]$PreflightOnly,
    [switch]$SmokeTestOnly,
    [switch]$InstallTestDependencies,
    [switch]$RequireSignedPackage,
    [switch]$TenantIntegrationTest,
    [switch]$TenantCanaryTest,
    [switch]$TenantPilotTest,
    [string]$NoWriteEvidencePath,
    [string]$CanaryEvidencePath
)


# Maintenance notes
# Responsibility: Enforces package trust, execution order, safety gates, module boundaries, write-session timing, workload stop/rollback behavior, and terminal reports.
# Versioning: The product stays at v1 until the project owner authorizes a new product version.
# Graph access: The parent does not call Microsoft Graph directly; Core/DER.Graph.psm1 owns transport.
# Failure handling: Unknown or unclassified failures are ENGINE failures. ACTION requires positive tenant/request/validation evidence.
# Recovery: Resolve interrupted or uncertain state through Core/DER.Recovery.psm1 before any write-capable path continues.
# Ordering: Safety gates are intentional dependencies; do not move tenant mutation earlier for convenience.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# DER parent constants
# -----------------------------------------------------------------------------
$script:DEREngineVersion           = '1.0.0-dev'
$script:DERBaselineVersion         = '1.0.0'
$script:DERDefinitionSchema        = '1.0'
$script:DERPortableStateVersion    = '1.0'
$script:DERPackageVersion          = '1.0.0-dev'
$script:DERPackageBuildNumber      = 24
$script:DERPackageManifestSchema   = '1.0'
$script:DERUpdateManifestSchema    = '1.0'
$script:DERDependencyLockVersion   = '1.0.0'
$script:DERSigningPolicyVersion    = '1.0.0'
$script:DERWindowsValidationPolicy = '1.0.0'
$script:DERIntegrationPolicyVersion = '1.0.0'
$script:DERCanaryPolicyVersion      = '1.0.0'
$script:DERPilotPolicyVersion       = '1.0.0'
$script:DERDevFreezePolicyVersion   = '1.0.0'
$script:DERMinPowerShellVersion    = [version]'7.4.0'
$script:DERPinnedPowerShell        = '7.6.4'
$script:DERPowerShellMsiSHA256     = 'd11942df52fd12470169797abfa4781d9480efdc81000ba4fa55a5b921ed8dd0'
$script:DERGraphAuthVersion        = '2.36.1'
$script:DERGraphAuthModuleGuid     = [guid]'883916f2-9184-46ee-b1f8-b6a2fb784cee'
$script:DERPackageManifestSHA256   = '61dcac4ed18fbc5ebf866eeb040323d8243b8874851aa1d140e3536256d81602'
$script:DERPackageRoot             = $PSScriptRoot
$script:DERRunId                  = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 6).ToUpperInvariant())
$script:DERBootstrapLog           = $null
$script:DERRuntimeRoot            = $null
$script:DERDependencyRoot         = $null

# Official Microsoft PowerShell project release asset. Microsoft Learn documents
# GitHub release assets as the direct MSI download source for PowerShell 7.
$script:DERPowerShellMsiUrl = 'https://github.com/PowerShell/PowerShell/releases/download/v{0}/PowerShell-{0}-win-x64.msi' -f $script:DERPinnedPowerShell

# -----------------------------------------------------------------------------
# Parent-advertised child-module catalog used for deterministic import ordering and
# entry-point validation. Tenant build logic remains in the child modules.
# -----------------------------------------------------------------------------
$script:DERModuleCatalog = @(
    # Core engine
    [pscustomobject]@{ Order =  10; Area = 'Core'; File = 'Core\DER.Logging.psm1';            EntryPoint = 'Initialize-DERLogging';             Required = $true  },
    [pscustomobject]@{ Order =  20; Area = 'Core'; File = 'Core\DER.Graph.psm1';              EntryPoint = 'Initialize-DERGraphEngine';         Required = $true  },
    [pscustomobject]@{ Order =  30; Area = 'Core'; File = 'Core\DER.Authentication.psm1';     EntryPoint = 'Connect-DERDiscoverySession';       Required = $true  },
    [pscustomobject]@{ Order =  40; Area = 'Core'; File = 'Core\DER.Discovery.psm1';          EntryPoint = 'Invoke-DERTenantDiscovery';         Required = $true  },
    [pscustomobject]@{ Order =  50; Area = 'Core'; File = 'Core\DER.Snapshot.psm1';           EntryPoint = 'New-DERPreBuildSnapshot';           Required = $true  },
    [pscustomobject]@{ Order =  60; Area = 'Core'; File = 'Core\DER.Analysis.psm1';           EntryPoint = 'Invoke-DERTenantAnalysis';          Required = $true  },
    [pscustomobject]@{ Order =  70; Area = 'Core'; File = 'Core\DER.State.psm1';              EntryPoint = 'Initialize-DERState';               Required = $true  },
    [pscustomobject]@{ Order =  80; Area = 'Core'; File = 'Core\DER.Questionnaire.psm1';      EntryPoint = 'Invoke-DERQuestionnaire';           Required = $true  },
    [pscustomobject]@{ Order =  90; Area = 'Core'; File = 'Core\DER.Planner.psm1';            EntryPoint = 'New-DERBuildPlan';                  Required = $true  },
    [pscustomobject]@{ Order =  95; Area = 'Core'; File = 'Core\DER.Adoption.psm1';           EntryPoint = 'Invoke-DERAdoptionWorkflow';        Required = $true  },
    [pscustomobject]@{ Order = 100; Area = 'Core'; File = 'Core\DER.Permissions.psm1';        EntryPoint = 'Resolve-DERRequiredPermissions';    Required = $true  },
    [pscustomobject]@{ Order = 110; Area = 'Core'; File = 'Core\DER.DryRun.psm1';             EntryPoint = 'Invoke-DERDryRun';                  Required = $true  },
    [pscustomobject]@{ Order = 115; Area = 'Core'; File = 'Core\DER.IntegrationTest.psm1';    EntryPoint = 'New-DERNoWriteEvidence';           Required = $true  },
    [pscustomobject]@{ Order = 117; Area = 'Core'; File = 'Core\DER.Canary.psm1';             EntryPoint = 'Invoke-DERTenantCanary';           Required = $true  },
    [pscustomobject]@{ Order = 118; Area = 'Core'; File = 'Core\DER.Pilot.psm1';              EntryPoint = 'Invoke-DERWorkloadPilot';          Required = $true  },
    [pscustomobject]@{ Order = 120; Area = 'Core'; File = 'Core\DER.Validation.psm1';         EntryPoint = 'Invoke-DERPostBuildValidation';     Required = $true  },
    [pscustomobject]@{ Order = 130; Area = 'Core'; File = 'Core\DER.Rollback.psm1';           EntryPoint = 'Invoke-DERModuleRollback';          Required = $true  },
    [pscustomobject]@{ Order = 140; Area = 'Core'; File = 'Core\DER.Recovery.psm1';           EntryPoint = 'Invoke-DERRecoveryCheck';           Required = $true  },
    [pscustomobject]@{ Order = 150; Area = 'Core'; File = 'Core\DER.Reporting.psm1';          EntryPoint = 'New-DERFinalReports';               Required = $true  },

    # Workload modules
    [pscustomobject]@{ Order = 200; Area = 'Workload'; File = 'Workloads\DER.Groups.psm1';                 EntryPoint = 'Invoke-DERGroupsModule';                 Required = $false },
    [pscustomobject]@{ Order = 210; Area = 'Workload'; File = 'Workloads\DER.EntraDevice.psm1';            EntryPoint = 'Invoke-DEREntraDeviceModule';            Required = $false },
    [pscustomobject]@{ Order = 220; Area = 'Workload'; File = 'Workloads\DER.Enrollment.psm1';             EntryPoint = 'Invoke-DEREnrollmentModule';             Required = $false },
    [pscustomobject]@{ Order = 230; Area = 'Workload'; File = 'Workloads\DER.Autopilot.psm1';              EntryPoint = 'Invoke-DERAutopilotModule';              Required = $false },
    [pscustomobject]@{ Order = 240; Area = 'Workload'; File = 'Workloads\DER.Compliance.psm1';             EntryPoint = 'Invoke-DERComplianceModule';             Required = $false },
    [pscustomobject]@{ Order = 250; Area = 'Workload'; File = 'Workloads\DER.BitLocker.psm1';              EntryPoint = 'Invoke-DERBitLockerModule';              Required = $false },
    [pscustomobject]@{ Order = 260; Area = 'Workload'; File = 'Workloads\DER.LAPS.psm1';                   EntryPoint = 'Invoke-DERLAPSModule';                   Required = $false },
    [pscustomobject]@{ Order = 270; Area = 'Workload'; File = 'Workloads\DER.Defender.psm1';               EntryPoint = 'Invoke-DERDefenderModule';               Required = $false },
    [pscustomobject]@{ Order = 280; Area = 'Workload'; File = 'Workloads\DER.ASR.psm1';                    EntryPoint = 'Invoke-DERASRModule';                    Required = $false },
    [pscustomobject]@{ Order = 290; Area = 'Workload'; File = 'Workloads\DER.Firewall.psm1';               EntryPoint = 'Invoke-DERFirewallModule';               Required = $false },
    [pscustomobject]@{ Order = 300; Area = 'Workload'; File = 'Workloads\DER.Configuration.psm1';          EntryPoint = 'Invoke-DERConfigurationModule';          Required = $false },
    [pscustomobject]@{ Order = 310; Area = 'Workload'; File = 'Workloads\DER.AuthenticationMethods.psm1';  EntryPoint = 'Invoke-DERAuthenticationMethodsModule';  Required = $false },
    [pscustomobject]@{ Order = 320; Area = 'Workload'; File = 'Workloads\DER.NamedLocations.psm1';         EntryPoint = 'Invoke-DERNamedLocationsModule';         Required = $false },
    [pscustomobject]@{ Order = 330; Area = 'Workload'; File = 'Workloads\DER.ConditionalAccess.psm1';      EntryPoint = 'Invoke-DERConditionalAccessModule';      Required = $false },
    [pscustomobject]@{ Order = 340; Area = 'Workload'; File = 'Workloads\DER.GuestExternal.psm1';          EntryPoint = 'Invoke-DERGuestExternalModule';          Required = $false },
    [pscustomobject]@{ Order = 350; Area = 'Workload'; File = 'Workloads\DER.AppConsent.psm1';             EntryPoint = 'Invoke-DERAppConsentModule';             Required = $false },
    [pscustomobject]@{ Order = 360; Area = 'Workload'; File = 'Workloads\DER.PasswordProtection.psm1';    EntryPoint = 'Invoke-DERPasswordProtectionModule';    Required = $false },
    [pscustomobject]@{ Order = 370; Area = 'Workload'; File = 'Workloads\DER.PIM.psm1';                    EntryPoint = 'Invoke-DERPIMModule';                    Required = $false },
    [pscustomobject]@{ Order = 380; Area = 'Workload'; File = 'Workloads\DER.Updates.psm1';                EntryPoint = 'Invoke-DERUpdatesModule';                Required = $false },
    [pscustomobject]@{ Order = 390; Area = 'Workload'; File = 'Workloads\DER.Drivers.psm1';                EntryPoint = 'Invoke-DERDriversModule';                Required = $false },
    [pscustomobject]@{ Order = 400; Area = 'Workload'; File = 'Workloads\DER.OneDrive.psm1';               EntryPoint = 'Invoke-DEROneDriveModule';               Required = $false },
    [pscustomobject]@{ Order = 410; Area = 'Workload'; File = 'Workloads\DER.DeliveryOptimization.psm1';   EntryPoint = 'Invoke-DERDeliveryOptimizationModule';   Required = $false },
    [pscustomobject]@{ Order = 420; Area = 'Workload'; File = 'Workloads\DER.TenantSettings.psm1';         EntryPoint = 'Invoke-DERTenantSettingsModule';         Required = $false },
    [pscustomobject]@{ Order = 430; Area = 'Workload'; File = 'Workloads\DER.Analytics.psm1';              EntryPoint = 'Invoke-DERAnalyticsModule';              Required = $false },
    [pscustomobject]@{ Order = 440; Area = 'Workload'; File = 'Workloads\DER.LoggingIntegration.psm1';     EntryPoint = 'Invoke-DERLoggingIntegrationModule';     Required = $false }
)

# -----------------------------------------------------------------------------
# Minimal bootstrap helpers. These stay in the parent because they must work
# before any child module can be loaded.
# -----------------------------------------------------------------------------
function Write-DERBootstrapMessage {
    <#
    .SYNOPSIS
        Writes parent/bootstrap progress before and after the structured logger exists.

    .DESCRIPTION
        Before DER.Logging loads, this helper writes console/bootstrap-file evidence.
        After DER.Logging initializes, it mirrors the same event into the structured
        timeline without duplicating console output. Callers may explicitly identify
        ACTION versus ENGINE failure provenance; ActionId remains correlation only.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR','STEP')][string]$Level = 'INFO',
        [ValidateSet('General','Action','Engine')][string]$EventDomain = 'Engine',
        [ValidateSet('Auto','None','Action','Engine')][string]$FailureKind = 'Auto',
        [string]$ActionId,
        [string]$DerId,
        [switch]$SkipStructuredMirror
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $prefix = switch ($Level) {
        'OK'    { '[+]' }
        'WARN'  { '[!]' }
        'ERROR' { '[X]' }
        'STEP'  { '[>]' }
        default { '[i]' }
    }

    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        default { 'Gray' }
    }

    Write-Host ('{0} {1} {2}' -f $prefix, $timestamp, $Message) -ForegroundColor $color

    if ($script:DERBootstrapLog) {
        try {
            Add-Content -LiteralPath $script:DERBootstrapLog -Value ('{0} [{1}] {2}' -f $timestamp, $Level, $Message) -Encoding UTF8
        }
        catch {
            # Before the structured logger exists, bootstrap persistence is best-effort.
            # After structured logging initializes, the mirror below becomes authoritative
            # and any failure there is allowed to surface as an ENGINE failure.
        }
    }

    # Once DER.Logging is initialized, mirror parent/bootstrap events into the same
    # structured ENGINE timeline as module events. This preserves a continuous run
    # chronology without duplicating console output. Bootstrap activity is engine
    # orchestration, not evidence that a tenant action failed.
    if (-not $SkipStructuredMirror -and
        (Get-Command 'Write-DERLog' -ErrorAction SilentlyContinue) -and
        (Get-Command 'Test-DERLoggingInitialized' -ErrorAction SilentlyContinue) -and
        (Test-DERLoggingInitialized)) {
        Write-DERLog -Level $Level -Component 'Bootstrap' -EventDomain $EventDomain -FailureKind $(if($Level -eq 'ERROR'){$FailureKind}else{'None'}) -ActionId $ActionId -DerId $DerId -Message $Message -NoConsole
    }
}

function Test-DERIsWindows {
    return ($env:OS -eq 'Windows_NT')
}

function Test-DERIsAdministrator {
    if (-not (Test-DERIsWindows)) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DERLocalFixedRuntimePath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.StartsWith('\\')) { return $false }
    try {
        $root=[System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))
        if ([string]::IsNullOrWhiteSpace($root)) { return $false }
        $drive=[System.IO.DriveInfo]::new($root)
        return ($drive.DriveType -eq [System.IO.DriveType]::Fixed)
    }
    catch { return $false }
}

function Initialize-DERRuntimeRoot {
    $preferred = Join-Path $env:ProgramData 'DER\IntuneBuilder'
    $fallback = Join-Path $env:LOCALAPPDATA 'DER\IntuneBuilder'

    foreach ($candidate in @($preferred, $fallback)) {
        try {
            if (-not (Test-DERLocalFixedRuntimePath -Path $candidate)) {
                Write-DERBootstrapMessage -Level WARN -Message ("DER skipped non-local runtime path '{0}'. Persistent DER state requires a local fixed-disk filesystem." -f $candidate)
                continue
            }
            if (-not (Test-Path -LiteralPath $candidate)) {
                New-Item -ItemType Directory -Path $candidate -Force | Out-Null
            }

            $probe = Join-Path $candidate ('.write-test-{0}.tmp' -f $PID)
            Set-Content -LiteralPath $probe -Value 'DER' -Encoding ASCII
            Remove-Item -LiteralPath $probe -Force
            $script:DERRuntimeRoot = $candidate
            break
        }
        catch {
            continue
        }
    }

    if (-not $script:DERRuntimeRoot) {
        throw 'DER could not create a writable local fixed-disk runtime directory under ProgramData or LOCALAPPDATA. DER will not place authoritative tenant state on UNC/network/removable storage.'
    }

    $paths = @(
        'Dependencies',
        'Evidence',
        'Logs',
        'Reports',
        'Runs',
        'Snapshots',
        'State',
        'Temp',
        'ValidationDependencies'
    )

    foreach ($relative in $paths) {
        $path = Join-Path $script:DERRuntimeRoot $relative
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }

    $script:DERDependencyRoot = Join-Path $script:DERRuntimeRoot 'Dependencies'
    $runLogDirectory = Join-Path (Join-Path $script:DERRuntimeRoot 'Logs') $script:DERRunId
    New-Item -ItemType Directory -Path $runLogDirectory -Force | Out-Null
    $script:DERBootstrapLog = Join-Path $runLogDirectory 'DER-Bootstrap.log'

    Write-DERBootstrapMessage -Level OK -Message ('Runtime workspace: {0}' -f $script:DERRuntimeRoot)
}

function Get-DERPwshPath {
    $known = @(
        (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
    )

    foreach ($candidate in $known) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $cmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Get-DERPwshVersion {
    param([Parameter(Mandatory = $true)][string]$PwshPath)

    try {
        $raw = & $PwshPath -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        if ($raw) { return [version]($raw | Select-Object -First 1) }
    }
    catch {
        return $null
    }

    return $null
}

function Get-DERForwardedStateArguments {
    $items=New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($ImportStatePath)) {
        $items.Add('-ImportStatePath')
        $items.Add(('"{0}"' -f $ImportStatePath.Replace('"','\"')))
        $items.Add('-StateImportMode')
        $items.Add($StateImportMode)
    }
    if (-not [string]::IsNullOrWhiteSpace($ExportStatePath)) {
        $items.Add('-ExportStatePath')
        $items.Add(('"{0}"' -f $ExportStatePath.Replace('"','\"')))
    }
    $items.Add('-AdoptionMode')
    $items.Add($AdoptionMode)
    if (-not [string]::IsNullOrWhiteSpace($AdoptionDecisionPath)) {
        $items.Add('-AdoptionDecisionPath')
        $items.Add(('"{0}"' -f $AdoptionDecisionPath.Replace('"','\"')))
    }
    $items.Add('-RecoveryMode')
    $items.Add($RecoveryMode)
    if ($PreflightOnly) { $items.Add('-PreflightOnly') }
    if ($SmokeTestOnly) { $items.Add('-SmokeTestOnly') }
    if ($InstallTestDependencies) { $items.Add('-InstallTestDependencies') }
    if ($RequireSignedPackage) {
        $items.Add('-RequireSignedPackage')
    }
    if ($TenantIntegrationTest) { $items.Add('-TenantIntegrationTest') }
    if ($TenantCanaryTest) {
        $items.Add('-TenantCanaryTest')
        if (-not [string]::IsNullOrWhiteSpace($NoWriteEvidencePath)) {
            $items.Add('-NoWriteEvidencePath')
            $items.Add(('"{0}"' -f $NoWriteEvidencePath.Replace('"','\"')))
        }
    }
    if ($TenantPilotTest) {
        $items.Add('-TenantPilotTest')
        if (-not [string]::IsNullOrWhiteSpace($NoWriteEvidencePath)) {
            $items.Add('-NoWriteEvidencePath')
            $items.Add(('"{0}"' -f $NoWriteEvidencePath.Replace('"','\"')))
        }
        if (-not [string]::IsNullOrWhiteSpace($CanaryEvidencePath)) {
            $items.Add('-CanaryEvidencePath')
            $items.Add(('"{0}"' -f $CanaryEvidencePath.Replace('"','\"')))
        }
    }
    return ($items -join ' ')
}

function Start-DERElevatedBootstrap {
    Write-DERBootstrapMessage -Level WARN -Message 'Administrator elevation is required only to install/upgrade PowerShell 7.'

    $hostExecutable = (Get-Process -Id $PID).Path
    $forwarded=Get-DERForwardedStateArguments
    $arguments = ('-NoLogo -NoProfile -File "{0}" -BootstrapInstall {1}' -f $PSCommandPath,$forwarded).Trim()

    Start-Process -FilePath $hostExecutable -ArgumentList $arguments -Verb RunAs | Out-Null
    exit 0
}

function Install-DERPowerShell7 {
    if (-not (Test-DERIsWindows)) {
        throw 'DER v1 currently supports Windows only.'
    }

    if (-not (Test-DERIsAdministrator)) {
        Start-DERElevatedBootstrap
    }

    $tempDirectory = Join-Path $script:DERRuntimeRoot 'Temp'
    $msiPath = Join-Path $tempDirectory ('PowerShell-{0}-win-x64.msi' -f $script:DERPinnedPowerShell)

    Write-DERBootstrapMessage -Level STEP -Message ('Downloading PowerShell {0} directly from the official Microsoft PowerShell release...' -f $script:DERPinnedPowerShell)

    if (Test-Path -LiteralPath $msiPath) {
        Remove-Item -LiteralPath $msiPath -Force
    }

    if ($PSVersionTable.PSVersion.Major -le 5) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $script:DERPowerShellMsiUrl -OutFile $msiPath -UseBasicParsing
    }
    else {
        Invoke-WebRequest -Uri $script:DERPowerShellMsiUrl -OutFile $msiPath
    }

    if (-not (Test-Path -LiteralPath $msiPath)) {
        throw 'PowerShell MSI download did not produce a file.'
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Validating published SHA-256 for the PowerShell MSI...'
    $msiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msiPath).Hash.ToLowerInvariant()
    if ($msiHash -ne $script:DERPowerShellMsiSHA256) {
        Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
        throw ('PowerShell MSI SHA-256 validation failed. Expected {0}; got {1}.' -f $script:DERPowerShellMsiSHA256,$msiHash)
    }
    Write-DERBootstrapMessage -Level OK -Message ('PowerShell MSI SHA-256 matches the pinned Microsoft release artifact: {0}' -f $msiHash)

    Write-DERBootstrapMessage -Level STEP -Message 'Validating Microsoft Authenticode signature on the PowerShell MSI...'
    $signature = Get-AuthenticodeSignature -LiteralPath $msiPath

    if ($signature.Status -ne 'Valid') {
        throw ('PowerShell MSI signature validation failed. Status: {0}' -f $signature.Status)
    }

    if (-not $signature.SignerCertificate) {
        throw 'PowerShell MSI signature is valid but no signer certificate was returned.'
    }

    $signerSimpleName=$signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
    if ([string]$signerSimpleName -cne 'Microsoft Corporation') {
        throw ('PowerShell MSI signer identity does not match the expected Microsoft publisher. SimpleName={0}; Subject={1}' -f $signerSimpleName,$signature.SignerCertificate.Subject)
    }

    Write-DERBootstrapMessage -Level OK -Message ('PowerShell MSI signature valid for exact signer identity: {0}' -f $signerSimpleName)
    Write-DERBootstrapMessage -Level STEP -Message 'Installing PowerShell 7 silently...'

    $msiArguments = @(
        '/i',
        ('"{0}"' -f $msiPath),
        '/qn',
        '/norestart',
        'ADD_PATH=1',
        'USE_MU=0',
        'ENABLE_MU=0',
        'REGISTER_MANIFEST=1',
        'ENABLE_PSREMOTING=0'
    )

    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList ($msiArguments -join ' ') -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw ('PowerShell MSI installation failed with exit code {0}.' -f $process.ExitCode)
    }

    Write-DERBootstrapMessage -Level OK -Message ('PowerShell {0} installation completed. Exit code: {1}' -f $script:DERPinnedPowerShell, $process.ExitCode)
}

function Restart-DERUnderPowerShell7 {
    param([Parameter(Mandatory = $true)][string]$PwshPath)

    Write-DERBootstrapMessage -Level STEP -Message ('Relaunching DER under {0}' -f $PwshPath)
    $forwarded=Get-DERForwardedStateArguments
    $arguments = ('-NoLogo -NoProfile -File "{0}" -RelaunchedFromBootstrap {1}' -f $PSCommandPath,$forwarded).Trim()
    Start-Process -FilePath $PwshPath -ArgumentList $arguments | Out-Null
    exit 0
}

function Initialize-DERPowerShell7 {
    $current = $PSVersionTable.PSVersion
    if ($current.Major -ge 7 -and $current -ge $script:DERMinPowerShellVersion) {
        Write-DERBootstrapMessage -Level OK -Message ('PowerShell {0} is supported.' -f $current)
        return
    }

    $pwshPath = Get-DERPwshPath
    if ($pwshPath) {
        $pwshVersion = Get-DERPwshVersion -PwshPath $pwshPath
        if ($pwshVersion -and $pwshVersion -ge $script:DERMinPowerShellVersion) {
            Write-DERBootstrapMessage -Level OK -Message ('Supported PowerShell {0} found at {1}' -f $pwshVersion, $pwshPath)
            Restart-DERUnderPowerShell7 -PwshPath $pwshPath
        }
    }

    Write-DERBootstrapMessage -Level WARN -Message ('PowerShell {0}+ is required. DER has not found a supported installation.' -f $script:DERMinPowerShellVersion)

    $approved = $false
    if ($BootstrapInstall) {
        $approved = $true
    }
    else {
        $answer = Read-Host ('Install PowerShell {0} now from Microsoft? [Y/n]' -f $script:DERPinnedPowerShell)
        if ([string]::IsNullOrWhiteSpace($answer) -or $answer.Trim().ToUpperInvariant() -eq 'Y') {
            $approved = $true
        }
    }

    if (-not $approved) {
        throw 'PowerShell 7 installation was declined. DER cannot continue.'
    }

    Install-DERPowerShell7

    $pwshPath = Get-DERPwshPath
    if (-not $pwshPath) {
        throw 'PowerShell installation completed but pwsh.exe could not be located.'
    }

    $installedVersion = Get-DERPwshVersion -PwshPath $pwshPath
    if (-not $installedVersion -or $installedVersion -lt $script:DERMinPowerShellVersion) {
        throw ('Installed PowerShell version is not supported. Detected: {0}' -f $installedVersion)
    }

    Restart-DERUnderPowerShell7 -PwshPath $pwshPath
}

function ConvertTo-DERPackagePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw ('Unsafe package-relative path: {0}' -f $RelativePath)
    }

    $normalized = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar).Replace('\', [IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath((Join-Path $script:DERPackageRoot $normalized))
    $rootFull = [IO.Path]::GetFullPath($script:DERPackageRoot)
    $rootPrefix = $rootFull + [string][IO.Path]::DirectorySeparatorChar
    if (-not $full.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -and -not $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Package manifest path escaped the package root: {0}' -f $RelativePath)
    }
    return $full
}

function Test-DERBootstrapPackageIntegrity {
    Write-DERBootstrapMessage -Level STEP -Message 'Validating DER package integrity and signing posture...'

    $manifestPath = Join-Path $script:DERPackageRoot 'Definitions\Package\DER-PackageManifest.json'
    $signingPolicyPath = Join-Path $script:DERPackageRoot 'Definitions\Package\DER-SigningPolicy.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'DER package manifest is missing.' }
    if (-not (Test-Path -LiteralPath $signingPolicyPath)) { throw 'DER signing policy is missing.' }

    $actualManifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
    if ($actualManifestHash -ne $script:DERPackageManifestSHA256.ToLowerInvariant()) {
        throw ('DER package manifest trust-anchor hash mismatch. Expected {0}; got {1}.' -f $script:DERPackageManifestSHA256, $actualManifestHash)
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$manifest.schemaVersion -ne $script:DERPackageManifestSchema) { throw 'DER package manifest schema version mismatch.' }
    if ([string]$manifest.packageVersion -ne $script:DERPackageVersion) { throw 'DER package version mismatch between launcher and package manifest.' }
    if ([int]$manifest.buildNumber -ne $script:DERPackageBuildNumber) { throw 'DER package build number mismatch between launcher and package manifest.' }
    if ([string]$manifest.engineVersion -ne $script:DEREngineVersion) { throw 'DER engine version mismatch between launcher and package manifest.' }
    if ([string]$manifest.baselineVersion -ne $script:DERBaselineVersion) { throw 'DER baseline version mismatch between launcher and package manifest.' }
    if ([string]$manifest.hashAlgorithm -ne 'SHA256') { throw 'DER package manifest hash algorithm is unsupported.' }

    $seen = @{}
    foreach ($entry in @($manifest.protectedFiles)) {
        $relative = ([string]$entry.path).Replace('\','/')
        if ($seen.ContainsKey($relative.ToLowerInvariant())) { throw ('Duplicate package-manifest path: {0}' -f $relative) }
        $seen[$relative.ToLowerInvariant()] = $true
        $path = ConvertTo-DERPackagePath -RelativePath $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('DER package file is missing: {0}' -f $relative) }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne ([string]$entry.sha256).ToLowerInvariant()) {
            throw ('DER package integrity failure: {0} SHA-256 mismatch.' -f $relative)
        }
        $length = (Get-Item -LiteralPath $path).Length
        if ([long]$entry.bytes -ne [long]$length) { throw ('DER package integrity failure: {0} length mismatch.' -f $relative) }
    }

    $specialFiles = @('start-derintunebuilder.ps1','definitions/package/der-packagemanifest.json','sha256sums.txt')
    $untracked = New-Object System.Collections.Generic.List[string]
    foreach ($file in Get-ChildItem -LiteralPath $script:DERPackageRoot -Recurse -File -ErrorAction Stop) {
        $rel = [IO.Path]::GetRelativePath($script:DERPackageRoot, $file.FullName).Replace('\','/')
        $key = $rel.ToLowerInvariant()
        if ($key -in $specialFiles -or $rel -match '\.(zip|sha256)$') { continue }
        if (-not $seen.ContainsKey($key)) { $untracked.Add($rel) }
    }
    if ($untracked.Count -gt 0) {
        throw ('DER package contains untracked files: {0}' -f (($untracked | Sort-Object) -join ', '))
    }

    $updateManifestPath = Join-Path $script:DERPackageRoot 'Definitions\Package\DER-UpdateManifest.json'
    if (-not (Test-Path -LiteralPath $updateManifestPath)) { throw 'DER update manifest is missing.' }
    $updateManifest = Get-Content -LiteralPath $updateManifestPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$updateManifest.schemaVersion -ne $script:DERUpdateManifestSchema) { throw 'DER update manifest schema version mismatch.' }
    if ([string]$updateManifest.packageVersion -ne $script:DERPackageVersion -or [int]$updateManifest.buildNumber -ne $script:DERPackageBuildNumber) { throw 'DER update manifest package identity does not match the launcher.' }
    if ([string]$updateManifest.channel -ne [string]$manifest.channel -or [string]$updateManifest.engineVersion -ne $script:DEREngineVersion -or [string]$updateManifest.baselineVersion -ne $script:DERBaselineVersion) { throw 'DER update manifest runtime identity does not match the package manifest.' }
    if ([string]$updateManifest.runtime.minimumPowerShell -ne $script:DERMinPowerShellVersion.ToString() -or [string]$updateManifest.runtime.bootstrapPowerShell -ne $script:DERPinnedPowerShell -or [string]$updateManifest.runtime.bootstrapPowerShellMsiSHA256 -ne $script:DERPowerShellMsiSHA256) { throw 'DER update manifest PowerShell contract does not match the launcher.' }
    if ([string]$updateManifest.dependencies.lockVersion -ne $script:DERDependencyLockVersion) { throw 'DER update manifest dependency-lock version does not match the launcher.' }

    $integrationPolicyPath = Join-Path $script:DERPackageRoot 'Definitions\Integration\DER-TestTenantIntegrationPolicy.json'
    if (-not (Test-Path -LiteralPath $integrationPolicyPath)) { throw 'DER test-tenant integration policy is missing.' }
    $integrationPolicy = Get-Content -LiteralPath $integrationPolicyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$integrationPolicy.policyVersion -ne $script:DERIntegrationPolicyVersion) { throw 'DER test-tenant integration policy version mismatch.' }
    if ([string]$integrationPolicy.generatedForPackage -ne $script:DERPackageVersion) { throw 'DER test-tenant integration policy package binding does not match the launcher.' }
    if ([int]$integrationPolicy.generatedForBuild -ne $script:DERPackageBuildNumber) { throw 'DER test-tenant integration policy internal-build binding does not match the launcher.' }
    if ([string]$updateManifest.compatibility.testTenantIntegrationPolicy -ne $script:DERIntegrationPolicyVersion) { throw 'DER update manifest integration-policy compatibility does not match the launcher.' }

    $canaryPolicyPath = Join-Path $script:DERPackageRoot 'Definitions\Canary\DER-CanaryPolicy.json'
    if (-not (Test-Path -LiteralPath $canaryPolicyPath)) { throw 'DER controlled canary policy is missing.' }
    $canaryPolicy = Get-Content -LiteralPath $canaryPolicyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$canaryPolicy.policyVersion -ne $script:DERCanaryPolicyVersion) { throw 'DER canary policy version mismatch.' }
    if ([string]$canaryPolicy.generatedForPackage -ne $script:DERPackageVersion) { throw 'DER canary policy package binding does not match the launcher.' }
    if ([int]$canaryPolicy.generatedForBuild -ne $script:DERPackageBuildNumber) { throw 'DER canary policy internal-build binding does not match the launcher.' }
    if ([string]$updateManifest.compatibility.canaryPilotPolicy -ne $script:DERCanaryPolicyVersion) { throw 'DER update manifest canary-policy compatibility does not match the launcher.' }

    $pilotPolicyPath = Join-Path $script:DERPackageRoot 'Definitions\Pilot\DER-PilotPolicy.json'
    if (-not (Test-Path -LiteralPath $pilotPolicyPath)) { throw 'DER workload pilot policy is missing.' }
    $pilotPolicy = Get-Content -LiteralPath $pilotPolicyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$pilotPolicy.policyVersion -ne $script:DERPilotPolicyVersion) { throw 'DER workload pilot policy version mismatch.' }
    if ([string]$pilotPolicy.generatedForPackage -ne $script:DERPackageVersion) { throw 'DER workload pilot policy package binding does not match the launcher.' }
    if ([int]$pilotPolicy.generatedForBuild -ne $script:DERPackageBuildNumber) { throw 'DER workload pilot policy internal-build binding does not match the launcher.' }
    if ([string]$updateManifest.compatibility.workloadPilotPolicy -ne $script:DERPilotPolicyVersion) { throw 'DER update manifest workload-pilot compatibility does not match the launcher.' }

    $freezePolicyPath = Join-Path $script:DERPackageRoot 'Definitions\Release\DER-DevFreezePolicy.json'
    if (-not (Test-Path -LiteralPath $freezePolicyPath)) { throw 'DER development freeze policy is missing.' }
    $freezePolicy = Get-Content -LiteralPath $freezePolicyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$freezePolicy.policyVersion -ne $script:DERDevFreezePolicyVersion) { throw 'DER development freeze policy version mismatch.' }
    if ([string]$freezePolicy.generatedForPackage -ne $script:DERPackageVersion) { throw 'DER development freeze policy package binding does not match the launcher.' }
    if ([int]$freezePolicy.generatedForBuild -ne $script:DERPackageBuildNumber) { throw 'DER development freeze policy internal-build binding does not match the launcher.' }
    if ([string]$freezePolicy.lifecycleStatus -ne 'FeatureCompleteDevelopment') { throw 'DER development freeze policy lifecycle status is invalid.' }
    if ([bool]$freezePolicy.featureFreeze.newTenantFeaturesAllowed) { throw 'DER development freeze unexpectedly allows new tenant features.' }
    if ([string]$updateManifest.compatibility.devFreezePolicy -ne $script:DERDevFreezePolicyVersion) { throw 'DER update manifest development-freeze compatibility does not match the launcher.' }

    $signingPolicy = Get-Content -LiteralPath $signingPolicyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$signingPolicy.policyVersion -ne $script:DERSigningPolicyVersion) { throw 'DER signing policy version mismatch.' }
    $strictSigning = [bool]$RequireSignedPackage -or ([string]$manifest.channel -eq 'Release')
    $allowedThumbprints = @($signingPolicy.release.allowedCertificateThumbprints | ForEach-Object { ([string]$_).Replace(' ','').ToUpperInvariant() })
    if ($strictSigning -and [bool]$signingPolicy.release.blockIfThumbprintListEmpty -and $allowedThumbprints.Count -eq 0) {
        throw 'Signed-package validation was requested, but no DER release certificate thumbprint is configured in the signing policy.'
    }

    $signable = New-Object System.Collections.Generic.List[string]
    $signable.Add((Join-Path $script:DERPackageRoot 'Start-DERIntuneBuilder.ps1'))
    foreach ($dir in @('Core','Workloads')) {
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $script:DERPackageRoot $dir) -Filter '*.psm1' -File | Sort-Object Name) { $signable.Add($file.FullName) }
    }

    $signedCount = 0
    $unsignedCount = 0
    foreach ($file in $signable) {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        $status = [string]$sig.Status
        if ($status -eq 'Valid') {
            $signedCount++
            if ($strictSigning) {
                if (-not $sig.SignerCertificate) { throw ('Signed DER file has no signer certificate: {0}' -f $file) }
                $thumbprint = ([string]$sig.SignerCertificate.Thumbprint).Replace(' ','').ToUpperInvariant()
                if ($thumbprint -notin $allowedThumbprints) { throw ('DER file signer is not in the release allowlist: {0}' -f $file) }
                if ([bool]$signingPolicy.release.timestampRequired -and -not $sig.TimeStamperCertificate) { throw ('DER release signature is missing a trusted timestamp: {0}' -f $file) }
            }
        }
        elseif ($status -eq 'NotSigned') {
            $unsignedCount++
            if ($strictSigning) { throw ('DER release-mode package contains an unsigned runtime file: {0}' -f $file) }
        }
        else {
            throw ('DER runtime file has an invalid Authenticode status ({0}): {1}' -f $status, $file)
        }
    }

    $report = [ordered]@{
        schemaVersion = '1.0'
        packageVersion = $script:DERPackageVersion
        buildNumber = $script:DERPackageBuildNumber
        channel = [string]$manifest.channel
        manifestSHA256 = $actualManifestHash
        manifestFilesValidated = @($manifest.protectedFiles).Count
        strictSigning = $strictSigning
        validSignedRuntimeFiles = $signedCount
        unsignedRuntimeFiles = $unsignedCount
        status = 'PASS'
        checkedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    if ($script:DERBootstrapLog) {
        $reportPath = Join-Path (Split-Path $script:DERBootstrapLog -Parent) 'DER-PackageSelfCheck.json'
        $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $reportPath -Encoding utf8
    }

    Write-DERBootstrapMessage -Level OK -Message ('Package self-check PASS: {0} protected files; signatures valid={1}, unsigned={2}, strict={3}.' -f @($manifest.protectedFiles).Count, $signedCount, $unsignedCount, $strictSigning)
    return [pscustomobject]$report
}

function Get-DERDependencyContract {
    $path = Join-Path $script:DERPackageRoot 'Definitions\Package\DER-DependencyLock.json'
    if (-not (Test-Path -LiteralPath $path)) { throw 'DER dependency lock is missing.' }
    $lock = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 100
    if ([string]$lock.lockVersion -ne $script:DERDependencyLockVersion) { throw 'DER dependency lock version mismatch.' }
    if ([string]$lock.generatedForEngine -ne $script:DEREngineVersion) { throw 'DER dependency lock engine version mismatch.' }
    $dependency = @($lock.dependencies | Where-Object { [string]$_.name -eq 'Microsoft.Graph.Authentication' }) | Select-Object -First 1
    if (-not $dependency) { throw 'Microsoft.Graph.Authentication is missing from the DER dependency lock.' }
    if ([string]$dependency.version -ne $script:DERGraphAuthVersion) { throw 'Graph Authentication version does not match the DER dependency lock.' }
    if ([guid]$dependency.moduleGuid -ne $script:DERGraphAuthModuleGuid) { throw 'Graph Authentication module GUID does not match the DER dependency lock.' }
    return $dependency
}

function Get-DERGraphAuthManifestPath {
    $candidates = @(
        [pscustomobject]@{ Root=(Join-Path $script:DERPackageRoot 'Dependencies\Microsoft.Graph.Authentication'); Source='Package' },
        [pscustomobject]@{ Root=(Join-Path $script:DERDependencyRoot 'Microsoft.Graph.Authentication'); Source='Runtime' }
    )
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate.Root)) { continue }
        $known = Join-Path $candidate.Root ('{0}\Microsoft.Graph.Authentication.psd1' -f $script:DERGraphAuthVersion)
        if (Test-Path -LiteralPath $known) { return [pscustomobject]@{Path=$known;Source=$candidate.Source} }
        foreach ($manifest in Get-ChildItem -LiteralPath $candidate.Root -Recurse -Filter 'Microsoft.Graph.Authentication.psd1' -File -ErrorAction SilentlyContinue) {
            try {
                $info = Test-ModuleManifest -Path $manifest.FullName -ErrorAction Stop
                if ($info.Version -eq [version]$script:DERGraphAuthVersion -and $info.Guid -eq $script:DERGraphAuthModuleGuid) {
                    return [pscustomobject]@{Path=$manifest.FullName;Source=$candidate.Source}
                }
            }
            catch { continue }
        }
    }
    return $null
}

function Get-DERDependencyContentLockPath {
    $lockRoot = Join-Path $script:DERDependencyRoot 'Locks'
    if (-not (Test-Path -LiteralPath $lockRoot)) { New-Item -ItemType Directory -Path $lockRoot -Force | Out-Null }
    return (Join-Path $lockRoot ('Microsoft.Graph.Authentication-{0}.integrity.json' -f $script:DERGraphAuthVersion))
}

function New-DERDependencyContentLock {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $moduleRoot = Split-Path $ManifestPath -Parent
    $files = foreach ($file in Get-ChildItem -LiteralPath $moduleRoot -Recurse -File | Sort-Object FullName) {
        [ordered]@{
            path = [IO.Path]::GetRelativePath($moduleRoot, $file.FullName).Replace('\','/')
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
            bytes = [long]$file.Length
        }
    }
    $lock = [ordered]@{
        schemaVersion='1.0'
        dependency='Microsoft.Graph.Authentication'
        version=$script:DERGraphAuthVersion
        moduleGuid=$script:DERGraphAuthModuleGuid.ToString()
        createdUtc=(Get-Date).ToUniversalTime().ToString('o')
        files=@($files)
    }
    $lockPath = Get-DERDependencyContentLockPath
    $lock | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $lockPath -Encoding utf8
    return $lockPath
}

function Test-DERDependencyContentLock {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $lockPath = Get-DERDependencyContentLockPath
    if (-not (Test-Path -LiteralPath $lockPath)) { return $false }
    try { $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json -Depth 50 } catch { return $false }
    if ([string]$lock.dependency -ne 'Microsoft.Graph.Authentication' -or [string]$lock.version -ne $script:DERGraphAuthVersion -or [guid]$lock.moduleGuid -ne $script:DERGraphAuthModuleGuid) { return $false }
    $moduleRoot = Split-Path $ManifestPath -Parent
    $actualFiles = @(Get-ChildItem -LiteralPath $moduleRoot -Recurse -File)
    if ($actualFiles.Count -ne @($lock.files).Count) { return $false }
    foreach ($entry in @($lock.files)) {
        $relative = ([string]$entry.path).Replace('/', [IO.Path]::DirectorySeparatorChar)
        $path = Join-Path $moduleRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
        if ((Get-Item -LiteralPath $path).Length -ne [long]$entry.bytes) { return $false }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne ([string]$entry.sha256).ToLowerInvariant()) { return $false }
    }
    return $true
}

function Assert-DERGraphAuthenticationContract {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $dependency = Get-DERDependencyContract
    $moduleInfo = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop
    if ($moduleInfo.Version -ne [version]$dependency.version) { throw ('Graph dependency version mismatch: {0}' -f $moduleInfo.Version) }
    if ($moduleInfo.Guid -ne [guid]$dependency.moduleGuid) { throw ('Graph dependency GUID mismatch: {0}' -f $moduleInfo.Guid) }
    if ([string]$moduleInfo.Author -ne [string]$dependency.publisher -or [string]$moduleInfo.CompanyName -ne [string]$dependency.publisher) {
        throw 'Graph dependency publisher metadata does not match the DER dependency lock.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $ManifestPath
    if ([string]$signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
        throw ('Graph dependency manifest Authenticode validation failed. Status: {0}' -f $signature.Status)
    }
    $expectedSigner=[string]$dependency.runtimeIntegrity.manifestSignerSimpleName
    if ([string]::IsNullOrWhiteSpace($expectedSigner)) { throw 'Graph dependency lock is missing manifestSignerSimpleName.' }
    $actualSigner=$signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
    if ([string]$actualSigner -cne $expectedSigner) {
        throw ('Graph dependency signer identity does not match the dependency lock. Expected={0}; Actual={1}; Subject={2}' -f $expectedSigner,$actualSigner,$signature.SignerCertificate.Subject)
    }
    return $moduleInfo
}

function Initialize-DERGraphAuthenticationModule {
    Write-DERBootstrapMessage -Level STEP -Message ('Checking Microsoft.Graph.Authentication {0} against the dependency lock...' -f $script:DERGraphAuthVersion)

    $candidate = Get-DERGraphAuthManifestPath
    if ($candidate -and $candidate.Source -eq 'Runtime' -and -not (Test-DERDependencyContentLock -ManifestPath $candidate.Path)) {
        Write-DERBootstrapMessage -Level WARN -Message 'Existing DER Graph dependency cache has no valid content lock. It will be discarded and reacquired.'
        $staleRoot = Join-Path $script:DERDependencyRoot 'Microsoft.Graph.Authentication'
        if (Test-Path -LiteralPath $staleRoot) { Remove-Item -LiteralPath $staleRoot -Recurse -Force -ErrorAction Stop }
        $candidate = $null
    }

    if (-not $candidate) {
        Write-DERBootstrapMessage -Level WARN -Message ('Microsoft.Graph.Authentication {0} is missing from the trusted DER dependency locations.' -f $script:DERGraphAuthVersion)
        Write-DERBootstrapMessage -Level STEP -Message 'Downloading the exact pinned module from PowerShell Gallery with Authenticode validation...'

        Import-Module Microsoft.PowerShell.PSResourceGet -ErrorAction SilentlyContinue
        if (-not (Get-Command Save-PSResource -ErrorAction SilentlyContinue)) {
            throw 'Save-PSResource is unavailable. DER requires Microsoft.PowerShell.PSResourceGet so dependency downloads can use Authenticode validation.'
        }

        try {
            Save-PSResource -Name 'Microsoft.Graph.Authentication' -Version $script:DERGraphAuthVersion -Repository 'PSGallery' -Path $script:DERDependencyRoot -TrustRepository -AuthenticodeCheck -ErrorAction Stop
        }
        catch {
            throw ('Unable to acquire validated Microsoft.Graph.Authentication {0}: {1}' -f $script:DERGraphAuthVersion, $_.Exception.Message)
        }

        $candidate = Get-DERGraphAuthManifestPath
        if (-not $candidate -or $candidate.Source -ne 'Runtime') { throw 'Validated Graph dependency download did not produce the expected isolated runtime module.' }
        Assert-DERGraphAuthenticationContract -ManifestPath $candidate.Path | Out-Null
        $contentLock = New-DERDependencyContentLock -ManifestPath $candidate.Path
        Write-DERBootstrapMessage -Level OK -Message ('Dependency content lock created: {0}' -f $contentLock)
    }
    else {
        Assert-DERGraphAuthenticationContract -ManifestPath $candidate.Path | Out-Null
    }

    if ($candidate.Source -eq 'Runtime' -and -not (Test-DERDependencyContentLock -ManifestPath $candidate.Path)) {
        throw 'Graph dependency runtime content-lock verification failed.'
    }

    Import-Module -Name $candidate.Path -Force -ErrorAction Stop
    $loaded = Get-Module -Name Microsoft.Graph.Authentication | Select-Object -First 1
    if (-not $loaded) { throw ('DER expected Microsoft.Graph.Authentication {0}, but the module did not load.' -f $script:DERGraphAuthVersion) }
    if ($loaded.Version -ne [version]$script:DERGraphAuthVersion -or $loaded.Guid -ne $script:DERGraphAuthModuleGuid) {
        throw ('DER loaded an unexpected Microsoft.Graph.Authentication identity. Version={0}; GUID={1}.' -f $loaded.Version, $loaded.Guid)
    }

    foreach ($command in @((Get-DERDependencyContract).requiredCommands)) {
        if (-not (Get-Command ([string]$command) -ErrorAction SilentlyContinue)) { throw ('Required Microsoft Graph command is unavailable after import: {0}' -f $command) }
    }
    Write-DERBootstrapMessage -Level OK -Message ('Microsoft.Graph.Authentication {0} loaded from {1} with publisher and content-integrity checks.' -f $loaded.Version, $candidate.Source)
}


function Invoke-DERWindowsPreflightGate {
    $tool = Join-Path $script:DERPackageRoot 'Tools\Invoke-DERWindowsPreflight.ps1'
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'DER Windows preflight tool is missing.' }

    $policyPath = Join-Path $script:DERPackageRoot 'Definitions\Validation\DER-WindowsValidationPolicy.json'
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw 'DER Windows validation policy is missing.' }
    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json -Depth 100
    if ([string]$policy.policyVersion -ne $script:DERWindowsValidationPolicy) { throw 'DER Windows validation policy version mismatch.' }
    if ([string]$policy.generatedForPackage -ne $script:DERPackageVersion) { throw 'DER Windows validation policy package version mismatch.' }
    if ([int]$policy.generatedForBuild -ne $script:DERPackageBuildNumber) { throw 'DER Windows validation policy internal-build mismatch.' }
    if ([string]$policy.platform.preferredPowerShell -ne $script:DERPinnedPowerShell) { throw 'DER Windows validation policy PowerShell target does not match the launcher.' }

    $reportPath = Join-Path (Split-Path $script:DERBootstrapLog -Parent) 'DER-WindowsPreflight.json'
    $result = & $tool -ProjectRoot $script:DERPackageRoot -RuntimeRoot $script:DERRuntimeRoot -OutputPath $reportPath -SkipPackageCheck
    if (-not $result -or [string]$result.Status -ne 'PASS') {
        throw ('DER Windows preflight failed. Review {0}' -f $reportPath)
    }
    Write-DERBootstrapMessage -Level OK -Message ('Windows preflight PASS. Report: {0}' -f $reportPath)
    return $result
}

function Invoke-DERWindowsSmokeGate {
    $tool = Join-Path $script:DERPackageRoot 'Tools\Invoke-DERWindowsSmokeTest.ps1'
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'DER Windows smoke-test tool is missing.' }
    $output = Join-Path (Split-Path $script:DERBootstrapLog -Parent) 'SmokeTest'
    $smokeArguments = @{
        ProjectRoot = $script:DERPackageRoot
        RuntimeRoot = $script:DERRuntimeRoot
        OutputDirectory = $output
        SkipPreflight = $true
        SkipPackageCheck = $true
    }
    if ($InstallTestDependencies) { $smokeArguments.InstallTestDependencies = $true }
    if ($RequireSignedPackage) { $smokeArguments.RequireSignedPackage = $true }

    $result = & $tool @smokeArguments
    if (-not $result -or [string]$result.Status -ne 'PASS') {
        throw ('DER Windows smoke test failed. Review {0}' -f (Join-Path $output 'DER-WindowsSmokeTest.json'))
    }
    Write-DERBootstrapMessage -Level OK -Message ('Windows smoke test PASS. Report: {0}' -f (Join-Path $output 'DER-WindowsSmokeTest.json'))
    return $result
}

function Get-DERChildModuleStatus {
    $status = foreach ($module in ($script:DERModuleCatalog | Sort-Object Order)) {
        $path = Join-Path $script:DERPackageRoot $module.File
        $exists = Test-Path -LiteralPath $path
        $implemented = $false
        $reason = $null

        if ($exists) {
            try {
                $content = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
                if (-not [string]::IsNullOrWhiteSpace($content)) {
                    $implemented = $true
                }
                else {
                    $reason = 'Module file exists but is empty'
                }
            }
            catch {
                $reason = $_.Exception.Message
            }
        }
        else {
            $reason = 'Required module file is missing from this package'
        }

        [pscustomobject]@{
            Order       = $module.Order
            Area        = $module.Area
            File        = $module.File
            EntryPoint  = $module.EntryPoint
            Required    = $module.Required
            Exists      = $exists
            Implemented = $implemented
            Reason      = $reason
        }
    }

    return $status
}

function Import-DERChildModules {
    param([Parameter(Mandatory = $true)][array]$Status)

    foreach ($item in ($Status | Where-Object Implemented | Sort-Object Order)) {
        $path = Join-Path $script:DERPackageRoot $item.File
        Write-DERBootstrapMessage -Level STEP -Message ('Loading child module: {0}' -f $item.File)
        Import-Module -Name $path -Force -ErrorAction Stop

        if (-not (Get-Command $item.EntryPoint -ErrorAction SilentlyContinue)) {
            throw ('Child module {0} loaded but required entry point {1} was not exported.' -f $item.File, $item.EntryPoint)
        }
    }
}

function Show-DERHeader {
    Clear-Host
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor DarkCyan
    Write-Host ' DER INTUNE / ENTRA ENVIRONMENT BUILDER' -ForegroundColor Cyan
    Write-Host ' Development Build' -ForegroundColor Yellow
    Write-Host '==============================================================' -ForegroundColor DarkCyan
    Write-Host (' Engine   : {0}' -f $script:DEREngineVersion)
    Write-Host (' Baseline : {0}' -f $script:DERBaselineVersion)
    Write-Host (' Product  : DER v1 | Package {0} | Internal build {1}' -f $script:DERPackageVersion, $script:DERPackageBuildNumber)
    Write-Host (' Run ID   : {0}' -f $script:DERRunId)
    Write-Host '==============================================================' -ForegroundColor DarkCyan
    Write-Host ''
}

function Show-DERDevelopmentStatus {
    <#
    .SYNOPSIS
        Displays and enforces the exact DER v1 child-module inventory.

    .DESCRIPTION
        The module catalog is a package/runtime contract, not a progressive feature
        list. Every advertised Core and Workload module must be present and non-empty
        before DER proceeds. Workloads may be disabled by the build plan, but their
        implementation files are still required package content. A missing/empty
        catalog entry is therefore an ENGINE/package defect and can never produce a
        successful launcher result.
    #>
    param([Parameter(Mandatory = $true)][array]$Status)

    $implemented = @($Status | Where-Object Implemented)
    $unavailable = @($Status | Where-Object { -not $_.Implemented })
    $catalog = @($Status)

    Write-Host ''
    Write-Host 'DER CHILD MODULE STATUS' -ForegroundColor Cyan
    Write-Host ('  Available : {0}/{1}' -f $implemented.Count, $catalog.Count)
    Write-Host ('  Missing/invalid: {0}' -f $unavailable.Count)
    Write-Host ''

    foreach ($item in ($Status | Sort-Object Order)) {
        $mark = if ($item.Implemented) { '[+]' } else { '[X]' }
        $color = if ($item.Implemented) { 'Green' } else { 'Red' }
        Write-Host ('{0} {1}' -f $mark, $item.File) -ForegroundColor $color
    }

    Write-Host ''

    if ($unavailable.Count -gt 0) {
        $first=$unavailable | Sort-Object Order | Select-Object -First 1
        Write-DERBootstrapMessage -Level ERROR -EventDomain Engine -FailureKind Engine -Message (
            'DER v1 package module inventory is incomplete or unreadable. First unavailable module: {0}. Reason: {1}' -f $first.File,$first.Reason
        )
        return $false
    }

    return $true
}

# -----------------------------------------------------------------------------
# Parent execution
# -----------------------------------------------------------------------------
try {
    Show-DERHeader

    if (-not (Test-DERIsWindows)) {
        throw 'DER v1 development build currently supports Windows only.'
    }

    Initialize-DERRuntimeRoot

    Write-DERBootstrapMessage -Level INFO -Message ('Package root: {0}' -f $script:DERPackageRoot)
    Write-DERBootstrapMessage -Level INFO -Message ('Host PowerShell: {0} ({1})' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)

    Initialize-DERPowerShell7

    if ($PreflightOnly -and $SmokeTestOnly) {
        throw 'Choose either -PreflightOnly or -SmokeTestOnly, not both.'
    }
    if ($InstallTestDependencies -and -not $SmokeTestOnly) {
        throw '-InstallTestDependencies is valid only with -SmokeTestOnly.'
    }
    if ($TenantIntegrationTest -and ($PreflightOnly -or $SmokeTestOnly)) {
        throw '-TenantIntegrationTest cannot be combined with -PreflightOnly or -SmokeTestOnly.'
    }
    if ($TenantIntegrationTest -and -not [string]::IsNullOrWhiteSpace($ImportStatePath)) {
        throw '-TenantIntegrationTest cannot import portable DER state. Use a clean disposable test-tenant run.'
    }
    if ($TenantIntegrationTest -and $TenantCanaryTest) {
        throw 'Choose either -TenantIntegrationTest or -TenantCanaryTest, not both.'
    }
    if ($TenantCanaryTest -and ($PreflightOnly -or $SmokeTestOnly)) {
        throw '-TenantCanaryTest cannot be combined with -PreflightOnly or -SmokeTestOnly.'
    }
    if ($TenantCanaryTest -and [string]::IsNullOrWhiteSpace($NoWriteEvidencePath)) {
        throw '-TenantCanaryTest requires -NoWriteEvidencePath from a passing same-package integration run.'
    }
    if ($TenantCanaryTest -and -not [string]::IsNullOrWhiteSpace($ImportStatePath)) {
        throw '-TenantCanaryTest cannot import portable DER state. Use a clean disposable test-tenant run.'
    }
    if ($TenantPilotTest -and ($PreflightOnly -or $SmokeTestOnly)) {
        throw '-TenantPilotTest cannot be combined with -PreflightOnly or -SmokeTestOnly.'
    }
    if ($TenantPilotTest -and ([string]::IsNullOrWhiteSpace($NoWriteEvidencePath) -or [string]::IsNullOrWhiteSpace($CanaryEvidencePath))) {
        throw '-TenantPilotTest requires both -NoWriteEvidencePath and -CanaryEvidencePath from passing same-package runs.'
    }
    if ($TenantPilotTest -and -not [string]::IsNullOrWhiteSpace($ImportStatePath)) {
        throw '-TenantPilotTest cannot import portable DER state. Use a clean disposable test-tenant run.'
    }
    if (@(@($TenantIntegrationTest,$TenantCanaryTest,$TenantPilotTest) | Where-Object { $_ }).Count -gt 1) {
        throw 'Choose only one tenant test mode: -TenantIntegrationTest, -TenantCanaryTest, or -TenantPilotTest.'
    }

    # Execution only reaches this point in the supported PS7 host. Package
    # integrity and Windows preflight are completed before Graph dependency
    # acquisition, child-module load, or tenant authentication.
    Test-DERBootstrapPackageIntegrity | Out-Null
    $preflightResult = Invoke-DERWindowsPreflightGate

    if ($PreflightOnly) {
        Write-Host ''
        Write-Host 'DER PREFLIGHT-ONLY RESULT: PASS' -ForegroundColor Green
        Write-Host 'No Microsoft Graph authentication or tenant request was performed.' -ForegroundColor Gray
        Write-Host ''
        exit 0
    }

    if ($SmokeTestOnly) {
        $smokeResult = Invoke-DERWindowsSmokeGate
        Write-Host ''
        Write-Host 'DER SMOKE-TEST-ONLY RESULT: PASS' -ForegroundColor Green
        Write-Host 'No Microsoft Graph authentication or tenant request was performed.' -ForegroundColor Gray
        Write-Host ''
        exit 0
    }

    Initialize-DERGraphAuthenticationModule

    $childStatus = @(Get-DERChildModuleStatus)
    Import-DERChildModules -Status $childStatus

    $moduleInventoryReady = Show-DERDevelopmentStatus -Status $childStatus
    if (-not $moduleInventoryReady) {
        throw 'DER v1 package module inventory validation failed. The package is incomplete or unreadable and cannot continue.'
    }

    # -------------------------------------------------------------------------
    # Main orchestration flow.
    # Each call remains deliberately delegated to a child module.
    # -------------------------------------------------------------------------
    Write-DERBootstrapMessage -Level STEP -Message 'Initializing full DER logging...'
    Initialize-DERLogging -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot -EngineVersion $script:DEREngineVersion -PackageVersion $script:DERPackageVersion -BuildNumber $script:DERPackageBuildNumber -BaselineVersion $script:DERBaselineVersion

    Write-DERBootstrapMessage -Level STEP -Message 'Initializing DER Graph engine...'
    Initialize-DERGraphEngine -RunId $script:DERRunId -PackageRoot $script:DERPackageRoot

    if ($TenantIntegrationTest -or $TenantCanaryTest -or $TenantPilotTest) {
        $modeName=if($TenantPilotTest){'END-TO-END WORKLOAD PILOT MODE'}elseif($TenantCanaryTest){'CONTROLLED CANARY MODE'}else{'TEST-TENANT INTEGRATION MODE'}
        Write-DERBootstrapMessage -Level WARN -Message ("{0}: enabling central Graph DENY-ALL write guard before tenant authentication." -f $modeName)
        $guardReason=if($TenantPilotTest){'Workload pilot pre-approval guard. Writes remain impossible until same-package evidence and PILOT-WRITE approval pass.'}elseif($TenantCanaryTest){'Canary pre-approval guard. Writes remain impossible until prerequisite evidence and CANARY-WRITE approval pass.'}else{'Test-tenant integration run. POST/PATCH/PUT/DELETE are forbidden before transport.'}
        Set-DERGraphWriteGuard -Mode DenyAll -Reason $guardReason | Out-Null
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Starting read/discovery authentication...'
    $discoverySession = Connect-DERDiscoverySession -RunId $script:DERRunId

    $integrationAttestation = $null
    if ($TenantIntegrationTest) {
        $integrationAttestation = Confirm-DERTestTenant -Session $discoverySession -PackageRoot $script:DERPackageRoot
        if (-not [bool]$integrationAttestation.Confirmed) { throw (New-DERFailureException -Message 'Disposable test-tenant confirmation was not granted. DER made no tenant changes.' -FailureKind Action -Component 'IntegrationTest') }
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Initializing tenant state engine...'
    Initialize-DERState -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot

    if (-not $TenantIntegrationTest) {
        Write-DERBootstrapMessage -Level WARN -Message 'DER tenant state and the per-tenant mutex are local to this Windows machine. Do not run another DER write-capable session against this same tenant from a different computer at the same time.'
    }

    # Controlled write tests require a completely clean prior-run state. They do
    # not offer recovery/reconcile interaction of their own, so never let Canary
    # or Pilot bypass the same interrupted-run safety gate used by normal builds.
    if ($TenantCanaryTest -or $TenantPilotTest) {
        Write-DERBootstrapMessage -Level STEP -Message 'Verifying that no interrupted prior DER run can affect this controlled write test...'
        $testRecovery = Invoke-DERRecoveryCheck -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot -PackageRoot $script:DERPackageRoot -Mode Stop
        if ($testRecovery -and -not [bool]$testRecovery.ReadyToContinue) {
            throw (New-DERFailureException -Message 'Controlled tenant write testing is blocked until prior DER recovery/reconciliation is complete.' -FailureKind Action -Component 'Recovery')
        }
    }

    if ($TenantCanaryTest) {
        Write-DERBootstrapMessage -Level STEP -Message 'Validating prior no-write proof and starting controlled canary lifecycle...'
        Set-DERRunState -Status Running -Stage 'Canary' -Message 'Controlled canary prerequisite validation started.' | Out-Null
        $canary = Invoke-DERTenantCanary -RunId $script:DERRunId -DiscoverySession $discoverySession -RuntimeRoot $script:DERRuntimeRoot -PackageRoot $script:DERPackageRoot -NoWriteEvidencePath $NoWriteEvidencePath
        if (-not [bool]$canary.Passed) {
            $status=if([bool]$canary.CleanupComplete){'Failed'}else{'RecoveryRequired'}
            Set-DERRunState -Status $status -Stage 'Canary' -Message 'DER controlled canary did not satisfy the full lifecycle contract.' -Data @{evidencePath=$canary.EvidencePath;evidenceSHA256=$canary.EvidenceSHA256;cleanupComplete=$canary.CleanupComplete;graphDelta=$canary.GraphDelta} | Out-Null
            Write-Host ''
            Write-Host 'DER CONTROLLED CANARY RESULT: FAIL' -ForegroundColor Red
            Write-Host ('Evidence: {0}' -f $canary.EvidencePath) -ForegroundColor Yellow
            Write-Host ('Cleanup complete: {0}' -f $canary.CleanupComplete) -ForegroundColor $(if($canary.CleanupComplete){'Green'}else{'Red'})
            Write-Host ''
            exit 2
        }
        Set-DERRunState -Status Completed -Stage 'Canary' -Message 'DER controlled canary create/read-back/rollback/purge completed successfully.' -Data @{evidencePath=$canary.EvidencePath;evidenceSHA256=$canary.EvidenceSHA256;cleanupComplete=$true;graphDelta=$canary.GraphDelta} | Out-Null
        Write-Host ''
        Write-Host 'DER CONTROLLED CANARY RESULT: PASS' -ForegroundColor Green
        Write-Host ('Canary evidence : {0}' -f $canary.EvidencePath) -ForegroundColor Cyan
        Write-Host ('Evidence SHA-256: {0}' -f $canary.EvidenceSHA256) -ForegroundColor Gray
        Write-Host 'One DER-owned object was created, validated, rolled back, and permanently purged.' -ForegroundColor Green
        Write-Host ''
        exit 0
    }

    if ($TenantPilotTest) {
        Write-DERBootstrapMessage -Level STEP -Message 'Validating same-package no-write/canary proof and starting the one-object workload pilot...'
        Set-DERRunState -Status Running -Stage 'Pilot' -Message 'Controlled workload pilot prerequisite validation started.' | Out-Null
        $pilot = Invoke-DERWorkloadPilot -RunId $script:DERRunId -DiscoverySession $discoverySession -RuntimeRoot $script:DERRuntimeRoot -PackageRoot $script:DERPackageRoot -NoWriteEvidencePath $NoWriteEvidencePath -CanaryEvidencePath $CanaryEvidencePath
        if (-not [bool]$pilot.Passed) {
            $status=if([bool]$pilot.CleanupComplete){'Failed'}else{'RecoveryRequired'}
            Set-DERRunState -Status $status -Stage 'Pilot' -Message 'DER workload pilot did not satisfy the full create/validate/rollback/cleanup contract.' -Data @{evidencePath=$pilot.EvidencePath;evidenceSHA256=$pilot.EvidenceSHA256;cleanupComplete=$pilot.CleanupComplete;graphDelta=$pilot.GraphDelta} | Out-Null
            Write-Host ''
            Write-Host 'DER END-TO-END WORKLOAD PILOT RESULT: FAIL' -ForegroundColor Red
            Write-Host ('Evidence: {0}' -f $pilot.EvidencePath) -ForegroundColor Yellow
            Write-Host ('Cleanup complete: {0}' -f $pilot.CleanupComplete) -ForegroundColor $(if($pilot.CleanupComplete){'Green'}else{'Red'})
            Write-Host ''
            exit 2
        }
        Set-DERRunState -Status Completed -Stage 'Pilot' -Message 'DER Groups workload create/read-back/state/rollback/purge pilot completed successfully.' -Data @{evidencePath=$pilot.EvidencePath;evidenceSHA256=$pilot.EvidenceSHA256;cleanupComplete=$true;graphDelta=$pilot.GraphDelta} | Out-Null
        Write-Host ''
        Write-Host 'DER END-TO-END WORKLOAD PILOT RESULT: PASS' -ForegroundColor Green
        Write-Host ('Pilot evidence : {0}' -f $pilot.EvidencePath) -ForegroundColor Cyan
        Write-Host ('Evidence SHA-256: {0}' -f $pilot.EvidenceSHA256) -ForegroundColor Gray
        Write-Host 'The real Groups workload created one DER-owned object; DER validated it, rolled back that exact object, and permanently purged its tombstone.' -ForegroundColor Green
        Write-Host ''
        exit 0
    }

    if (-not $TenantIntegrationTest -and -not $TenantCanaryTest -and -not $TenantPilotTest) {
        if (-not [string]::IsNullOrWhiteSpace($ImportStatePath)) {
            Write-DERBootstrapMessage -Level STEP -Message 'Validating and importing portable DER state...'
            Import-DERPortableState -Path $ImportStatePath -Mode $StateImportMode | Out-Null
        }

        Write-DERBootstrapMessage -Level STEP -Message 'Checking this tenant for interrupted DER runs...'
        $recovery = Invoke-DERRecoveryCheck -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot -PackageRoot $script:DERPackageRoot -Mode $RecoveryMode
        if ($recovery -and -not [bool]$recovery.ReadyToContinue) {
            throw (New-DERFailureException -Message 'DER recovery analysis did not authorize continuation. Review RecoveryDecision.json before retrying.' -FailureKind Action -Component 'Recovery')
        }
    } elseif ($TenantIntegrationTest) {
        Write-DERBootstrapMessage -Level INFO -Message 'No-write integration mode skips portable-state import and recovery replay analysis because the central Graph guard forbids every tenant write.'
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Scanning tenant...'
    Set-DERRunState -Status Running -Stage 'Discovery' -Message 'Scanning tenant.' | Out-Null
    $discovery = Invoke-DERTenantDiscovery -Session $discoverySession -RunId $script:DERRunId

    Write-DERBootstrapMessage -Level STEP -Message 'Creating pre-build configuration snapshot...'
    $snapshot = New-DERPreBuildSnapshot -Discovery $discovery -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot

    Write-DERBootstrapMessage -Level STEP -Message 'Analyzing discovered tenant configuration...'
    $analysis = Invoke-DERTenantAnalysis -Discovery $discovery -Snapshot $snapshot -RunId $script:DERRunId

    Write-DERBootstrapMessage -Level STEP -Message 'Starting discovery-driven questionnaire...'
    $answers = Invoke-DERQuestionnaire -Discovery $discovery -Analysis $analysis -RunId $script:DERRunId

    Write-DERBootstrapMessage -Level STEP -Message 'Applying engineer-approved Preview API safety policy...'
    Set-DERGraphPreviewPolicy -AllowPreviewWrites ([bool]$answers.Safety.AllowPreviewApis) | Out-Null

    Write-DERBootstrapMessage -Level STEP -Message 'Generating build plan...'
    $buildPlan = New-DERBuildPlan -Discovery $discovery -Analysis $analysis -Answers $answers -RunId $script:DERRunId

    $adoption = $null
    if (-not $TenantIntegrationTest) {
        Write-DERBootstrapMessage -Level STEP -Message 'Scanning for explicit customer-object adoption candidates...'
        $adoption = Invoke-DERAdoptionWorkflow -BuildPlan $buildPlan -RunId $script:DERRunId -PackageRoot $script:DERPackageRoot -Mode $AdoptionMode -DecisionPath $AdoptionDecisionPath
    } else {
        Write-DERBootstrapMessage -Level INFO -Message 'Test-tenant integration mode skips adoption decisions; this run is discovery/analysis/questionnaire/dry-run only.'
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Resolving minimum write permissions...'
    $permissionPlan = Resolve-DERRequiredPermissions -BuildPlan $buildPlan -RunId $script:DERRunId

    $writeSession = $null
    if (-not $TenantIntegrationTest -and -not $permissionPlan.ReportOnly -and @($permissionPlan.RequiredScopes).Count -gt 0) {
        Write-DERBootstrapMessage -Level STEP -Message 'Starting tenant-verified write authentication for the approved plan...'
        $writeSession = Connect-DERWriteSession -RunId $script:DERRunId -ExpectedTenantId $buildPlan.TenantId -Scopes $permissionPlan.RequiredScopes -Environment $discoverySession.Environment
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Running full dry run...'
    if ($TenantIntegrationTest) {
        $dryRun = Invoke-DERDryRun -BuildPlan $buildPlan -PermissionPlan $permissionPlan -RunId $script:DERRunId -IntegrationNoWrite -SkipFinalApproval

        Write-DERBootstrapMessage -Level STEP -Message 'Generating cryptographic no-write integration evidence...'
        $integrationEvidence = New-DERNoWriteEvidence -RunId $script:DERRunId -TenantId $buildPlan.TenantId -TenantName $buildPlan.TenantName -BuildPlan $buildPlan -DryRun $dryRun -PermissionPlan $permissionPlan -RuntimeRoot $script:DERRuntimeRoot -PackageRoot $script:DERPackageRoot -OperatorAttestation $integrationAttestation
        New-DERFinalReports -RunId $script:DERRunId -Discovery $discovery -Analysis $analysis -BuildPlan $buildPlan -DryRun $dryRun -PermissionPlan $permissionPlan -Adoption $null -RuntimeRoot $script:DERRuntimeRoot
        if (-not [bool]$integrationEvidence.Passed) {
            Set-DERRunState -Status Failed -Stage 'IntegrationTest' -Message 'DER test-tenant integration evidence failed the zero-write contract.' -Data @{evidencePath=$integrationEvidence.EvidencePath;failedChecks=$integrationEvidence.FailedChecks} | Out-Null
            throw (New-DERFailureException -Message 'DER TEST-TENANT INTEGRATION FAILED. Review DER-NoWriteEvidence.json. The run did not satisfy the zero-write proof contract.' -FailureKind Action -Component 'IntegrationTest')
        }
        Set-DERRunState -Status Completed -Stage 'IntegrationTest' -Message 'DER test-tenant integration completed with verified zero Graph writes.' -Data @{evidencePath=$integrationEvidence.EvidencePath;evidenceSHA256=$integrationEvidence.EvidenceSHA256;transportWriteCount=0} | Out-Null
        Write-Host ''
        Write-Host 'DER TEST-TENANT INTEGRATION RESULT: PASS' -ForegroundColor Green
        Write-Host ('No-write evidence: {0}' -f $integrationEvidence.EvidencePath) -ForegroundColor Cyan
        Write-Host ('Evidence SHA-256 : {0}' -f $integrationEvidence.EvidenceSHA256) -ForegroundColor Gray
        Write-Host 'Graph mutation requests reaching transport: 0' -ForegroundColor Green
        Write-Host 'Write authentication sessions opened: 0' -ForegroundColor Green
        Write-Host ''
        exit 0
    }
    $dryRun = Invoke-DERDryRun -BuildPlan $buildPlan -PermissionPlan $permissionPlan -RunId $script:DERRunId -WriteSession $writeSession

    if (-not $dryRun.ReadyToBuild) {
        Write-DERBootstrapMessage -Level ERROR -EventDomain Action -FailureKind Action -Message 'Dry run contains blocking failures. No tenant build will be started.'
        New-DERFinalReports -RunId $script:DERRunId -Discovery $discovery -Analysis $analysis -BuildPlan $buildPlan -DryRun $dryRun -PermissionPlan $permissionPlan -Adoption $adoption -RuntimeRoot $script:DERRuntimeRoot
        $blockedStateExport=Export-DERPortableState -Path $ExportStatePath
        Write-DERBootstrapMessage -Level INFO -Message ('Portable DER state saved: {0}' -f $blockedStateExport.Path)
        exit 2
    }

    # The Planner/DryRun modules own the exact final approval experience.
    if (-not $dryRun.FinalApprovalGranted) {
        Write-DERBootstrapMessage -Level WARN -Message 'Final BUILD approval was not granted. Tenant remains unchanged.'
        New-DERFinalReports -RunId $script:DERRunId -Discovery $discovery -Analysis $analysis -BuildPlan $buildPlan -DryRun $dryRun -PermissionPlan $permissionPlan -Adoption $adoption -RuntimeRoot $script:DERRuntimeRoot
        $approvalStateExport=Export-DERPortableState -Path $ExportStatePath
        Write-DERBootstrapMessage -Level INFO -Message ('Portable DER state saved: {0}' -f $approvalStateExport.Path)
        exit 0
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Executing approved DER workload modules...'
    Set-DERRunState -Status Running -Stage 'Workloads' -Message 'Executing approved DER workload modules.' | Out-Null
    $workloadResults = New-Object System.Collections.Generic.List[object]
    foreach ($module in ($script:DERModuleCatalog | Where-Object { $_.Area -eq 'Workload' } | Sort-Object Order)) {
        if (-not (Get-Command $module.EntryPoint -ErrorAction SilentlyContinue)) { continue }

        $moduleName=[System.IO.Path]::GetFileNameWithoutExtension([string]$module.File).Replace('DER.','')
        $moduleActionId=New-DERActionId -Component 'MODULE'
        Register-DERTransaction -ActionId $moduleActionId -Phase PRECHECK -Module $moduleName -Message 'Starting workload module precheck. Only the central Graph transport records EXECUTE when a tenant write is actually about to be attempted.' -Data @{entryPoint=$module.EntryPoint} | Out-Null
        try {
            $moduleResult = & $module.EntryPoint -BuildPlan $buildPlan -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot
            if ($null -ne $moduleResult) {
                $workloadResults.Add($moduleResult)
                if ($moduleResult.Status -eq 'CompletedWithFailures') {
                    $failedItems=@($moduleResult.Results|Where-Object{[string]$_.Status -eq 'Failed'})
                    $engineFailures=@($failedItems|Where-Object{$_.PSObject.Properties.Name -contains 'FailureKind' -and [string]$_.FailureKind -eq 'Engine'})
                    $actionFailures=@($failedItems|Where-Object{$_.PSObject.Properties.Name -contains 'FailureKind' -and [string]$_.FailureKind -eq 'Action'})
                    $unclassifiedFailures=[Math]::Max(0,$failedItems.Count-$engineFailures.Count-$actionFailures.Count)
                    # Failure classification is deliberately conservative. ACTION is used only when
                    # the originating code positively tagged the failure as a tenant/request/read-back
                    # problem. An unclassified failure is treated as ENGINE because DER must never blame
                    # Microsoft or tenant state for an exception whose origin it cannot prove.
                    $moduleFailureKind=if($engineFailures.Count -gt 0 -or $unclassifiedFailures -gt 0){'Engine'}else{'Action'}
                    Register-DERTransaction -ActionId $moduleActionId -Phase FAIL -Module $moduleName -Message 'Workload module returned CompletedWithFailures; safe rollback/reconciliation may be required.' -Data @{failureKind=$moduleFailureKind;engineFailures=$engineFailures.Count;actionFailures=$actionFailures.Count;unclassifiedFailures=$unclassifiedFailures} | Out-Null
                    if($moduleFailureKind -eq 'Engine'){
                        if(Get-Command Write-DEREngineFailure -ErrorAction SilentlyContinue){Write-DEREngineFailure -Component $moduleResult.Module -ActionId $moduleActionId -Message 'Workload module completed with one or more DER engine/runtime failures.' -Data $moduleResult}
                    } else {
                        if(Get-Command Write-DERActionFailure -ErrorAction SilentlyContinue){Write-DERActionFailure -Component $moduleResult.Module -ActionId $moduleActionId -Message 'Workload module completed with one or more tenant/action failures.' -Data $moduleResult}
                    }
                    Write-DERBootstrapMessage -Level WARN -Message ("Workload {0} reported failures. DER will attempt safe module-scoped rollback." -f $moduleResult.Module)
                    $rollbackResult = Invoke-DERModuleRollback -Module $moduleResult.Module -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot -Reason 'Automatic rollback after workload failure.'
                    $rollbackFailed=($rollbackResult.Summary.Failed -gt 0 -or $rollbackResult.Summary.ManualRequired -gt 0)
                    $moduleMessage=if($rollbackFailed){"DER workload {0} failed and rollback was incomplete/manual. Dependent workload execution is stopped." -f $moduleResult.Module}else{"DER workload {0} failed. Safe rollback completed; DER stops this run rather than continuing dependent workloads from a questionable state." -f $moduleResult.Module}
                    $moduleException=[System.InvalidOperationException]::new($moduleMessage)
                    $moduleException.Data['DERFailureKind']=$moduleFailureKind
                    $moduleException.Data['DERActionId']=$moduleActionId
                    $moduleException.Data['DERComponent']=$moduleName
                    $moduleException.Data['DEREngineFailureCount']=$engineFailures.Count
                    $moduleException.Data['DERActionFailureCount']=$actionFailures.Count
                    throw $moduleException
                }
                elseif ($moduleResult.Status -eq 'Skipped') {
                    Register-DERTransaction -ActionId $moduleActionId -Phase SKIP -Module $moduleName -Message 'Workload module completed with no tenant write required.' | Out-Null
                }
                else {
                    Register-DERTransaction -ActionId $moduleActionId -Phase COMMIT -Module $moduleName -Message 'Workload module returned a terminal successful result.' | Out-Null
                }
            }
            else {
                Register-DERTransaction -ActionId $moduleActionId -Phase SKIP -Module $moduleName -Message 'Workload module returned no result; no replay checkpoint is needed.' | Out-Null
            }
        }
        catch {
            $workloadError=$_
            $alreadyFailed=@(Get-DERTransactionJournal|Where-Object{[string]$_.actionId-eq$moduleActionId -and [string]$_.phase-eq'FAIL'}).Count -gt 0
            if(-not$alreadyFailed){Register-DERTransaction -ActionId $moduleActionId -Phase FAIL -Module $moduleName -Message $workloadError.Exception.Message | Out-Null}
            if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $workloadError -Component $moduleName -ActionId $moduleActionId -Message ("Workload {0} terminated: {1}" -f $moduleName,$workloadError.Exception.Message)}
            throw $workloadError
        }
    }

    Write-DERBootstrapMessage -Level STEP -Message 'Running post-build validation...'
    $validation = Invoke-DERPostBuildValidation -BuildPlan $buildPlan -RunId $script:DERRunId -RuntimeRoot $script:DERRuntimeRoot

    Write-DERBootstrapMessage -Level STEP -Message 'Generating final DER report set...'
    New-DERFinalReports -RunId $script:DERRunId -Discovery $discovery -Analysis $analysis -BuildPlan $buildPlan -DryRun $dryRun -Validation $validation -PermissionPlan $permissionPlan -Adoption $adoption -RuntimeRoot $script:DERRuntimeRoot

    $finalStatus = if ($validation -and [int]$validation.Summary.Failed -gt 0) { 'CompletedWithWarnings' } else { 'Completed' }
    $stateExport=Export-DERPortableState -Path $ExportStatePath
    Set-DERRunState -Status $finalStatus -Stage 'Completed' -Message 'DER run completed and final reports were generated.' -Data @{validation=$validation.Summary;workloads=@($workloadResults).Count;portableStatePath=$stateExport.Path;portableStateSHA256=$stateExport.PayloadSHA256} | Out-Null
    Write-DERBootstrapMessage -Level OK -Message ('Portable DER state saved: {0}' -f $stateExport.Path)
    Write-DERBootstrapMessage -Level OK -Message 'DER run completed.'
    if(Get-Command Release-DERTenantStateLock -ErrorAction SilentlyContinue){Release-DERTenantStateLock}
    exit 0
}
catch {
    $fatalError=$_
    try {
        if ((Get-Command Write-DERError -ErrorAction SilentlyContinue) -and (Get-Command Test-DERLoggingInitialized -ErrorAction SilentlyContinue) -and (Test-DERLoggingInitialized)) {
            Write-DERError -ErrorRecord $fatalError -Component 'Orchestrator' -Message ('DER terminated before completing the requested workflow: {0}' -f $fatalError.Exception.Message)
        }
    } catch {
        Write-Warning ("DER could not persist the structured fatal error log: {0}" -f $_.Exception.Message)
    }
    try {
        if (Get-Command Set-DERRunState -ErrorAction SilentlyContinue) {
            $recoveryStatus='Failed'
            $recoveryReason='Fatal run error occurred with no unresolved tenant-write timeline.'
            if ((Get-Command Read-DERRecoveryJournalStrict -ErrorAction SilentlyContinue) -and (Get-Command Get-DERRecoveryActionTimelines -ErrorAction SilentlyContinue) -and (Get-Command Get-DERStateContext -ErrorAction SilentlyContinue)) {
                $stateContext=Get-DERStateContext
                if($stateContext){
                    $journalResult=Read-DERRecoveryJournalStrict -Path $stateContext.TransactionJournalPath -ExpectedRunId $script:DERRunId -ExpectedTenantId $stateContext.TenantId
                    if(-not$journalResult.Valid){$recoveryStatus='RecoveryRequired';$recoveryReason='Fatal run error occurred and the transaction journal is invalid/corrupt. Fail-closed recovery is required.'}
                    else{
                        $timelines=@(Get-DERRecoveryActionTimelines -Events @($journalResult.Events))
                        if(@($timelines|Where-Object{$_.RequiresExplicitReconcile -or $_.Invalid}).Count -gt 0){$recoveryStatus='RecoveryRequired';$recoveryReason='Fatal run error occurred with unresolved/uncertain tenant-write activity in the central recovery timeline.'}
                        if((Get-Command Get-DERRecoveryPendingAdoptedPreparations -ErrorAction SilentlyContinue) -and @(Get-DERRecoveryPendingAdoptedPreparations).Count -gt 0){$recoveryStatus='RecoveryRequired';$recoveryReason='Fatal run error left unresolved DER-Adopted rollback preparation in CurrentState. Microsoft-state reconciliation is required.'}
                    }
                }
            } elseif (Get-Command Get-DERTransactionJournal -ErrorAction SilentlyContinue) {
                try{$journal=@(Get-DERTransactionJournal);$possibleWrite=@($journal|Where-Object{[string]$_.phase -in @('EXECUTE','CREATED','UPDATED','ASSIGNED','READBACK','VALIDATE','ROLLBACK')}).Count -gt 0;if($possibleWrite){$recoveryStatus='RecoveryRequired';$recoveryReason='Fatal run error occurred after transaction activity indicated a possible tenant write.'}}
                catch{$recoveryStatus='RecoveryRequired';$recoveryReason='Fatal run error occurred and strict transaction-journal reading failed. Fail-closed recovery is required.'}
            }
            Set-DERRunState -Status $recoveryStatus -Stage 'UnhandledException' -Message $fatalError.Exception.Message -Data @{reason=$recoveryReason} | Out-Null
        }
    } catch {
        Write-Warning ("DER could not persist the fatal run-state/recovery classification: {0}" -f $_.Exception.Message)
    }
    try {
        # Write-DERError above already persisted the authoritative structured fatal
        # event with its original ENGINE/ACTION provenance and Incident ID. These
        # final bootstrap messages are console/bootstrap-file echoes only; mirroring
        # them again would double-count one failure and could lose its provenance.
        Write-DERBootstrapMessage -Level ERROR -Message $fatalError.Exception.Message -SkipStructuredMirror
        if ($fatalError.ScriptStackTrace) {
            Write-DERBootstrapMessage -Level ERROR -Message ('Stack: {0}' -f $fatalError.ScriptStackTrace) -SkipStructuredMirror
        }
    }
    catch {
        Write-Error $_.Exception.Message
    }

    Write-Host ''
    Write-Host 'DER terminated before completing the requested workflow.' -ForegroundColor Red
    if ($script:DERBootstrapLog) {
        Write-Host ('Bootstrap log: {0}' -f $script:DERBootstrapLog) -ForegroundColor Yellow
    }
    Write-Host ''
    if(Get-Command Release-DERTenantStateLock -ErrorAction SilentlyContinue){
        try{Release-DERTenantStateLock}catch{Write-Warning ("DER tenant mutex release after fatal error reported: {0}" -f $_.Exception.Message)}
    }
    exit 1
}
