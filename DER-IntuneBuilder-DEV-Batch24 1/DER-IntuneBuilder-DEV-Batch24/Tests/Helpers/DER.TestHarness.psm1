<#
.SYNOPSIS
    DER v1 deterministic test harness.

.DESCRIPTION
    Provides tenant-free fixtures and helper behavior used by Pester. It must remain deterministic, must not authenticate to Microsoft Graph, and must not hide the production code path a test claims to exercise.

.NOTES
    Keep test isolation, boundary placement, and failure semantics explicit when
    editing this helper.
#>

#
# Test intent: Provide deterministic synthetic plans, state, and command shims shared by Pester suites without creating a real tenant dependency.
# Static inspection of this file is not an executed Pester result.


# Requires -Version 7.4
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DERTestProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Import-DERTestCoreCommands {
    param([string]$ProjectRoot=$script:DERTestProjectRoot)
    foreach ($relative in @(
        'Core\DER.Graph.psm1',
        'Core\DER.Logging.psm1',
        'Core\DER.State.psm1',
        'Core\DER.Validation.psm1'
    )) {
        Import-Module (Join-Path $ProjectRoot $relative) -Force -Global -ErrorAction Stop
    }
}

function Get-DERTestFixture {
    param(
        [string]$ProjectRoot=$script:DERTestProjectRoot,
        [Parameter(Mandatory)][string]$Name
    )
    $catalogPath = Join-Path $ProjectRoot 'Tests\Fixtures\DER-GraphFixtureCatalog.json'
    $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -Depth 100
    $entry = @($catalog.fixtures | Where-Object name -eq $Name | Select-Object -First 1)
    if (-not $entry) { throw "Unknown DER test fixture '$Name'." }
    $path = Join-Path (Join-Path $ProjectRoot 'Tests\Fixtures') ([string]$entry.path)
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 100
}

function New-DERTestPlannedObject {
    param(
        [Parameter(Mandatory)][string]$DerId,
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$DisplayName,
        $Metadata = $null
    )
    if ($null -eq $Metadata) { $Metadata = [pscustomobject]@{} }
    return [pscustomobject][ordered]@{
        DerId=$DerId;Module=$Module;ObjectType=$ObjectType;DisplayName=$DisplayName
        Enabled=$true;Action='Create';SafeState='Pilot/test only';Metadata=$Metadata
    }
}

function New-DERTestBuildPlan {
    param([object[]]$Objects=@())
    $answers=[pscustomobject][ordered]@{
        Safety=[pscustomobject]@{AllowPreviewApis=$true;ChangeControl='Approved build'}
        Enrollment=[pscustomobject]@{
            AutopilotGroupTag='DER-AUTOPILOT';ComputerNameTemplate='DER-%RAND:7%';ESPAllowContinueOnFailure=$false
            ESPTimeoutMinutes=60;EndUserAccountType='Standard User';ExistingDeviceAutopilotAction='Do not convert existing devices'
            HidePrivacyOobe=$true;PreProvisioning=$true;BlockNewWindows10=$true;CorporateWindowsOnly=$true
            MaxEnrollmentsPerUser=5;GlobalAdminsLocalAdmins=$false
        }
        Security=[pscustomobject]@{
            RequireBitLocker=$true;RequireSecureBoot=$true;RequireCodeIntegrity=$true;RequireFirewallCompliance=$true
            RequireTPM=$true;PrimaryAV='Microsoft Defender';EncryptFixedDrives=$true;CreateTamperProtection=$true
            DeviceLockMinutes=15;AllowLocalFirewallRuleMerge=$false;LAPSPasswordLength=20;LAPSPostAuthRotation=8;LAPSRotationDays=30
        }
        Identity=[pscustomobject]@{
            EnableAuthenticator=$true;EnableFIDO2=$true;EnableTAP=$true;EnableSMSFallback=$false;EnableSoftwareOATH=$false;EnableVoice=$false
            PartnerTenants=@();PIMActivationHours=4;PIMRequireApproval=$false;EnableCustomPasswordProtection=$false
        }
        Updates=[pscustomobject]@{
            PilotUpdateDeferralDays=2;ProductionUpdateDeferralDays=7;FeatureDeadlineDays=7;UpdateDeadlineDays=3;UpdateGraceDays=2
            ManageDrivers=$true;TargetFeatureUpdateVersion='Windows 11, version 25H2';PreserveAutopatch=$false
            DriverPilotDelayDays=3;DriverProductionDelayDays=14
        }
        UserData=[pscustomobject]@{FilesOnDemand=$true;KnownFolderMove=$true;SilentSignIn=$true;SyncHealth=$true}
        Operations=[pscustomobject]@{
            DeviceCleanupDays=90;SupportName='Example IT';SupportEmail='helpdesk@example.invalid';SupportPhone='555-0100'
            SupportUrl='https://support.example.invalid';SIEM='None'
        }
    }
    return [pscustomobject][ordered]@{
        PlanVersion='1.0';BaselineVersion='1.0.0';TenantId='00000000-0000-4000-8000-000000000001';TenantName='Synthetic Test Tenant'
        EnvironmentClassification='NewOrMostlyEmpty';Profile='Custom';Answers=$answers;Safety=[pscustomobject]@{ChangeControl='Approved build'}
        Objects=@($Objects);ManualActions=@();Modules=@();Summary=[pscustomobject]@{}
    }
}

Export-ModuleMember -Function @('Import-DERTestCoreCommands','Get-DERTestFixture','New-DERTestPlannedObject','New-DERTestBuildPlan')
