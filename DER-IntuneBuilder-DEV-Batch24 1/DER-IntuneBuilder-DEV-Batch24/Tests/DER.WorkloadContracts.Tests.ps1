# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Workload body contract.

.DESCRIPTION
    Proves representative workload bodies retain required security settings, assignments, and baseline semantics before transport is involved.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves representative workload bodies retain required security settings, assignments, and baseline semantics before transport is involved.
# Failure significance: A failure here means a workload may construct the wrong tenant configuration even if Graph transport succeeds.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $PSScriptRoot 'Helpers\DER.TestHarness.psm1') -Force -Global
    Import-DERTestCoreCommands -ProjectRoot $ProjectRoot
    foreach ($name in @('Groups','EntraDevice','Enrollment','Autopilot','Compliance','ConditionalAccess','NamedLocations','DeliveryOptimization','Drivers','PIM','TenantSettings','Updates')) {
        Import-Module (Join-Path $ProjectRoot ("Workloads\DER.{0}.psm1" -f $name)) -Force
    }
}

Describe 'DER workload body safety contracts' {
    It 'builds corporate Windows enrollment restrictions without blocking Windows itself' {
        $p = New-DERTestPlannedObject -DerId 'DER-ENR-010' -Module Enrollment -ObjectType EnrollmentRestriction -DisplayName 'DER - ENR - 010'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $body = New-DERWindowsRestrictionBody -BuildPlan $plan -Planned $p
        $body.windowsRestriction.platformBlocked | Should -BeFalse
        $body.windowsRestriction.personalDeviceEnrollmentBlocked | Should -BeTrue
        $body.windowsRestriction.osMinimumVersion | Should -Be '10.0.22000.0'
    }

    It 'keeps Autopilot user-driven deployment standard-user and blocks use-before-complete' {
        $p = New-DERTestPlannedObject -DerId 'DER-AUTO-010' -Module Autopilot -ObjectType AutopilotProfile -DisplayName 'DER - AUTO - 010'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $body = New-DERAutopilotProfileBody -BuildPlan $plan -Planned $p
        $body.outOfBoxExperienceSetting.userType | Should -Be 'standard'
        $body.outOfBoxExperienceSetting.deviceUsageType | Should -Be 'singleUser'
        $body.enrollmentStatusScreenSettings.allowDeviceUseBeforeProfileAndAppInstallComplete | Should -BeFalse
        $body.deviceNameTemplate | Should -Be 'DER-%RAND:7%'
    }

    It 'keeps Windows compliance security requirements enabled for the Defender profile' {
        $p = New-DERTestPlannedObject -DerId 'DER-COMP-010' -Module Compliance -ObjectType CompliancePolicy -DisplayName 'DER - COMP - 010'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $body = New-DERWindowsComplianceBody -BuildPlan $plan -Planned $p
        $body.bitLockerEnabled | Should -BeTrue
        $body.secureBootEnabled | Should -BeTrue
        $body.tpmRequired | Should -BeTrue
        $body.activeFirewallRequired | Should -BeTrue
        $body.defenderEnabled | Should -BeTrue
    }

    It 'creates every Conditional Access body in Report-only state and excludes emergency access' {
        $plan = New-DERTestBuildPlan
        foreach ($id in @('DER-CAP-010','DER-CAP-020','DER-CAP-030','DER-CAP-040','DER-CAP-050','DER-CAP-060','DER-CAP-070','DER-CAP-080','DER-CAP-090','DER-CAP-100','DER-CAP-110','DER-CAP-120')) {
            $p = New-DERTestPlannedObject -DerId $id -Module ConditionalAccess -ObjectType ConditionalAccessPolicy -DisplayName $id
            $body = New-DERConditionalAccessBody -PlannedObject $p -BuildPlan $plan -EmergencyGroupId '00000000-0000-4000-8000-000000000299' -PrivilegedRoleIds @('00000000-0000-4000-8000-000000000201') -PhishingStrengthId '00000000-0000-4000-8000-000000000210' -ApprovedCountryLocationId '00000000-0000-4000-8000-000000000601' -TravelGroupId '00000000-0000-4000-8000-000000000298'
            $body.state | Should -Be 'enabledForReportingButNotEnforced'
            $body.conditions.users.excludeGroups | Should -Contain '00000000-0000-4000-8000-000000000299'
        }
    }

    It 'requires password change plus MFA with AND for high-risk-user CA' {
        $p = New-DERTestPlannedObject -DerId 'DER-CAP-100' -Module ConditionalAccess -ObjectType ConditionalAccessPolicy -DisplayName 'DER - CAP - 100'
        $body = New-DERConditionalAccessBody -PlannedObject $p -BuildPlan (New-DERTestBuildPlan) -EmergencyGroupId '00000000-0000-4000-8000-000000000299'
        $body.grantControls.operator | Should -Be 'AND'
        $body.grantControls.builtInControls | Should -Contain 'mfa'
        $body.grantControls.builtInControls | Should -Contain 'passwordChange'
    }

    It 'keeps Delivery Optimization on NAT/subnet peering with VPN peer caching disabled' {
        $p = New-DERTestPlannedObject -DerId 'DER-DO-010' -Module DeliveryOptimization -ObjectType DeliveryOptimizationConfiguration -DisplayName 'DER - DO - 010'
        $body = New-DERDeliveryOptimizationBody -Planned $p
        $body.deliveryOptimizationMode | Should -Be 'httpWithPeeringNat'
        $body.restrictPeerSelectionBy | Should -Be 'subnetMask'
        $body.vpnPeerCaching | Should -Be 'disabled'
    }

    It 'stages driver deferrals differently for Pilot and Production' {
        $plan = New-DERTestBuildPlan
        $pilot = New-DERTestPlannedObject -DerId 'DER-WU-030' -Module Drivers -ObjectType DriverUpdatePolicy -DisplayName 'Pilot Drivers'
        $prod = New-DERTestPlannedObject -DerId 'DER-WU-040' -Module Drivers -ObjectType DriverUpdatePolicy -DisplayName 'Production Drivers'
        (New-DERDriverProfileBody -BuildPlan $plan -Planned $pilot).deploymentDeferralInDays | Should -Be 3
        (New-DERDriverProfileBody -BuildPlan $plan -Planned $prod).deploymentDeferralInDays | Should -Be 14
    }

    It 'keeps update rings unpaused and production more deferred than pilot' {
        $plan = New-DERTestBuildPlan
        $pilot = New-DERTestPlannedObject -DerId 'DER-WU-010' -Module Updates -ObjectType UpdateRing -DisplayName 'Pilot Updates'
        $prod = New-DERTestPlannedObject -DerId 'DER-WU-020' -Module Updates -ObjectType UpdateRing -DisplayName 'Production Updates'
        $a = New-DERUpdateRingBody -BuildPlan $plan -Planned $pilot
        $b = New-DERUpdateRingBody -BuildPlan $plan -Planned $prod
        $a.qualityUpdatesPaused | Should -BeFalse
        $b.qualityUpdatesPaused | Should -BeFalse
        $b.qualityUpdatesDeferralPeriodInDays | Should -BeGreaterThan $a.qualityUpdatesDeferralPeriodInDays
        (New-DERFeatureUpdateBody -BuildPlan $plan -Planned $pilot).featureUpdateVersion | Should -Be 'Windows 11, version 25H2'
    }

    It 'refuses unsafe cleanup ages and only targets Windows records' {
        $p = New-DERTestPlannedObject -DerId 'DER-TENANT-010' -Module TenantSettings -ObjectType ManagedDeviceCleanupRule -DisplayName 'Cleanup'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $body = New-DERDeviceCleanupRuleBody -BuildPlan $plan -Planned $p
        $body.deviceCleanupRulePlatformType | Should -Be 'windows'
        $plan.Answers.Operations.DeviceCleanupDays = 10
        { New-DERDeviceCleanupRuleBody -BuildPlan $plan -Planned $p } | Should -Throw '*between 30 and 270*'
    }

    It 'preserves unrelated built-in device registration policy properties during copy' {
        $current = Get-DERTestFixture -ProjectRoot $ProjectRoot -Name 'deviceRegistrationPolicy.current'
        $copy = Copy-DERDeviceRegistrationBody -Current $current
        $copy.userDeviceQuota | Should -Be 50
        $copy.multiFactorAuthConfiguration | Should -Be 'notRequired'
        $copy.azureADRegistration.allowedToRegister.'@odata.type' | Should -Be '#microsoft.graph.allDeviceRegistrationMembership'
        $copy.localAdminPassword.isEnabled | Should -BeFalse
    }

    It 'uses documentation-safe CIDR conversion and never trusts IP locations by default' {
        (ConvertTo-DERCidrRange '203.0.113.8').cidrAddress | Should -Be '203.0.113.8/32'
        $p = New-DERTestPlannedObject -DerId 'DER-LOC-SITE-001' -Module NamedLocations -ObjectType NamedLocation -DisplayName 'Example Site' -Metadata ([pscustomobject]@{IPv4=@('203.0.113.0/24');Trusted=$false})
        $body = New-DERNamedLocationBody -PlannedObject $p
        $body.isTrusted | Should -BeFalse
        $body.ipRanges[0].cidrAddress | Should -Be '203.0.113.0/24'
    }

    It 'requires justification and MFA in the PIM enablement rule without dropping existing rules' {
        $body = New-DERPIMEnablementBody -ExistingRules @('Approval')
        $body.enabledRules | Should -Contain 'Approval'
        $body.enabledRules | Should -Contain 'Justification'
        $body.enabledRules | Should -Contain 'MultiFactorAuthentication'
        (New-DERPIMExpirationBody -Hours 4).maximumDuration | Should -Be 'PT4H'
    }
}
