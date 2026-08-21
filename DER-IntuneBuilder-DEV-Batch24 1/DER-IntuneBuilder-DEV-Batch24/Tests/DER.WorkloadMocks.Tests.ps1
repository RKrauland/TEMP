# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Mocked workload behavior contract.

.DESCRIPTION
    Proves representative workloads make the correct create/skip/update decisions when state and Graph observations vary.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves representative workloads make the correct create/skip/update decisions when state and Graph observations vary.
# Failure significance: A failure here means orchestration decisions may be wrong even though individual helper functions appear valid.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $PSScriptRoot 'Helpers\DER.TestHarness.psm1') -Force -Global
    Import-DERTestCoreCommands -ProjectRoot $ProjectRoot
    foreach ($name in @('Groups','EntraDevice','ConditionalAccess','Compliance','AuthenticationMethods')) {
        Import-Module (Join-Path $ProjectRoot ("Workloads\DER.{0}.psm1" -f $name)) -Force
    }
}

Describe 'DER Groups mocked workload behavior' {
    BeforeEach {
        Mock Get-DERStateContext -ModuleName 'DER.Groups' { $null }
        Mock Write-DERLog -ModuleName 'DER.Groups' {}
        Mock New-DERActionId -ModuleName 'DER.Groups' { 'GROUP-TEST-001' }
        Mock Get-DERStateObject -ModuleName 'DER.Groups' { $null }
        Mock Register-DERTransaction -ModuleName 'DER.Groups' { [pscustomobject]@{} }
        Mock Add-DERStateObject -ModuleName 'DER.Groups' { [pscustomobject]@{} }
        Mock Update-DERStateObject -ModuleName 'DER.Groups' { [pscustomobject]@{} }
        Mock Test-DERExpectedSubset -ModuleName 'DER.Groups' { [pscustomobject]@{Success=$true} }
    }

    It 'skips an exact-name customer-owned collision and never POSTs a group' {
        Mock Invoke-DERGraphRequest -ModuleName 'DER.Groups' {
            param($Method,$Uri,$ApiVersion,$Body,$Component,$ActionId)
            if ($Method -eq 'GET' -and $Uri -like 'groups?*') { return Get-DERTestFixture -Name 'groups.customerCollision' }
            throw "Unexpected Graph call in collision test: $Method $Uri"
        }
        $p = New-DERTestPlannedObject -DerId 'DER-GRP-D-010' -Module Groups -ObjectType SecurityGroup -DisplayName 'DER - GRP - 010 - Pilot Devices' -Metadata ([pscustomobject]@{PrincipalType='Device';Membership='Assigned'})
        $out = Invoke-DERGroupsModule -BuildPlan (New-DERTestBuildPlan -Objects @($p)) -RunId 'RUN-TEST' -RuntimeRoot $TestDrive
        $out.Summary.Skipped | Should -Be 1
        $out.Summary.Created | Should -Be 0
        $out.Results[0].Message | Should -Match 'customer-owned'
        Should -Invoke -CommandName Invoke-DERGraphRequest -ModuleName 'DER.Groups' -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'creates only after the ownership/name precheck and records DER-Owned state' {
        Mock Invoke-DERGraphRequest -ModuleName 'DER.Groups' {
            param($Method,$Uri,$ApiVersion,$Body,$Component,$ActionId)
            if ($Method -eq 'GET' -and $Uri -like 'groups?*') { return [pscustomobject]@{value=@()} }
            if ($Method -eq 'POST' -and $Uri -eq 'groups') { return Get-DERTestFixture -Name 'groups.created' }
            if ($Method -eq 'GET' -and $Uri -like 'groups/00000000-0000-4000-8000-000000000102*') { return Get-DERTestFixture -Name 'groups.created' }
            throw "Unexpected Graph call in group create test: $Method $Uri"
        }
        $p = New-DERTestPlannedObject -DerId 'DER-GRP-D-010' -Module Groups -ObjectType SecurityGroup -DisplayName 'DER - GRP - 010 - Pilot Devices' -Metadata ([pscustomobject]@{PrincipalType='Device';Membership='Assigned'})
        $out = Invoke-DERGroupsModule -BuildPlan (New-DERTestBuildPlan -Objects @($p)) -RunId 'RUN-TEST' -RuntimeRoot $TestDrive
        $out.Summary.Created | Should -Be 1
        Should -Invoke -CommandName Invoke-DERGraphRequest -ModuleName 'DER.Groups' -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Uri -eq 'groups' }
        Should -Invoke -CommandName Add-DERStateObject -ModuleName 'DER.Groups' -Times 1 -ParameterFilter { $OwnershipClass -eq 'DER-Owned' -and $DerId -eq 'DER-GRP-D-010' }
    }
}

Describe 'DER tenant-wide mocked preservation behavior' {
    It 'preserves deviceRegistrationPolicy in an existing tenant unless Custom explicitly owns the change' {
        Mock Get-DERStateContext -ModuleName 'DER.EntraDevice' { $null }
        Mock Write-DERLog -ModuleName 'DER.EntraDevice' {}
        Mock New-DERActionId -ModuleName 'DER.EntraDevice' { 'ENTRADEV-TEST-001' }
        Mock Register-DERTransaction -ModuleName 'DER.EntraDevice' { [pscustomobject]@{} }
        Mock Invoke-DERGraphRequest -ModuleName 'DER.EntraDevice' { return Get-DERTestFixture -Name 'deviceRegistrationPolicy.current' }
        $p = New-DERTestPlannedObject -DerId 'DER-ENTRA-010' -Module EntraDevice -ObjectType DeviceRegistrationPolicy -DisplayName 'Microsoft Entra Device Registration Policy'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $plan.EnvironmentClassification = 'ExistingTenant'
        $plan.Profile = 'Standard'
        $out = Invoke-DEREntraDeviceModule -BuildPlan $plan -RunId 'RUN-TEST' -RuntimeRoot $TestDrive
        $out.Summary.Skipped | Should -Be 1
        $out.Results[0].Message | Should -Match 'preserved'
        Should -Invoke -CommandName Invoke-DERGraphRequest -ModuleName 'DER.EntraDevice' -Times 0 -ParameterFilter { $Method -eq 'PUT' }
    }
}

Describe 'DER Conditional Access mocked workload behavior' {
    It 'POSTs only a Report-only policy and validates the same safety state on read-back' {
        Mock Get-DERStateContext -ModuleName 'DER.ConditionalAccess' { $null }
        Mock Write-DERLog -ModuleName 'DER.ConditionalAccess' {}
        Mock New-DERActionId -ModuleName 'DER.ConditionalAccess' { 'CAP-TEST-001' }
        Mock Get-DERStateObject -ModuleName 'DER.ConditionalAccess' {
            param($DerId)
            if ($DerId -eq 'DER-GRP-U-030') { return [pscustomobject]@{ObjectId='00000000-0000-4000-8000-000000000299'} }
            return $null
        }
        Mock Register-DERTransaction -ModuleName 'DER.ConditionalAccess' { [pscustomobject]@{} }
        Mock Add-DERStateObject -ModuleName 'DER.ConditionalAccess' { [pscustomobject]@{} }
        Mock Update-DERStateObject -ModuleName 'DER.ConditionalAccess' { [pscustomobject]@{} }
        Mock Invoke-DERGraphCollectionRequest -ModuleName 'DER.ConditionalAccess' {
            param($Uri,$ApiVersion,$Component,$ActionId)
            if ($Uri -like 'roleManagement/directory/roleDefinitions*') { return @((Get-DERTestFixture -Name 'conditionalAccess.roleDefinitions').value) }
            if ($Uri -eq 'policies/authenticationStrengthPolicies') { return @((Get-DERTestFixture -Name 'conditionalAccess.authenticationStrengths').value) }
            if ($Uri -eq 'identity/conditionalAccess/policies') { return @() }
            throw "Unexpected collection call: $Uri"
        }
        Mock Invoke-DERGraphRequest -ModuleName 'DER.ConditionalAccess' {
            param($Method,$Uri,$ApiVersion,$Body,$Component,$ActionId)
            if ($Method -eq 'POST' -and $Uri -eq 'identity/conditionalAccess/policies') {
                if ([string]$Body.state -ne 'enabledForReportingButNotEnforced') { throw 'Test caught attempted enforced CA POST.' }
                return Get-DERTestFixture -Name 'conditionalAccess.created.reportOnly'
            }
            if ($Method -eq 'GET' -and $Uri -like 'identity/conditionalAccess/policies/*') { return Get-DERTestFixture -Name 'conditionalAccess.created.reportOnly' }
            throw "Unexpected CA Graph call: $Method $Uri"
        }
        $p = New-DERTestPlannedObject -DerId 'DER-CAP-020' -Module ConditionalAccess -ObjectType ConditionalAccessPolicy -DisplayName 'DER - CAP - 020 - Require MFA'
        $out = Invoke-DERConditionalAccessModule -BuildPlan (New-DERTestBuildPlan -Objects @($p)) -RunId 'RUN-TEST' -RuntimeRoot $TestDrive
        $out.Summary.Created | Should -Be 1
        Should -Invoke -CommandName Invoke-DERGraphRequest -ModuleName 'DER.ConditionalAccess' -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Body.state -eq 'enabledForReportingButNotEnforced' }
        Should -Invoke -CommandName Add-DERStateObject -ModuleName 'DER.ConditionalAccess' -Times 1 -ParameterFilter { $OwnershipClass -eq 'DER-Owned' }
    }
}

Describe 'DER preview and built-in method mocked gates' {
    It 'does not touch Graph when complete compliance requires Preview and Preview is disabled' {
        Mock Get-DERStateContext -ModuleName 'DER.Compliance' { $null }
        Mock Invoke-DERGraphRequest -ModuleName 'DER.Compliance' { throw 'Graph must not be called.' }
        Mock Invoke-DERGraphCollectionRequest -ModuleName 'DER.Compliance' { throw 'Graph must not be called.' }
        $p = New-DERTestPlannedObject -DerId 'DER-COMP-010' -Module Compliance -ObjectType CompliancePolicy -DisplayName 'DER - COMP - 010'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $plan.Answers.Safety.AllowPreviewApis = $false
        $out = Invoke-DERComplianceModule -BuildPlan $plan -RunId 'RUN-TEST' -RuntimeRoot $TestDrive
        $out.Summary.Skipped | Should -Be 1
        Should -Invoke -CommandName Invoke-DERGraphRequest -ModuleName 'DER.Compliance' -Times 0
        Should -Invoke -CommandName Invoke-DERGraphCollectionRequest -ModuleName 'DER.Compliance' -Times 0
    }

    It 'preserves an already-enabled Microsoft Authenticator configuration and does not PATCH it' {
        Mock Get-DERStateContext -ModuleName 'DER.AuthenticationMethods' { $null }
        Mock Invoke-DERGraphRequest -ModuleName 'DER.AuthenticationMethods' { return Get-DERTestFixture -Name 'authMethods.authenticator.enabled' }
        Mock Register-DERTransaction -ModuleName 'DER.AuthenticationMethods' { [pscustomobject]@{} }
        $p = New-DERTestPlannedObject -DerId 'DER-AUTH-010' -Module AuthenticationMethods -ObjectType AuthenticationMethodsPolicy -DisplayName 'Authentication Methods'
        $plan = New-DERTestBuildPlan -Objects @($p)
        $plan.Answers.Identity.EnableFIDO2 = $false
        $plan.Answers.Identity.EnableTAP = $false
        $out = Invoke-DERAuthenticationMethodsModule -BuildPlan $plan -RunId 'RUN-TEST' -RuntimeRoot $TestDrive
        $out.Summary.Existing | Should -Be 1
        Should -Invoke -CommandName Invoke-DERGraphRequest -ModuleName 'DER.AuthenticationMethods' -Times 0 -ParameterFilter { $Method -eq 'PATCH' }
    }
}
