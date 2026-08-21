# Requires -Version 7.4
# Pester 5.x

<#
.SYNOPSIS
    DER v1 Pester suite — Adoption safety contract.

.DESCRIPTION
    Proves adoption changes DER ownership state only, covers every collision-capable workload, and preserves explicit acknowledgement semantics.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves adoption changes DER ownership state only, covers every collision-capable workload, and preserves explicit acknowledgement semantics.
# Failure significance: A failure here means DER could misclassify or silently take ownership of an existing tenant object.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $ProjectRoot 'Tests\Helpers\DER.TestHarness.psm1') -Force
    Import-DERTestCoreCommands -ProjectRoot $ProjectRoot
    Import-Module (Join-Path $ProjectRoot 'Workloads\DER.Groups.psm1') -Force -Global
    Import-Module (Join-Path $ProjectRoot 'Core\DER.Adoption.psm1') -Force
    $CatalogPath = Join-Path $ProjectRoot 'Definitions\Adoption\DER-AdoptionCatalog.json'
    $Catalog = Get-Content $CatalogPath -Raw | ConvertFrom-Json -Depth 100
    $Ack = 'I understand DER adoption changes local DER ownership state only and does not modify the tenant object during adoption.'
}

Describe 'DER adoption catalog safety contract' {
    It 'covers every workload that currently reports an explicit adoption-required exact-name collision' {
        $required = @('Groups','Enrollment','Autopilot','Compliance','BitLocker','LAPS','Defender','ASR','Firewall','Configuration','NamedLocations','ConditionalAccess','Updates','Drivers','OneDrive','DeliveryOptimization','Analytics')
        foreach ($m in $required) {
            @($Catalog.entries | Where-Object module -eq $m).Count | Should -BeGreaterThan 0 -Because "$m has exact-name adoption behavior"
        }
    }

    It 'declares adoption as ownership-only with no tenant or assignment write' {
        $Catalog.semantics.tenantWriteDuringAdoption | Should -BeFalse
        $Catalog.semantics.assignmentsChangedDuringAdoption | Should -BeFalse
        $Catalog.semantics.partialComparisonRequiresExtraAcknowledgement | Should -BeTrue
    }

    It 'contains no mutating Graph verb in the adoption engine' {
        $text = Get-Content (Join-Path $ProjectRoot 'Core\DER.Adoption.psm1') -Raw
        $text | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
        $text | Should -Match 'OwnershipClass\s+''DER-Adopted'''
        $text | Should -Match 'AdoptionNoTenantWrite=\$true'
    }
}

Describe 'DER explicit adoption decisions' {
    BeforeEach {
        $script:RunRoot = Join-Path $TestDrive 'run'
        New-Item -ItemType Directory -Path $script:RunRoot -Force | Out-Null
        $script:Added = @()
        $script:Transactions = @()
        Mock -ModuleName DER.Adoption Get-DERStateContext { [pscustomobject]@{TenantId='00000000-0000-4000-8000-000000000001';RunRoot=$script:RunRoot} }
        Mock -ModuleName DER.Adoption Get-DERStateObject { $null }
        Mock -ModuleName DER.Adoption Register-DERTransaction { param($ActionId,$Phase,$Module,$DerId,$ObjectId,$Message,$Data); $script:Transactions += [pscustomobject]@{Phase=$Phase;DerId=$DerId;ObjectId=$ObjectId} }
        Mock -ModuleName DER.Adoption Add-DERStateObject { $script:Added += [pscustomobject]$PSBoundParameters }
        Mock -ModuleName DER.Adoption Protect-DERLogData { param($InputObject) $InputObject }
        Mock -ModuleName DER.Adoption New-DERActionId { 'ADOPT-TEST' }
    }

    It 'adopts the exact candidate ObjectId from a valid file decision and performs no tenant write' {
        $planned = New-DERTestPlannedObject -DerId 'DER-GRP-D-010' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName 'SYN - SG - Device - 010 - Pilot' -Metadata ([pscustomobject]@{Membership='Assigned';PrincipalType='Device'})
        $plan = New-DERTestBuildPlan -Objects @($planned)
        $candidate = [pscustomobject]@{id='11111111-1111-4111-8111-111111111111';displayName=$planned.DisplayName;mailEnabled=$false;securityEnabled=$true;groupTypes=@()}
        Mock -ModuleName DER.Adoption Invoke-DERGraphCollectionRequest { @($candidate) }
        Mock -ModuleName DER.Adoption Invoke-DERGraphRequest { param($Method,$Uri,$ApiVersion,$Component,$ActionId); if($Method -ne 'GET'){throw 'mutation attempted'}; return $candidate }
        Mock -ModuleName DER.Adoption Test-DERExpectedSubset { [pscustomobject]@{Success=$true;Differences=@()} }

        $decisionPath = Join-Path $TestDrive 'adopt.json'
        [pscustomobject]@{schemaVersion='1.0';tenantId=$plan.TenantId;decisions=@([pscustomobject]@{derId=$planned.DerId;objectId=$candidate.id;decision='Adopt';acknowledgement=$Ack;allowIncompleteComparison=$false})} |
            ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $decisionPath

        $result = Invoke-DERAdoptionWorkflow -BuildPlan $plan -RunId 'RUN-1' -PackageRoot $ProjectRoot -Mode FileOnly -DecisionPath $decisionPath
        $result.Summary.Adopted | Should -Be 1
        $script:Added.Count | Should -Be 1
        $script:Added[0].OwnershipClass | Should -Be 'DER-Adopted'
        $script:Added[0].ObjectId | Should -Be $candidate.id
        $script:Added[0].Metadata.AdoptionNoTenantWrite | Should -BeTrue
        $script:Added[0].Metadata.PSObject.Properties.Name | Should -Not -Contain 'DeleteUri'
        $script:Added[0].Metadata.PSObject.Properties.Name | Should -Not -Contain 'UpdateUri'
    }

    It 'rejects a decision file that binds the same Microsoft ObjectId to multiple DER IDs' {
        $decisionPath = Join-Path $TestDrive 'duplicate-object.json'
        [pscustomobject]@{schemaVersion='1.0';tenantId='00000000-0000-4000-8000-000000000001';decisions=@(
            [pscustomobject]@{derId='DER-GRP-D-010';objectId='11111111-1111-4111-8111-111111111111';decision='Skip'},
            [pscustomobject]@{derId='DER-GRP-D-020';objectId='11111111-1111-4111-8111-111111111111';decision='Skip'}
        )} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $decisionPath

        { Read-DERAdoptionDecisions -Path $decisionPath -ExpectedTenantId '00000000-0000-4000-8000-000000000001' } | Should -Throw '*bound to more than one DER ID*'
    }

    It 'fails closed when a file decision ObjectId does not match the discovered exact-name candidate' {
        $planned = New-DERTestPlannedObject -DerId 'DER-GRP-D-010' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName 'SYN - SG - Device - 010 - Pilot' -Metadata ([pscustomobject]@{Membership='Assigned';PrincipalType='Device'})
        $plan = New-DERTestBuildPlan -Objects @($planned)
        $candidate = [pscustomobject]@{id='11111111-1111-4111-8111-111111111111';displayName=$planned.DisplayName;mailEnabled=$false;securityEnabled=$true;groupTypes=@()}
        Mock -ModuleName DER.Adoption Invoke-DERGraphCollectionRequest { @($candidate) }
        Mock -ModuleName DER.Adoption Invoke-DERGraphRequest { $candidate }
        Mock -ModuleName DER.Adoption Test-DERExpectedSubset { [pscustomobject]@{Success=$true;Differences=@()} }

        $decisionPath = Join-Path $TestDrive 'wrong-id.json'
        [pscustomobject]@{schemaVersion='1.0';tenantId=$plan.TenantId;decisions=@([pscustomobject]@{derId=$planned.DerId;objectId='22222222-2222-4222-8222-222222222222';decision='Adopt';acknowledgement=$Ack;allowIncompleteComparison=$false})} |
            ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $decisionPath

        { Invoke-DERAdoptionWorkflow -BuildPlan $plan -RunId 'RUN-2' -PackageRoot $ProjectRoot -Mode FileOnly -DecisionPath $decisionPath } | Should -Throw '*ObjectId mismatch*'
        $script:Added.Count | Should -Be 0
    }

    It 'refuses ambiguous same-name objects instead of choosing the first one' {
        $planned = New-DERTestPlannedObject -DerId 'DER-GRP-D-010' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName 'SYN - SG - Device - 010 - Pilot' -Metadata ([pscustomobject]@{Membership='Assigned';PrincipalType='Device'})
        $plan = New-DERTestBuildPlan -Objects @($planned)
        Mock -ModuleName DER.Adoption Invoke-DERGraphCollectionRequest {
            @(
                [pscustomobject]@{id='11111111-1111-4111-8111-111111111111';displayName=$planned.DisplayName},
                [pscustomobject]@{id='22222222-2222-4222-8222-222222222222';displayName=$planned.DisplayName}
            )
        }
        $result = Invoke-DERAdoptionWorkflow -BuildPlan $plan -RunId 'RUN-3' -PackageRoot $ProjectRoot -Mode FileOnly
        $result.Summary.Ambiguous | Should -Be 1
        $result.Summary.Adopted | Should -Be 0
        $script:Added.Count | Should -Be 0
    }

    It 'requires the extra partial-comparison opt-in for template-driven policies' {
        $planned = New-DERTestPlannedObject -DerId 'DER-BL-010' -Module 'BitLocker' -ObjectType 'EndpointSecurityPolicy' -DisplayName 'SYN - BL - 010 - Windows BitLocker'
        $plan = New-DERTestBuildPlan -Objects @($planned)
        $candidate = [pscustomobject]@{id='33333333-3333-4333-8333-333333333333';name=$planned.DisplayName;platforms='windows10';technologies='mdm'}
        Mock -ModuleName DER.Adoption Invoke-DERGraphCollectionRequest { @($candidate) }
        Mock -ModuleName DER.Adoption Invoke-DERGraphRequest { $candidate }
        Mock -ModuleName DER.Adoption Test-DERExpectedSubset { [pscustomobject]@{Success=$true;Differences=@()} }

        $decisionPath = Join-Path $TestDrive 'partial.json'
        [pscustomobject]@{schemaVersion='1.0';tenantId=$plan.TenantId;decisions=@([pscustomobject]@{derId=$planned.DerId;objectId=$candidate.id;decision='Adopt';acknowledgement=$Ack;allowIncompleteComparison=$false})} |
            ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $decisionPath

        { Invoke-DERAdoptionWorkflow -BuildPlan $plan -RunId 'RUN-4' -PackageRoot $ProjectRoot -Mode FileOnly -DecisionPath $decisionPath } | Should -Throw '*allowIncompleteComparison=true*'
        $script:Added.Count | Should -Be 0
    }
}
