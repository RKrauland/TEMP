# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Hard safety invariant contract.

.DESCRIPTION
    Proves workloads cannot bypass central Graph transport and that planner-level customer-owned/enforcement safety promises remain true.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves workloads cannot bypass central Graph transport and that planner-level customer-owned/enforcement safety promises remain true.
# Failure significance: A failure here is a safety-boundary failure, not a cosmetic test failure.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $WorkloadRoot = Join-Path $ProjectRoot 'Workloads'
    $PlannerText = Get-Content (Join-Path $ProjectRoot 'Core\DER.Planner.psm1') -Raw
    $DryRunText = Get-Content (Join-Path $ProjectRoot 'Core\DER.DryRun.psm1') -Raw
    $Catalog = Get-Content (Join-Path $ProjectRoot 'Definitions\Compatibility\DER-CompatibilityCatalog.json') -Raw | ConvertFrom-Json -Depth 100
    $Baseline = Get-Content (Join-Path $ProjectRoot 'Definitions\Baselines\1.0.0\DER-Baseline.json') -Raw | ConvertFrom-Json -Depth 100
}
Describe 'DER hard safety invariants' {
    It 'forbids workload bypass of the central Graph engine' {
        foreach ($f in Get-ChildItem $WorkloadRoot -Filter '*.psm1') {
            $t = Get-Content $f.FullName -Raw
            $t | Should -Not -Match '\bInvoke-MgGraphRequest\b'
            $t | Should -Not -Match '\bInvoke-RestMethod\b'
            $t | Should -Not -Match '\bConnect-MgGraph\b'
        }
    }
    It 'keeps customer-owned writes and production enforcement at zero in the planner' {
        $PlannerText | Should -Match 'CustomerOwnedObjectsModified=0'
        $PlannerText | Should -Match 'CustomerOwnedObjectsDeleted=0'
        $PlannerText | Should -Match 'ProductionEnforcement=0'
    }
    It 'plans Conditional Access in Report-only state' { $PlannerText | Should -Match "Module 'ConditionalAccess'.*SafeState 'Report-only'" }
    It 'blocks non-report-only Conditional Access in dry run' { $DryRunText | Should -Match "SAFE-004" }
    It 'asserts Microsoft object ID as ownership authority in the baseline' { $Baseline.defaults.ownership.microsoftObjectIdIsAuthority | Should -BeTrue }
    It 'asserts unowned objects are never automatically modified' { $Baseline.defaults.ownership.neverModifyUnowned | Should -BeTrue }
    It 'centrally enforces the Preview API gate and compatibility catalog' {
        $graph = Get-Content (Join-Path $ProjectRoot 'Core\DER.Graph.psm1') -Raw
        $parent = Get-Content (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
        $graph | Should -Match 'Assert-DERGraphWriteCompatibility'
        $graph | Should -Match 'Preview API writes are disabled'
        $parent | Should -Match 'Set-DERGraphPreviewPolicy'
    }
    It 'fails closed on portable-state tenant, integrity, and ownership remap checks' {
        $state = Get-Content (Join-Path $ProjectRoot 'Core\DER.State.psm1') -Raw
        $state | Should -Match 'does not match authenticated tenant'
        $state | Should -Match 'SHA-256 integrity check failed'
        $state | Should -Match 'State merge conflict: DerId'
        $state | Should -Match 'ownership class changed'
        $state | Should -Match 'New-DERStateImportBackup'
    }
}
Describe 'DER Safe Preview catalog' {
    It 'has at least one allowlisted beta-write path for every workload that performs beta writes' {
        $betaWriteModules = @()
        foreach ($f in Get-ChildItem $WorkloadRoot -Filter '*.psm1') {
            $t = Get-Content $f.FullName -Raw
            if ($t -match "(?s)Invoke-DERGraphRequest.{0,300}-Method\s+(POST|PATCH|PUT|DELETE).{0,300}-ApiVersion\s+(?:beta|'beta'|`"beta`")") {
                $betaWriteModules += ($f.BaseName -replace '^DER\.','')
            }
        }
        $betaWriteModules = @($betaWriteModules | Sort-Object -Unique)
        foreach ($m in $betaWriteModules) {
            @($Catalog.entries | Where-Object { $_.module -eq $m -and $_.apiVersion -eq 'beta' -and $_.previewWriteAllowed }).Count | Should -BeGreaterThan 0 -Because "beta-write module $m requires explicit catalog coverage"
        }
    }
    It 'never marks PasswordProtection or LoggingIntegration as automatic preview writers' {
        @($Catalog.entries | Where-Object { $_.module -in @('PasswordProtection','LoggingIntegration') -and $_.previewWriteAllowed }).Count | Should -Be 0
    }
}

Describe 'DER customer-object adoption invariants' {
    It 'keeps adoption ownership-only and prohibits mutating Graph verbs' {
        $adoption = Get-Content (Join-Path $ProjectRoot 'Core\DER.Adoption.psm1') -Raw
        $adoption | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
        $adoption | Should -Match "OwnershipClass\s+'DER-Adopted'"
        $adoption | Should -Match 'AdoptionNoTenantWrite=\$true'
        $adoption | Should -Match 'AdoptionAssignmentsChanged=\$false'
    }
    It 'requires exact ObjectId binding and stronger acknowledgement for partial comparisons' {
        $adoption = Get-Content (Join-Path $ProjectRoot 'Core\DER.Adoption.psm1') -Raw
        $adoption | Should -Match 'Adoption decision ObjectId mismatch'
        $adoption | Should -Match 'allowIncompleteComparison=true'
        $adoption | Should -Match 'ADOPT INCOMPLETE'
    }
    It 'does not treat an ownership-only adoption as something to automatically roll back' {
        $rollback = Get-Content (Join-Path $ProjectRoot 'Core\DER.Rollback.psm1') -Raw
        $rollback | Should -Match 'Ownership-only adoption made no tenant change'
    }
}
