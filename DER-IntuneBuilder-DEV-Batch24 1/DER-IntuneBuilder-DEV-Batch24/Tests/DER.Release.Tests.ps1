# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — v1 release/freeze contract.

.DESCRIPTION
    Proves the v1 feature freeze and production-release gates remain explicit and package-aligned.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves the v1 feature freeze and production-release gates remain explicit and package-aligned.
# Failure significance: A failure here means development scope or release readiness could be represented inaccurately.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $FreezePath = Join-Path $ProjectRoot 'Definitions\Release\DER-DevFreezePolicy.json'
    $CertToolPath = Join-Path $ProjectRoot 'Tools\Invoke-DERDevCertification.ps1'
    $SmokePath = Join-Path $ProjectRoot 'Tools\Invoke-DERWindowsSmokeTest.ps1'
    $Freeze = Get-Content -LiteralPath $FreezePath -Raw | ConvertFrom-Json -Depth 100
    $CertTool = Get-Content -LiteralPath $CertToolPath -Raw
    $Smoke = Get-Content -LiteralPath $SmokePath -Raw
    $Parent = Get-Content -LiteralPath (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
}
Describe 'DER v1 feature freeze contract' {
    It 'freezes the completed development feature set and blocks production claims' {
        $Freeze.generatedForPackage | Should -Be '1.0.0-dev'
        $Freeze.lifecycleStatus | Should -Be 'FeatureCompleteDevelopment'
        $Freeze.featureFreeze.newTenantFeaturesAllowed | Should -BeFalse
        $Freeze.featureFreeze.workloadDefinitionsFrozen | Should -BeTrue
        $Freeze.generatedForBuild | Should -Be $Freeze.packageIdentity.buildNumber
        $Freeze.packageIdentity.buildNumber | Should -BeGreaterThan 0
        $Freeze.packageIdentity.coreModules | Should -Be 19
        $Freeze.packageIdentity.workloadModules | Should -Be 25
        $Freeze.packageIdentity.parentModules | Should -Be 44
        $Freeze.productionRelease.ready | Should -BeFalse
        $Freeze.productionRelease.signedReleaseRequired | Should -BeTrue
        $Freeze.productionRelease.realCustomerTenantWriteAllowedBeforeGatesPass | Should -BeFalse
        $Parent | Should -Match 'DERDevFreezePolicyVersion'
        $Parent | Should -Match 'development freeze policy package binding does not match the launcher'
    }
    It 'requires the four validation gates in order' {
        @($Freeze.requiredGates).Count | Should -Be 4
        (@($Freeze.requiredGates.id) -join ',') | Should -Be 'WindowsSmoke,TenantNoWrite,TenantCanary,TenantPilot'
        (@($Freeze.requiredGates.order) -join ',') | Should -Be '1,2,3,4'
        @($Freeze.requiredGates | Where-Object id -in @('WindowsSmoke','TenantNoWrite') | Select-Object -ExpandProperty tenantMutationAllowed) | Should -Not -Contain $true
    }
}
Describe 'DER final certification tool safety' {
    It 'does not authenticate to Graph or perform Graph requests' {
        $CertTool | Should -Not -Match '(?m)^\s*(Connect-MgGraph|Invoke-MgGraphRequest|Disconnect-MgGraph)\b'
        $CertTool | Should -Match 'Invoke-DERWindowsSmokeTest.ps1'
        $CertTool | Should -Match 'DER-NoWriteEvidence.schema.json'
        $CertTool | Should -Match 'DER-CanaryEvidence.schema.json'
        $CertTool | Should -Match 'DER-PilotEvidence.schema.json'
        $CertTool | Should -Match 'productionReady=\$false'
    }
    It 'verifies the exact evidence hash chain and expected mutation deltas' {
        $CertTool | Should -Match 'prerequisite\.sha256 -ne \$nw\.SHA256'
        $CertTool | Should -Match 'prerequisites\.noWrite\.sha256 -ne \$nw\.SHA256'
        $CertTool | Should -Match 'prerequisites\.canary\.sha256 -ne \$can\.SHA256'
        $CertTool | Should -Match 'graphDelta\.post -ne 1'
        $CertTool | Should -Match 'graphDelta\.delete -ne 2'
    }
}
Describe 'DER smoke harness regression guard' {
    It 'no longer hard-codes the pre-Pilot 43-module count' {
        $Smoke | Should -Not -Match 'Expected 43 parent module catalog entries'
        $Smoke | Should -Match 'Parent module catalog is empty'
    }
}
