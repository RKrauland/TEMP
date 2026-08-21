#
<#
.SYNOPSIS
    DER v1 Pester suite — Canary gate contract.

.DESCRIPTION
    Proves the canary remains tightly scoped, package-bound, and dependent on prior zero-write evidence.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves the canary remains tightly scoped, package-bound, and dependent on prior zero-write evidence.
# Failure significance: A failure here means the first controlled tenant mutation may exceed its intended blast radius or skip a prerequisite.
# Static inspection of this file is not an executed Pester result.


$root=Split-Path -Parent $PSScriptRoot
Describe 'DER v1 canary contracts' {
    It 'ships the canary policy and evidence schema' {
        Test-Path (Join-Path $root 'Definitions\Canary\DER-CanaryPolicy.json') | Should -BeTrue
        Test-Path (Join-Path $root 'Definitions\Schema\DER-CanaryEvidence.schema.json') | Should -BeTrue
    }
    It 'limits canary mutations to one create and two deletes' {
        $p=Get-Content (Join-Path $root 'Definitions\Canary\DER-CanaryPolicy.json') -Raw|ConvertFrom-Json -Depth 100
        $p.graph.controlledObjectCount | Should -Be 1
        $p.graph.expectedMutationDelta.POST | Should -Be 1
        $p.graph.expectedMutationDelta.PATCH | Should -Be 0
        $p.graph.expectedMutationDelta.PUT | Should -Be 0
        $p.graph.expectedMutationDelta.DELETE | Should -Be 2
        @($p.graph.allowedMutationMethods) | Should -Not -Contain 'PATCH'
        @($p.graph.allowedMutationMethods) | Should -Not -Contain 'PUT'
    }
    It 'uses Group.ReadWrite.All and v1.0 only' {
        $p=Get-Content (Join-Path $root 'Definitions\Canary\DER-CanaryPolicy.json') -Raw|ConvertFrom-Json -Depth 100
        $p.graph.apiVersion | Should -Be 'v1.0'
        @($p.graph.requiredDelegatedScopes) | Should -Contain 'Group.ReadWrite.All'
    }
    It 'requires exact-build no-write proof before the canary' {
        $policy=Get-Content (Join-Path $root 'Definitions\Canary\DER-CanaryPolicy.json') -Raw|ConvertFrom-Json -Depth 100
        $source=Get-Content (Join-Path $root 'Core\DER.Canary.psm1') -Raw
        $policy.generatedForPackage | Should -Be '1.0.0-dev'
        [int]$policy.generatedForBuild | Should -BeGreaterThan 0
        $source | Should -Match 'Test-DERCanaryPrerequisiteEvidence'
        $source | Should -Match 'Evidence buildNumber does not match this canary internal build'
        $source | Should -Match 'package-manifest SHA-256 does not match'
        $source | Should -Match 'TransportWriteCount -ne 0'
        $source | Should -Match 'WriteSessionAttempts -ne 0'
    }
    It 'checks exact Object ID and display name before permanent purge' {
        $source=Get-Content (Join-Path $root 'Core\DER.Canary.psm1') -Raw
        $source | Should -Match 'directory/deletedItems'
        $source | Should -Match 'tombstone.id -ne \$objectId'
        $source | Should -Match 'tombstone.displayName -ne \$displayName'
    }
    It 'does not use PATCH or PUT in the canary module' {
        $source=Get-Content (Join-Path $root 'Core\DER.Canary.psm1') -Raw
        $source | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+PATCH'
        $source | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+PUT'
    }
}
