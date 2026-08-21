#
<#
.SYNOPSIS
    DER v1 Pester suite — Pilot gate contract.

.DESCRIPTION
    Proves pilot execution is constrained to its approved workload, prerequisites, mutation budget, and evidence requirements.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves pilot execution is constrained to its approved workload, prerequisites, mutation budget, and evidence requirements.
# Failure significance: A failure here means the real-workload pilot could execute outside its intended safety envelope.
# Static inspection of this file is not an executed Pester result.


$root=Split-Path -Parent $PSScriptRoot
Describe 'DER v1 end-to-end workload pilot contracts' {
    It 'ships pilot policy and evidence schema' {
        Test-Path (Join-Path $root 'Definitions\Pilot\DER-PilotPolicy.json') | Should -BeTrue
        Test-Path (Join-Path $root 'Definitions\Schema\DER-PilotEvidence.schema.json') | Should -BeTrue
        Test-Path (Join-Path $root 'Core\DER.Pilot.psm1') | Should -BeTrue
    }
    It 'uses the real Groups workload and normal rollback engine' {
        $p=Get-Content (Join-Path $root 'Definitions\Pilot\DER-PilotPolicy.json') -Raw|ConvertFrom-Json -Depth 100
        $p.workload.module | Should -Be 'Groups'
        $p.workload.entryPoint | Should -Be 'Invoke-DERGroupsModule'
        $p.workload.rollbackEntryPoint | Should -Be 'Invoke-DERModuleRollback'
        $p.workload.derId | Should -Be 'DER-PILOT-GRP-001'
        $source=Get-Content (Join-Path $root 'Core\DER.Pilot.psm1') -Raw
        $source | Should -Match 'Invoke-DERGroupsModule'
        $source | Should -Match "Invoke-DERModuleRollback\s+-Module\s+'Groups'.*-DerId.*-ObjectId"
    }
    It 'limits the successful pilot mutation contract to one create and two deletes' {
        $p=Get-Content (Join-Path $root 'Definitions\Pilot\DER-PilotPolicy.json') -Raw|ConvertFrom-Json -Depth 100
        $p.graph.controlledObjectCount | Should -Be 1
        $p.graph.expectedMutationDelta.POST | Should -Be 1
        $p.graph.expectedMutationDelta.PATCH | Should -Be 0
        $p.graph.expectedMutationDelta.PUT | Should -Be 0
        $p.graph.expectedMutationDelta.DELETE | Should -Be 2
        $p.graph.expectedWorkloadCreateCount | Should -Be 1
        $p.graph.expectedRollbackDeleteCount | Should -Be 1
        $p.graph.expectedPermanentPurgeCount | Should -Be 1
    }
    It 'requires exact-build passing no-write and canary evidence' {
        $source=Get-Content (Join-Path $root 'Core\DER.Pilot.psm1') -Raw
        $source | Should -Match 'No-write evidence is not from this DER v1 package identity'
        $source | Should -Match 'No-write evidence is not from this exact DER internal build'
        $source | Should -Match 'Canary evidence is not from this DER v1 package identity'
        $source | Should -Match 'Canary evidence is not from this exact DER internal build'
        $source | Should -Match 'Canary evidence did not pass with complete cleanup'
        $source | Should -Match 'package-manifest hash does not match this package'
        $source | Should -Match 'not chained to the exact no-write evidence file'
    }
    It 'requires exact DER ID and Object ID rollback filters' {
        $source=Get-Content (Join-Path $root 'Core\DER.Rollback.psm1') -Raw
        $source | Should -Match '\[string\]\$DerId'
        $source | Should -Match '\[string\]\$ObjectId'
        $source | Should -Match '\$_\.DerId -eq \$DerId'
        $source | Should -Match '\$_\.ObjectId -eq \$ObjectId'
    }
    It 'does not directly PATCH or PUT anything from the pilot harness' {
        $source=Get-Content (Join-Path $root 'Core\DER.Pilot.psm1') -Raw
        $source | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+PATCH'
        $source | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+PUT'
    }
    It 'proves both Graph cleanup and DER state cleanup before PASS' {
        $source=Get-Content (Join-Path $root 'Core\DER.Pilot.psm1') -Raw
        $source | Should -Match 'Wait-DERPilotAbsent.*groups/'
        $source | Should -Match 'directory/deletedItems'
        $source | Should -Match 'stateRemoved'
        $source | Should -Match 'cleanupComplete'
    }
    It 'requires an explicit PILOT-WRITE approval token' {
        $p=Get-Content (Join-Path $root 'Definitions\Pilot\DER-PilotPolicy.json') -Raw|ConvertFrom-Json -Depth 100
        $p.operator.confirmationToken | Should -Be 'PILOT-WRITE'
    }
}
