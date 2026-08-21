# Requires -Version 7.4
# Pester 5.x

<#
.SYNOPSIS
    DER v1 Pester suite — Recovery interpretation contract.

.DESCRIPTION
    Proves interrupted-run evidence is interpreted chronologically, fail-closed, and without automatic replay.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves interrupted-run evidence is interpreted chronologically, fail-closed, and without automatic replay.
# Failure significance: A failure here means DER could resume or declare recovery complete without sufficient proof.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $ProjectRoot 'Tests\Helpers\DER.TestHarness.psm1') -Force
    Import-DERTestCoreCommands -ProjectRoot $ProjectRoot
    Import-Module (Join-Path $ProjectRoot 'Core\DER.Recovery.psm1') -Force
    $Policy = Get-Content (Join-Path $ProjectRoot 'Definitions\Recovery\DER-RecoveryPolicy.json') -Raw | ConvertFrom-Json -Depth 100

    function New-DERTestJournalEvent {
        param([int]$Sequence,[string]$ActionId,[string]$Phase,[string]$ObjectId=$null,[string]$RunId='RUN-OLD',[string]$TenantId='00000000-0000-4000-8000-000000000001')
        [pscustomobject][ordered]@{journalVersion='1.1';sequence=$Sequence;timestamp='2026-08-20T00:00:00.0000000Z';runId=$RunId;tenantId=$TenantId;actionId=$ActionId;phase=$Phase;module='Groups';derId='DER-GRP-D-010';objectId=$ObjectId;message='synthetic';data=$null}
    }
}

Describe 'DER recovery policy safety contract' {
    It 'forbids every form of Graph request replay' {
        $Policy.semantics.graphWriteReplayAllowed | Should -BeFalse
        $Policy.semantics.serializedRequestReplayAllowed | Should -BeFalse
        $Policy.semantics.freshDiscoveryRequired | Should -BeTrue
        $Policy.semantics.uncertainWriteRequiresExplicitReconcile | Should -BeTrue
    }

    It 'contains no mutating Graph call in the recovery engine' {
        $text=Get-Content (Join-Path $ProjectRoot 'Core\DER.Recovery.psm1') -Raw
        $text | Should -Not -Match 'Invoke-DERGraphRequest\s+-Method\s+(POST|PATCH|PUT|DELETE)'
        $text | Should -Not -Match 'Invoke-DERGraphCollectionRequest\s+.*-Method\s+(POST|PATCH|PUT|DELETE)'
        $text | Should -Match 'ReplayPerformed=\$false'
    }

    It 'has a recovery disposition for every policy disposition name' {
        $names=@($Policy.dispositions.name)
        foreach($name in @('PreserveCommitted','PreserveRolledBack','PreserveSkipped','SafeToReplan','ReconcileFailed','ReconcileUncertainWrite','ReconcileUncertainRollback','JournalInvalid')){
            $names | Should -Contain $name
        }
    }
}

Describe 'DER strict journal reader' {
    It 'accepts a monotonic sequenced journal' {
        $path=Join-Path $TestDrive 'good.jsonl'
        @(
            (New-DERTestJournalEvent -Sequence 1 -ActionId 'DER-MODULE-00001' -Phase EXECUTE)
            (New-DERTestJournalEvent -Sequence 2 -ActionId 'DER-MODULE-00001' -Phase COMMIT)
        ) | ForEach-Object { ($_|ConvertTo-Json -Depth 20 -Compress) | Add-Content -LiteralPath $path }
        $result=Read-DERRecoveryJournalStrict -Path $path -ExpectedRunId 'RUN-OLD' -ExpectedTenantId '00000000-0000-4000-8000-000000000001'
        $result.Valid | Should -BeTrue
        $result.UsesSequence | Should -BeTrue
        $result.Events.Count | Should -Be 2
    }

    It 'fails closed on malformed JSON instead of silently dropping it' {
        $path=Join-Path $TestDrive 'malformed.jsonl'
        (New-DERTestJournalEvent -Sequence 1 -ActionId 'DER-MODULE-00001' -Phase EXECUTE|ConvertTo-Json -Compress) | Set-Content -LiteralPath $path
        '{not-json' | Add-Content -LiteralPath $path
        $result=Read-DERRecoveryJournalStrict -Path $path -ExpectedRunId 'RUN-OLD' -ExpectedTenantId '00000000-0000-4000-8000-000000000001'
        $result.Valid | Should -BeFalse
        @($result.Errors|Where-Object Code -eq 'MalformedJson').Count | Should -Be 1
    }

    It 'fails closed on reordered or duplicate sequence values' {
        $path=Join-Path $TestDrive 'sequence.jsonl'
        @(
            (New-DERTestJournalEvent -Sequence 2 -ActionId 'A-1' -Phase EXECUTE)
            (New-DERTestJournalEvent -Sequence 2 -ActionId 'A-1' -Phase COMMIT)
        ) | ForEach-Object { ($_|ConvertTo-Json -Depth 20 -Compress) | Add-Content -LiteralPath $path }
        $result=Read-DERRecoveryJournalStrict -Path $path -ExpectedRunId 'RUN-OLD' -ExpectedTenantId '00000000-0000-4000-8000-000000000001'
        $result.Valid | Should -BeFalse
        @($result.Errors|Where-Object Code -eq 'SequenceOrder').Count | Should -BeGreaterThan 0
    }

    It 'fails closed when tenant or run identity is wrong' {
        $path=Join-Path $TestDrive 'identity.jsonl'
        (New-DERTestJournalEvent -Sequence 1 -ActionId 'A-1' -Phase COMMIT -RunId 'WRONG-RUN'|ConvertTo-Json -Compress) | Set-Content -LiteralPath $path
        $result=Read-DERRecoveryJournalStrict -Path $path -ExpectedRunId 'RUN-OLD' -ExpectedTenantId '00000000-0000-4000-8000-000000000001'
        $result.Valid | Should -BeFalse
        @($result.Errors|Where-Object Code -eq 'RunIdMismatch').Count | Should -Be 1
    }
}

Describe 'DER action recovery classification' {
    It 'preserves a committed action and never marks it replayable' {
        $timeline=Get-DERRecoveryActionTimelines -Events @(
            (New-DERTestJournalEvent -Sequence 1 -ActionId 'A-COMMIT' -Phase EXECUTE)
            (New-DERTestJournalEvent -Sequence 2 -ActionId 'A-COMMIT' -Phase COMMIT -ObjectId '11111111-1111-4111-8111-111111111111')
        )
        $timeline.Count | Should -Be 1
        $timeline[0].Disposition | Should -Be 'PreserveCommitted'
        $timeline[0].ReplayAllowed | Should -BeFalse
        $timeline[0].RequiresExplicitReconcile | Should -BeFalse
    }

    It 'requires reconciliation when EXECUTE has no terminal outcome' {
        $timeline=Get-DERRecoveryActionTimelines -Events @((New-DERTestJournalEvent -Sequence 1 -ActionId 'A-CRASH' -Phase EXECUTE))
        $timeline[0].Disposition | Should -Be 'ReconcileUncertainWrite'
        $timeline[0].Risk | Should -Be 'High'
        $timeline[0].RequiresExplicitReconcile | Should -BeTrue
        $timeline[0].ReplayAllowed | Should -BeFalse
    }

    It 'allows planning-only activity to be safely replanned after discovery' {
        $timeline=Get-DERRecoveryActionTimelines -Events @(
            (New-DERTestJournalEvent -Sequence 1 -ActionId 'A-PLAN' -Phase PLAN)
            (New-DERTestJournalEvent -Sequence 2 -ActionId 'A-PLAN' -Phase PRECHECK)
        )
        $timeline[0].Disposition | Should -Be 'SafeToReplan'
        $timeline[0].Risk | Should -Be 'Low'
        $timeline[0].ReplayAllowed | Should -BeFalse
    }

    It 'uses the latest chronological terminal outcome instead of treating terminal words as a contradiction' {
        $timeline=Get-DERRecoveryActionTimelines -Events @(
            (New-DERTestJournalEvent -Sequence 1 -ActionId 'A-LATE-FAIL' -Phase EXECUTE)
            (New-DERTestJournalEvent -Sequence 2 -ActionId 'A-LATE-FAIL' -Phase COMMIT -ObjectId '11111111-1111-4111-8111-111111111111')
            (New-DERTestJournalEvent -Sequence 3 -ActionId 'A-LATE-FAIL' -Phase FAIL -ObjectId '11111111-1111-4111-8111-111111111111')
        )
        $timeline[0].Disposition | Should -Be 'ReconcileFailed'
        $timeline[0].Risk | Should -Be 'High'
        $timeline[0].RequiresExplicitReconcile | Should -BeTrue
        $timeline[0].Invalid | Should -BeFalse
    }
}

Describe 'DER safe resume gate' {
    BeforeEach {
        $script:CurrentRunRoot=Join-Path $TestDrive 'current'
        New-Item -ItemType Directory -Path $script:CurrentRunRoot -Force|Out-Null
        Mock -ModuleName DER.Recovery Get-DERStateContext { [pscustomobject]@{TenantId='00000000-0000-4000-8000-000000000001';RunRoot=$script:CurrentRunRoot} }
        Mock -ModuleName DER.Recovery Get-DERRecoveryPendingAdoptedPreparations { @() }
    }

    It 'refuses ResumeSafe when a prior tenant write is uncertain' {
        $priorRoot=Join-Path $TestDrive 'old'
        New-Item -ItemType Directory -Path $priorRoot -Force|Out-Null
        $action=[pscustomobject]@{ActionId='A-CRASH';Module='Groups';DerId='DER-GRP-D-010';ObjectId=$null;EventCount=1;Phases=@('EXECUTE');LastPhase='EXECUTE';Disposition='ReconcileUncertainWrite';Risk='High';RequiresExplicitReconcile=$true;PossibleTenantWrite=$true;ReplayAllowed=$false;Invalid=$false;Reason=$null}
        Mock -ModuleName DER.Recovery Get-DERIncompleteRuns { @([pscustomobject]@{RunId='RUN-OLD';RunRoot=$priorRoot;Status='RecoveryRequired';Stage='Workloads';UpdatedAt='2026-08-20T00:00:00Z';ProcessId=0;ProcessStillRunning=$false;JournalValid=$true;JournalErrors=@();JournalVersion='1.1';JournalEntries=1;ActionCount=1;CommittedActions=0;UncertainActions=1;LastPhase='EXECUTE';LastModule='Groups';LastActionId='A-CRASH';HighestRisk='High';Actions=@($action)}) }
        { Invoke-DERRecoveryCheck -RunId 'RUN-NEW' -RuntimeRoot $TestDrive -Mode ResumeSafe } | Should -Throw '*ResumeSafe refused*'
    }

    It 'fails closed before resume when CurrentState carries unresolved adopted rollback preparation' {
        Mock -ModuleName DER.Recovery Get-DERIncompleteRuns { @() }
        Mock -ModuleName DER.Recovery Get-DERRecoveryPendingAdoptedPreparations { @([pscustomobject]@{DerId='DER-ENTRA-DEVICE';ObjectId='deviceRegistrationPolicy';DisplayName='Entra device registration policy';RunId='RUN-OLD';ActionId='A-OLD';Malformed=$false}) }
        { Invoke-DERRecoveryCheck -RunId 'RUN-NEW' -RuntimeRoot $TestDrive -Mode Reconcile } | Should -Throw '*unresolved DER-Adopted rollback preparation*'
    }

    It 'allows explicit noninteractive Reconcile without replaying anything' {
        $priorRoot=Join-Path $TestDrive 'old2'
        New-Item -ItemType Directory -Path $priorRoot -Force|Out-Null
        $action=[pscustomobject]@{ActionId='A-CRASH';Module='Groups';DerId='DER-GRP-D-010';ObjectId=$null;EventCount=1;Phases=@('EXECUTE');LastPhase='EXECUTE';Disposition='ReconcileUncertainWrite';Risk='High';RequiresExplicitReconcile=$true;PossibleTenantWrite=$true;ReplayAllowed=$false;Invalid=$false;Reason=$null}
        Mock -ModuleName DER.Recovery Get-DERIncompleteRuns { @([pscustomobject]@{RunId='RUN-OLD2';RunRoot=$priorRoot;Status='RecoveryRequired';Stage='Workloads';UpdatedAt='2026-08-20T00:00:00Z';ProcessId=0;ProcessStillRunning=$false;JournalValid=$true;JournalErrors=@();JournalVersion='1.1';JournalEntries=1;ActionCount=1;CommittedActions=0;UncertainActions=1;LastPhase='EXECUTE';LastModule='Groups';LastActionId='A-CRASH';HighestRisk='High';Actions=@($action)}) }
        $result=Invoke-DERRecoveryCheck -RunId 'RUN-NEW' -RuntimeRoot $TestDrive -Mode Reconcile
        $result.ReadyToContinue | Should -BeTrue
        $result.Decision | Should -Be 'Reconcile'
        $result.ReplayPerformed | Should -BeFalse
        Test-Path (Join-Path $script:CurrentRunRoot 'RecoveryDecision.json') | Should -BeTrue
    }
}

Describe 'DER parent recovery checkpoints' {
    It 'journals every workload invocation at the parent level' {
        $text=Get-Content (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
        $text | Should -Match "New-DERActionId -Component 'MODULE'"
        $text | Should -Match 'Register-DERTransaction -ActionId \$moduleActionId -Phase PRECHECK'
        $text | Should -Match 'Register-DERTransaction -ActionId \$moduleActionId -Phase COMMIT'
        $text | Should -Match 'Register-DERTransaction -ActionId \$moduleActionId -Phase FAIL'
        $text | Should -Match "\$recoveryStatus='RecoveryRequired'"
    }

    It 'forwards RecoveryMode across bootstrap relaunch' {
        $text=Get-Content (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
        $text | Should -Match '\[ValidateSet\(''Prompt'',''Analyze'',''ResumeSafe'',''Reconcile'',''Stop''\)\]\[string\]\$RecoveryMode'
        $text | Should -Match "\$items.Add\('-RecoveryMode'\)"
    }

    It 'writes versioned sequenced transaction journal events' {
        $text=Get-Content (Join-Path $ProjectRoot 'Core\DER.State.psm1') -Raw
        $text | Should -Match "journalVersion='1\.1'"
        $text | Should -Match 'sequence=\$script:DERTransactionSequence'
        $text | Should -Match 'ProcessStartTimeUtc'
        $text | Should -Match 'MachineName'
    }
}
