<#
.SYNOPSIS
    DER interrupted-run recovery analyzer and safe-resume gate.

.DESCRIPTION
    Reconstructs prior DER transaction journals without replaying tenant writes.
    Recovery always starts from fresh Microsoft discovery. Completed actions are
    preserved, uncertain writes are reconciled against current tenant state, and
    malformed/contradictory journals fail closed.

    IMPORTANT: this module never issues Graph POST/PATCH/PUT/DELETE requests and
    never replays a serialized request body from a prior transaction journal.

.NOTES
    Required parent entry point: Invoke-DERRecoveryCheck
#>


# Maintenance notes
# Responsibility: Chronological interrupted-run/recovery interpreter. Ambiguous evidence fails closed and is never replay authorization.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

$script:DERRecoveryPhases=@('PLAN','PRECHECK','RECORD_ORIGINAL','EXECUTE','CREATED','UPDATED','ASSIGNED','READBACK','VALIDATE','COMMIT','ROLLBACK','ROLLBACK_VALIDATE','SKIP','FAIL')
$script:DERRecoveryTerminalPhases=@('COMMIT','ROLLBACK_VALIDATE','SKIP','FAIL')
$script:DERRecoveryPossibleWritePhases=@('EXECUTE','CREATED','UPDATED','ASSIGNED','READBACK','VALIDATE','ROLLBACK')

function Test-DERRecoveryCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DERRecoveryLog { param([string]$Level,[string]$Message,$Data) if(Test-DERRecoveryCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Recovery' -Message $Message -Data $Data} }
function Read-DERRecoveryJson { param([string]$Path) if(-not(Test-Path -LiteralPath $Path)){return $null}; try { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100 } catch { throw "DER recovery metadata is malformed/unreadable at '$Path'. Recovery must fail closed. $($_.Exception.Message)" } }
function Write-DERRecoveryJson { param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)]$Object) $dir=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null};$Object|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $Path -Encoding UTF8 }

function Get-DERRecoveryPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageRoot)
    $path=Join-Path $PackageRoot 'Definitions\Recovery\DER-RecoveryPolicy.json'
    if(-not(Test-Path -LiteralPath $path)){throw "DER recovery policy is missing: $path"}
    $policy=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json -Depth 100
    if([string]$policy.schemaVersion -ne '1.0'){throw 'Unsupported DER recovery policy schema version.'}
    if([bool]$policy.semantics.graphWriteReplayAllowed){throw 'DER recovery policy is unsafe: graphWriteReplayAllowed must remain false.'}
    if(-not[bool]$policy.semantics.freshDiscoveryRequired){throw 'DER recovery policy is unsafe: freshDiscoveryRequired must remain true.'}
    return $policy
}

function Read-DERRecoveryJournalStrict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExpectedRunId,
        [string]$ExpectedTenantId
    )
    $events=New-Object System.Collections.Generic.List[object]
    $errors=New-Object System.Collections.Generic.List[object]
    if(-not(Test-Path -LiteralPath $Path)){
        return [pscustomobject][ordered]@{Path=$Path;Exists=$false;Valid=$true;Events=@();Errors=@();JournalVersion='LegacyOrEmpty';UsesSequence=$false}
    }
    $lineNumber=0
    $lastSequence=0
    $expectedSequence=1
    $usesSequence=$false
    foreach($line in Get-Content -LiteralPath $Path){
        $lineNumber++
        if([string]::IsNullOrWhiteSpace($line)){continue}
        try{$event=$line|ConvertFrom-Json -Depth 100}catch{$errors.Add([pscustomobject]@{Line=$lineNumber;Code='MalformedJson';Message=$_.Exception.Message});continue}
        $names=@($event.PSObject.Properties.Name)
        foreach($required in @('runId','tenantId','actionId','phase')){
            if($names -notcontains $required -or [string]::IsNullOrWhiteSpace([string]$event.$required)){$errors.Add([pscustomobject]@{Line=$lineNumber;Code='MissingField';Message=("Missing required journal field: {0}"-f$required)})}
        }
        if($names -contains 'phase' -and [string]$event.phase -notin $script:DERRecoveryPhases){$errors.Add([pscustomobject]@{Line=$lineNumber;Code='UnknownPhase';Message=("Unknown transaction phase: {0}"-f$event.phase)})}
        if($ExpectedRunId -and $names -contains 'runId' -and [string]$event.runId -ne $ExpectedRunId){$errors.Add([pscustomobject]@{Line=$lineNumber;Code='RunIdMismatch';Message=("Journal RunId {0} does not match run directory {1}."-f$event.runId,$ExpectedRunId)})}
        if($ExpectedTenantId -and $names -contains 'tenantId' -and [string]$event.tenantId -ne $ExpectedTenantId){$errors.Add([pscustomobject]@{Line=$lineNumber;Code='TenantIdMismatch';Message='Journal TenantId does not match the authenticated tenant.'})}
        if($names -contains 'sequence' -and $null-ne$event.sequence){
            $usesSequence=$true
            try{$seq=[int64]$event.sequence}catch{$seq=0;$errors.Add([pscustomobject]@{Line=$lineNumber;Code='InvalidSequence';Message='Transaction sequence is not an integer.'})}
            if($seq -le $lastSequence){$errors.Add([pscustomobject]@{Line=$lineNumber;Code='SequenceOrder';Message=("Transaction sequence {0} is not greater than prior sequence {1}."-f$seq,$lastSequence)})}
            if($seq -gt 0 -and $seq -ne $expectedSequence){$errors.Add([pscustomobject]@{Line=$lineNumber;Code='SequenceGap';Message=("Expected transaction sequence {0} but found {1}."-f$expectedSequence,$seq)})}
            if($seq -gt 0){$lastSequence=$seq;$expectedSequence=$seq+1}
        }
        $events.Add($event)
    }
    if($usesSequence -and @($events|Where-Object{$_.PSObject.Properties.Name -notcontains 'sequence'}).Count -gt 0){$errors.Add([pscustomobject]@{Line=0;Code='MixedSequenceFormat';Message='Journal mixes sequenced and legacy unsequenced events.'})}
    $versions=@($events|Where-Object{$_.PSObject.Properties.Name -contains 'journalVersion'}|ForEach-Object{[string]$_.journalVersion}|Sort-Object -Unique)
    foreach($version in $versions){if($version -ne '1.1'){$errors.Add([pscustomobject]@{Line=0;Code='UnsupportedJournalVersion';Message=("Unsupported transaction journal version: {0}"-f$version)})}}
    if($versions.Count -gt 1){$errors.Add([pscustomobject]@{Line=0;Code='MixedJournalVersion';Message='Journal contains more than one transaction journal version.'})}
    return [pscustomobject][ordered]@{
        Path=$Path;Exists=$true;Valid=($errors.Count-eq0);Events=@($events);Errors=@($errors);
        JournalVersion=if($versions.Count-eq1){$versions[0]}elseif($versions.Count-gt1){'Mixed'}else{'1.0-legacy'};UsesSequence=$usesSequence
    }
}

function Get-DERRecoveryActionTimelines {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Events)
    $ordered=@($Events|Sort-Object @{Expression={if($_.PSObject.Properties.Name -contains 'sequence' -and $null-ne$_.sequence){[int64]$_.sequence}else{[int64]::MaxValue}}},@{Expression={try{[datetime]$_.timestamp}catch{[datetime]::MinValue}}})
    $out=New-Object System.Collections.Generic.List[object]
    foreach($group in @($ordered|Group-Object actionId)){
        $items=@($group.Group)
        if($items.Count-eq0){continue}
        $phases=@($items|ForEach-Object{[string]$_.phase})
        $last=$items|Select-Object -Last 1
        $possibleWrite=[bool](@($items|Where-Object{[string]$_.phase -in $script:DERRecoveryPossibleWritePhases}).Count)
        $successWrite=[bool](@($items|Where-Object{[string]$_.phase -in @('CREATED','UPDATED','ASSIGNED')}).Count)
        $rollbackValidated=@($items|Where-Object{[string]$_.phase -eq 'ROLLBACK_VALIDATE'}|Select-Object -Last 1)
        $commit=@($items|Where-Object{[string]$_.phase -eq 'COMMIT'}|Select-Object -Last 1)
        $fail=@($items|Where-Object{[string]$_.phase -eq 'FAIL'}|Select-Object -Last 1)
        $skip=@($items|Where-Object{[string]$_.phase -eq 'SKIP'}|Select-Object -Last 1)
        $rollback=@($items|Where-Object{[string]$_.phase -eq 'ROLLBACK'}|Select-Object -Last 1)
        $lastTerminal=@($items|Where-Object{[string]$_.phase -in $script:DERRecoveryTerminalPhases}|Select-Object -Last 1)
        $disposition='SafeToReplan';$risk='Low';$requires=$false;$invalid=$false;$reason=$null
        if($lastTerminal.Count){
            switch([string]$lastTerminal[0].phase){
                'ROLLBACK_VALIDATE'{$disposition='PreserveRolledBack';$risk='None'}
                'COMMIT'{$disposition='PreserveCommitted';$risk='None'}
                'SKIP'{$disposition='PreserveSkipped';$risk='None'}
                'FAIL'{
                    $outcome=$null
                    if($lastTerminal[0].data -and $lastTerminal[0].data.PSObject.Properties.Name -contains 'writeOutcome'){$outcome=[string]$lastTerminal[0].data.writeOutcome}
                    if($outcome -eq 'DefiniteNoWrite' -and -not$successWrite){$disposition='SafeToReplan';$risk='Low'}
                    else{$disposition='ReconcileFailed';$risk=if($possibleWrite){'High'}else{'Low'};$requires=$possibleWrite}
                }
            }
        } elseif($rollback.Count){$disposition='ReconcileUncertainRollback';$risk='High';$requires=$true}
        elseif($possibleWrite){$disposition='ReconcileUncertainWrite';$risk='High';$requires=$true}
        $objectId=@($items|Where-Object{-not[string]::IsNullOrWhiteSpace([string]$_.objectId)}|Select-Object -Last 1|ForEach-Object{[string]$_.objectId})
        $derId=@($items|Where-Object{-not[string]::IsNullOrWhiteSpace([string]$_.derId)}|Select-Object -Last 1|ForEach-Object{[string]$_.derId})
        $module=@($items|Where-Object{-not[string]::IsNullOrWhiteSpace([string]$_.module)}|Select-Object -Last 1|ForEach-Object{[string]$_.module})
        $lastSeq=if($last.PSObject.Properties.Name -contains 'sequence') {[int64]$last.sequence}else{0}
        $out.Add([pscustomobject][ordered]@{ActionId=[string]$group.Name;Module=if($module.Count){$module[0]}else{$null};DerId=if($derId.Count){$derId[0]}else{$null};ObjectId=if($objectId.Count){$objectId[0]}else{$null};EventCount=$items.Count;Phases=$phases;LastPhase=[string]$last.phase;LastSequence=$lastSeq;Disposition=$disposition;Risk=$risk;RequiresExplicitReconcile=$requires;PossibleTenantWrite=$possibleWrite;ReplayAllowed=$false;Invalid=$invalid;Reason=$reason;CorrelatedRollbackActionId=$null})
    }

    # A validated rollback may be a separate action. Correlate only when the
    # original write has a known Microsoft ObjectId; an ambiguous create with no
    # known ObjectId stays unresolved by design.
    foreach($entry in @($out|Where-Object{$_.RequiresExplicitReconcile -and -not[string]::IsNullOrWhiteSpace([string]$_.ObjectId)})){
        # Work around parser spacing ambiguity by filtering in a second pass.
        $matched=New-Object System.Collections.Generic.List[object]
        foreach($candidate in @($out)){
            if($candidate.ActionId -eq $entry.ActionId){continue}
            if($candidate.Disposition -ne 'PreserveRolledBack'){continue}
            if([string]$candidate.ObjectId -ne [string]$entry.ObjectId){continue}
            if(-not[string]::IsNullOrWhiteSpace([string]$entry.DerId)){
                if([string]::IsNullOrWhiteSpace([string]$candidate.DerId) -or [string]$candidate.DerId -ne [string]$entry.DerId){continue}
            }
            if($candidate.LastSequence -gt 0 -and $entry.LastSequence -gt 0 -and $candidate.LastSequence -le $entry.LastSequence){continue}
            $matched.Add($candidate)
        }
        if($matched.Count){$winner=@($matched|Sort-Object LastSequence|Select-Object -First 1)[0];$entry.Disposition='PreserveRolledBack';$entry.Risk='None';$entry.RequiresExplicitReconcile=$false;$entry.CorrelatedRollbackActionId=$winner.ActionId;$entry.Reason='A later validated rollback for the same Microsoft ObjectId and compatible DER identity resolved the earlier failed/uncertain write.'}
    }
    return @($out)
}

function Test-DERPriorRunProcessAlive {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RunState)
    try{
        if(-not($RunState.PSObject.Properties.Name -contains 'MachineName')){return $false}
        if(-not($RunState.PSObject.Properties.Name -contains 'ProcessStartTimeUtc')){return $false}
        if([string]$RunState.MachineName -ne [Environment]::MachineName){return $false}
        $pidValue=[int]$RunState.ProcessId
        if($pidValue-le0 -or $pidValue-eq$PID){return $false}
        $process=Get-Process -Id $pidValue -ErrorAction Stop
        $expected=[datetime]::Parse([string]$RunState.ProcessStartTimeUtc).ToUniversalTime()
        $actual=$process.StartTime.ToUniversalTime()
        return ([math]::Abs(($actual-$expected).TotalSeconds)-lt2)
    }catch{return $false}
}

function Get-DERRecoveryPendingAdoptedPreparations {
    [CmdletBinding()]
    param()
    if(-not(Test-DERRecoveryCommand 'Get-DERCurrentState')){return @()}
    $state=Get-DERCurrentState
    if(-not $state -or -not ($state.PSObject.Properties.Name -contains 'Objects')){return @()}
    $out=New-Object System.Collections.Generic.List[object]
    foreach($record in @($state.Objects)){
        if($null -eq $record -or [string]$record.OwnershipClass -ne 'DER-Adopted' -or -not $record.Metadata){continue}
        if($record.Metadata.PSObject.Properties.Name -notcontains 'RollbackPreparation'){continue}
        $prep=$record.Metadata.RollbackPreparation
        $malformed=($null -eq $prep -or [string]::IsNullOrWhiteSpace([string]$prep.RunId) -or [string]::IsNullOrWhiteSpace([string]$prep.ActionId) -or -not [bool]$prep.Eligible -or $null -eq $prep.ChangeMetadata)
        $out.Add([pscustomobject][ordered]@{
            DerId=[string]$record.DerId;ObjectId=[string]$record.ObjectId;DisplayName=[string]$record.DisplayName;
            RunId=if($prep){[string]$prep.RunId}else{$null};ActionId=if($prep){[string]$prep.ActionId}else{$null};Malformed=$malformed
        })
    }
    return @($out)
}

function Get-DERIncompleteRuns {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimeRoot,[Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$CurrentRunId)
    $root=Join-Path (Join-Path $RuntimeRoot 'Runs') $TenantId
    if(-not(Test-Path -LiteralPath $root)){return @()}
    $out=New-Object System.Collections.Generic.List[object]
    foreach($dir in Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop){
        if($dir.Name -eq $CurrentRunId){continue}
        $runState=Read-DERRecoveryJson (Join-Path $dir.FullName 'RunState.json')
        if(-not$runState){continue}
        if([string]$runState.Status -notin @('Running','RecoveryRequired','Failed','Aborted')){continue}
        $journalResult=Read-DERRecoveryJournalStrict -Path (Join-Path $dir.FullName 'TransactionJournal.jsonl') -ExpectedRunId $dir.Name -ExpectedTenantId $TenantId
        $timelines=Get-DERRecoveryActionTimelines -Events @($journalResult.Events)
        # If Microsoft returned an ObjectId but the success journal append itself failed,
        # Graph records that receipt in RunState before throwing. Use it only to enrich
        # the same ActionId; it never overrides an ObjectId already proven by the journal.
        $recoveryEvidence=$null
        if($runState.PSObject.Properties.Name -contains 'RecoveryEvidence' -and $runState.RecoveryEvidence){$recoveryEvidence=$runState.RecoveryEvidence}
        elseif($runState.Data -and [bool]$runState.Data.requiresRecovery){$recoveryEvidence=$runState.Data}
        if($recoveryEvidence -and -not[string]::IsNullOrWhiteSpace([string]$recoveryEvidence.actionId) -and $recoveryEvidence.details){
            $receiptObjectId=$null
            if($recoveryEvidence.details.PSObject.Properties.Name -contains 'objectId'){$receiptObjectId=[string]$recoveryEvidence.details.objectId}
            if(-not[string]::IsNullOrWhiteSpace($receiptObjectId)){
                $receiptAction=@($timelines|Where-Object{[string]$_.ActionId -eq [string]$recoveryEvidence.actionId}|Select-Object -First 1)
                if($receiptAction.Count -and [string]::IsNullOrWhiteSpace([string]$receiptAction[0].ObjectId)){$receiptAction[0].ObjectId=$receiptObjectId}
            }
        }
        $requires=@($timelines|Where-Object{$_.RequiresExplicitReconcile -or $_.Invalid})
        $unresolved=@($timelines|Where-Object{$_.Disposition -in @('ReconcileUncertainWrite','ReconcileUncertainRollback','ReconcileFailed','JournalInvalid')})
        # Failed/Aborted runs with no unresolved journal activity are terminal history, not a resume candidate.
        if([string]$runState.Status -in @('Failed','Aborted') -and $unresolved.Count-eq0 -and $journalResult.Valid){continue}
        $last=@($journalResult.Events|Select-Object -Last 1)
        $highestRisk=if(-not$journalResult.Valid){'Critical'}elseif(@($timelines|Where-Object{$_.Risk-eq'Critical'}).Count){'Critical'}elseif(@($timelines|Where-Object{$_.Risk-eq'High'}).Count){'High'}elseif(@($timelines|Where-Object{$_.Risk-eq'Low'}).Count){'Low'}else{'None'}
        $out.Add([pscustomobject][ordered]@{
            RunId=$dir.Name;RunRoot=$dir.FullName;Status=[string]$runState.Status;Stage=[string]$runState.Stage;UpdatedAt=$runState.UpdatedAt;ProcessId=$runState.ProcessId;
            ProcessStillRunning=(Test-DERPriorRunProcessAlive -RunState $runState);JournalValid=[bool]$journalResult.Valid;JournalErrors=@($journalResult.Errors);JournalVersion=$journalResult.JournalVersion;
            JournalEntries=@($journalResult.Events).Count;ActionCount=$timelines.Count;CommittedActions=@($timelines|Where-Object{$_.Disposition-eq'PreserveCommitted'}).Count;
            UncertainActions=$requires.Count;LastPhase=if($last.Count){[string]$last[0].phase}else{$null};LastModule=if($last.Count){[string]$last[0].module}else{$null};LastActionId=if($last.Count){[string]$last[0].actionId}else{$null};
            HighestRisk=$highestRisk;Actions=$timelines
        })
    }
    return @($out|Sort-Object UpdatedAt -Descending)
}

function Invoke-DERRecoveryCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [string]$PackageRoot,
        [ValidateSet('Analyze','Prompt','ResumeSafe','Reconcile','Stop','PreserveCompleted')][string]$Mode='Prompt'
    )
    $ctx=if(Test-DERRecoveryCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null}
    if(-not$ctx){throw 'DER Recovery requires initialized tenant state.'}
    $policy=$null
    if($PackageRoot){$policy=Get-DERRecoveryPolicy -PackageRoot $PackageRoot}
    $incomplete=@(Get-DERIncompleteRuns -RuntimeRoot $RuntimeRoot -TenantId $ctx.TenantId -CurrentRunId $RunId)
    $pendingPreparations=@(Get-DERRecoveryPendingAdoptedPreparations)
    if($incomplete.Count-eq0 -and $pendingPreparations.Count-eq0){
        Write-DERRecoveryLog -Level OK -Message 'No interrupted prior DER runs or unresolved adopted rollback preparations detected for this tenant.'
        return [pscustomobject]@{Found=$false;TenantId=$ctx.TenantId;Runs=@();PendingAdoptedPreparations=@();Decision='None';ReadyToContinue=$true;ReplayPerformed=$false;RecommendedAction='None'}
    }

    foreach($r in $incomplete){
        $plan=[pscustomobject][ordered]@{
            schemaVersion='1.0';generatedAt=(Get-Date).ToString('o');currentRunId=$RunId;tenantId=$ctx.TenantId;priorRunId=$r.RunId;
            priorRunStatus=$r.Status;priorStage=$r.Stage;journalValid=$r.JournalValid;journalErrors=@($r.JournalErrors);processStillRunning=$r.ProcessStillRunning;
            highestRisk=$r.HighestRisk;semantics=[pscustomobject]@{graphWriteReplayAllowed=$false;freshDiscoveryRequired=$true;serializedRequestReplayAllowed=$false};actions=@($r.Actions)
        }
        Write-DERRecoveryJson -Path (Join-Path $r.RunRoot 'RecoveryPlan.json') -Object $plan
    }

    $summary=[pscustomobject][ordered]@{
        schemaVersion='1.0';generatedAt=(Get-Date).ToString('o');currentRunId=$RunId;tenantId=$ctx.TenantId;mode=$Mode;
        graphWriteReplayAllowed=$false;freshDiscoveryRequired=$true;priorRuns=@($incomplete);pendingAdoptedPreparations=@($pendingPreparations)
    }
    Write-DERRecoveryJson -Path (Join-Path $ctx.RunRoot 'RecoverySummary.json') -Object $summary

    $active=@($incomplete|Where-Object{$_.ProcessStillRunning})
    $invalid=@($incomplete|Where-Object{-not$_.JournalValid -or $_.HighestRisk-eq'Critical'})
    $explicit=@($incomplete|ForEach-Object{@($_.Actions|Where-Object{$_.RequiresExplicitReconcile})})

    Write-DERRecoveryLog -Level WARN -Message ("Detected {0} prior run(s) and {1} unresolved adopted rollback preparation(s) requiring recovery analysis. No prior Graph request will be replayed."-f$incomplete.Count,$pendingPreparations.Count) -Data @{runs=$incomplete.Count;pendingAdoptedPreparations=$pendingPreparations.Count;explicitReconcile=$explicit.Count;invalid=$invalid.Count;active=$active.Count}
    Write-Host ''
    Write-Host 'DER RECOVERY / RESUME ANALYSIS' -ForegroundColor Yellow
    foreach($r in $incomplete){Write-Host (" - {0} | {1}/{2} | Risk: {3} | Commits: {4} | Uncertain: {5}"-f$r.RunId,$r.Status,$r.Stage,$r.HighestRisk,$r.CommittedActions,$r.UncertainActions) -ForegroundColor Yellow}
    Write-Host 'DER never replays a prior Graph write. Resume means fresh discovery + current-state reconciliation + normal dry run.' -ForegroundColor Gray

    if($active.Count){throw ("DER found a prior run whose recorded PowerShell process is still active on this workstation ({0}). Stop the other run before continuing."-f$active[0].RunId)}
    if($invalid.Count){throw ("DER recovery failed closed because prior run {0} has an invalid/contradictory transaction journal. Review RecoveryPlan.json before continuing."-f$invalid[0].RunId)}
    if($pendingPreparations.Count){
        $first=$pendingPreparations[0]
        throw ("DER RECOVERY_REQUIRED: CurrentState contains unresolved DER-Adopted rollback preparation for DER ID '{0}' / ObjectId '{1}' from RunId '{2}' / ActionId '{3}'. DER will not auto-clear this evidence because Microsoft may have accepted the corresponding write. Reconcile the exact Microsoft object and state record before continuing." -f $first.DerId,$first.ObjectId,$first.RunId,$first.ActionId)
    }
    if($Mode-eq'Stop'){throw 'Engineer selected RecoveryMode Stop.'}

    $decision='Analyze'
    $ready=$true
    if($explicit.Count){
        $ready=$false
        if($Mode-eq'Reconcile'){$decision='Reconcile';$ready=$true}
        elseif($Mode-eq'Prompt'){
            Write-Host ''
            Write-Host 'At least one prior action may have reached Microsoft before DER recorded a terminal COMMIT/ROLLBACK.' -ForegroundColor Yellow
            Write-Host 'Recommended: RECONCILE. DER will rediscover Microsoft state; it will NOT replay the old request.' -ForegroundColor Cyan
            $operatorInput=Read-Host 'Type RECONCILE to continue, or STOP to exit'
            if($input.Trim().ToUpperInvariant()-eq'RECONCILE'){$decision='Reconcile';$ready=$true}else{throw 'Engineer stopped DER during recovery reconciliation approval.'}
        }
        elseif($Mode-in@('ResumeSafe','PreserveCompleted')){throw 'ResumeSafe refused: prior journal contains an uncertain tenant-write action. Use Prompt/RECONCILE after reviewing RecoveryPlan.json.'}
    }else{
        if($Mode-eq'Prompt'){
            Write-Host ''
            Write-Host 'No uncertain prior tenant write was found. Completed work will be preserved through fresh discovery.' -ForegroundColor Cyan
            $operatorInput=Read-Host 'Type RESUME to continue, or STOP to exit'
            if($input.Trim().ToUpperInvariant()-ne'RESUME'){throw 'Engineer stopped DER during safe resume approval.'}
            $decision='ResumeSafe'
        }elseif($Mode-in@('ResumeSafe','PreserveCompleted')){$decision='ResumeSafe'}
        elseif($Mode-eq'Reconcile'){$decision='Reconcile'}
    }

    $result=[pscustomobject][ordered]@{
        Found=$true;TenantId=$ctx.TenantId;Runs=$incomplete;PendingAdoptedPreparations=@($pendingPreparations);Decision=$decision;ReadyToContinue=$ready;ReplayPerformed=$false;
        FreshDiscoveryRequired=$true;UncertainActionCount=$explicit.Count;RecommendedAction=if($explicit.Count){'Reconcile current Microsoft state through fresh discovery; never replay journal writes.'}else{'Resume through fresh discovery; preserve committed prior work.'}
    }
    Write-DERRecoveryJson -Path (Join-Path $ctx.RunRoot 'RecoveryDecision.json') -Object $result
    return $result
}

Export-ModuleMember -Function @('Get-DERRecoveryPolicy','Read-DERRecoveryJournalStrict','Get-DERRecoveryActionTimelines','Test-DERPriorRunProcessAlive','Get-DERRecoveryPendingAdoptedPreparations','Get-DERIncompleteRuns','Invoke-DERRecoveryCheck')
