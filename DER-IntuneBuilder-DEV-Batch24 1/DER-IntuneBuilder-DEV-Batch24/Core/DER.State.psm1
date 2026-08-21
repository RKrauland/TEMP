<#
.SYNOPSIS
    DER persistent state and ownership engine.

.DESCRIPTION
    Maintains per-tenant DER ownership, run status, build history, transaction
    journals, and portable state metadata. Microsoft object IDs are the source
    of truth for ownership; names never establish ownership.

.NOTES
    Required parent entry point: Initialize-DERState
#>


# Maintenance notes
# Responsibility: Owns authoritative local tenant state, transaction journal persistence, portable state transfer, atomic replacement, and the per-tenant local mutex.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DERStateContext = $null
[long]$script:DERTransactionSequence = 0

function Test-DERStateCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERStateLog {
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','STEP','OK','WARN','ERROR','CRITICAL')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        $Data
    )
    if (Test-DERStateCommand -Name 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'State' -Message $Message -Data $Data
    }
}

function Get-DERStateContext {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERStateContext) { return $null }
    return [pscustomobject][ordered]@{
        Initialized=$script:DERStateContext.Initialized;RunId=$script:DERStateContext.RunId;TenantId=$script:DERStateContext.TenantId;
        TenantName=$script:DERStateContext.TenantName;RuntimeRoot=$script:DERStateContext.RuntimeRoot;TenantStateRoot=$script:DERStateContext.TenantStateRoot;
        CurrentStatePath=$script:DERStateContext.CurrentStatePath;PreviousStatePath=$script:DERStateContext.PreviousStatePath;
        BuildHistoryPath=$script:DERStateContext.BuildHistoryPath;RunRoot=$script:DERStateContext.RunRoot;RunStatePath=$script:DERStateContext.RunStatePath;
        TransactionJournalPath=$script:DERStateContext.TransactionJournalPath;MutexName=$script:DERStateContext.MutexName;InitializedAt=$script:DERStateContext.InitializedAt
    }
}


function Invoke-DERAtomicFileReplace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [string]$BackupPath,
        [ValidateRange(1,8)][int]$MaxAttempts=4
    )
    for($attempt=1;$attempt -le $MaxAttempts;$attempt++){
        try{
            [System.IO.File]::Replace($SourcePath,$DestinationPath,$(if([string]::IsNullOrWhiteSpace($BackupPath)){$null}else{$BackupPath}),$false)
            return
        }
        catch [System.IO.IOException] {
            if($attempt -ge $MaxAttempts){throw}
            $delayMs=[int](75 * [Math]::Pow(2,$attempt-1))
            Write-DERStateLog -Level WARN -Message ("Atomic state replacement hit a transient I/O error; retrying in {0} ms (attempt {1}/{2})." -f $delayMs,$attempt,$MaxAttempts) -Data @{destination=$DestinationPath;backup=$BackupPath;exception=$_.Exception.Message}
            Start-Sleep -Milliseconds $delayMs
        }
    }
}

function Write-DERAtomicJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object,
        [string]$BackupPath
    )
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $temp = Join-Path $directory ('.{0}.{1}.tmp' -f ([System.IO.Path]::GetFileName($Path)),[guid]::NewGuid().ToString('N'))
    try {
        $json = $Object | ConvertTo-Json -Depth 80
        [System.IO.File]::WriteAllText($temp,$json,[System.Text.UTF8Encoding]::new($false))

        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            # File.Replace preserves an existing destination until the replacement
            # operation commits. When BackupPath is supplied, the same operation
            # also captures the exact previously committed state.
            Invoke-DERAtomicFileReplace -SourcePath $temp -DestinationPath $Path -BackupPath $BackupPath
        }
        else {
            # First creation uses a same-directory rename. No previous committed
            # state exists to preserve or back up on this path.
            [System.IO.File]::Move($temp,$Path)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temp) {
            try { Remove-Item -LiteralPath $temp -Force -ErrorAction Stop }
            catch { Write-DERStateLog -Level WARN -Message ("Unable to remove failed atomic-write temporary file: {0}" -f $_.Exception.Message) -Data @{temp=$temp;target=$Path} }
        }
    }
}

function Add-DERJsonLineState {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)]$Object)
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $json = $Object | ConvertTo-Json -Depth 40 -Compress
    [System.IO.File]::AppendAllText($Path,($json+[Environment]::NewLine),[System.Text.UTF8Encoding]::new($false))
}

function Read-DERJsonFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $text = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json -Depth 80
}

function New-DEREmptyTenantState {
    param([Parameter(Mandatory)][string]$TenantId,[string]$TenantName,[Parameter(Mandatory)][string]$RunId)
    $engineVersion=$null;$baselineVersion=$null
    if (Test-DERStateCommand -Name 'Get-DERLoggingContext') {
        $logContext=Get-DERLoggingContext
        if ($logContext) {$engineVersion=$logContext.EngineVersion;$baselineVersion=$logContext.BaselineVersion}
    }
    return [pscustomobject][ordered]@{
        SchemaVersion='1.0';TenantId=$TenantId;TenantName=$TenantName;CreatedAt=(Get-Date).ToString('o');LastUpdatedAt=(Get-Date).ToString('o');
        LastRunId=$RunId;EngineVersion=$engineVersion;BaselineVersion=$baselineVersion;
        Objects=@();BuildRecipe=$null;Questionnaire=$null;Metadata=[pscustomobject]@{PortableStateVersion='1.0'}
    }
}

function Save-DERCurrentState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State,[switch]$SkipPreviousCopy)
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    if ([string]$State.TenantId -ne $script:DERStateContext.TenantId) { throw 'DER refuses to save state for a different tenant.' }

    $State.LastUpdatedAt=(Get-Date).ToString('o')
    $State.LastRunId=$script:DERStateContext.RunId
    $backupPath=if($SkipPreviousCopy){$null}else{$script:DERStateContext.PreviousStatePath}
    Write-DERAtomicJson -Path $script:DERStateContext.CurrentStatePath -Object $State -BackupPath $backupPath
    return $State
}

function Get-DERCurrentState {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $state=Read-DERJsonFile -Path $script:DERStateContext.CurrentStatePath
    if (-not $state) { throw 'DER current state file is missing or unreadable.' }
    if ([string]$state.TenantId -ne $script:DERStateContext.TenantId) { throw 'DER state tenant ID mismatch.' }
    return $state
}

function Set-DERRunState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Running','Completed','CompletedWithWarnings','Failed','Aborted','RecoveryRequired')][string]$Status,
        [string]$Stage,
        [string]$Message,
        $Data,
        $RecoveryEvidence
    )
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $existing=Read-DERJsonFile -Path $script:DERStateContext.RunStatePath
    if (-not $existing) {
        $existing=[pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$script:DERStateContext.RunId;TenantId=$script:DERStateContext.TenantId;StartedAt=(Get-Date).ToString('o')}
    }
    $existing | Add-Member -NotePropertyName Status -NotePropertyValue $Status -Force
    $existing | Add-Member -NotePropertyName Stage -NotePropertyValue $Stage -Force
    $existing | Add-Member -NotePropertyName Message -NotePropertyValue $Message -Force
    $now=(Get-Date).ToString('o')
    $processStart=$null
    try {$processStart=(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')}
    catch { $processStart=$null;Write-DERStateLog -Level WARN -Message ("Could not capture process start time for run-state metadata: {0}" -f $_.Exception.Message) }
    $existing | Add-Member -NotePropertyName UpdatedAt -NotePropertyValue $now -Force
    $existing | Add-Member -NotePropertyName HeartbeatAt -NotePropertyValue $now -Force
    $existing | Add-Member -NotePropertyName ProcessId -NotePropertyValue $PID -Force
    $existing | Add-Member -NotePropertyName MachineName -NotePropertyValue ([Environment]::MachineName) -Force
    $existing | Add-Member -NotePropertyName ProcessStartTimeUtc -NotePropertyValue $processStart -Force
    $existing | Add-Member -NotePropertyName Data -NotePropertyValue $Data -Force
    if($PSBoundParameters.ContainsKey('RecoveryEvidence')){
        $existing | Add-Member -NotePropertyName RecoveryEvidence -NotePropertyValue $RecoveryEvidence -Force
    }
    Write-DERAtomicJson -Path $script:DERStateContext.RunStatePath -Object $existing
    Add-DERJsonLineState -Path $script:DERStateContext.BuildHistoryPath -Object ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERStateContext.RunId;tenantId=$script:DERStateContext.TenantId;event='RunState';status=$Status;stage=$Stage;message=$Message})
    return $existing
}

function Register-DERTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ActionId,
        [Parameter(Mandatory)][ValidateSet('PLAN','PRECHECK','RECORD_ORIGINAL','EXECUTE','CREATED','UPDATED','ASSIGNED','READBACK','VALIDATE','COMMIT','ROLLBACK','ROLLBACK_VALIDATE','SKIP','FAIL')][string]$Phase,
        [string]$Module,
        [string]$DerId,
        [string]$ObjectId,
        [string]$Message,
        $Data
    )
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $script:DERTransactionSequence++
    $event=[ordered]@{journalVersion='1.1';sequence=$script:DERTransactionSequence;timestamp=(Get-Date).ToString('o');runId=$script:DERStateContext.RunId;tenantId=$script:DERStateContext.TenantId;actionId=$ActionId;phase=$Phase;module=$Module;derId=$DerId;objectId=$ObjectId;message=$Message;data=$Data}
    Add-DERJsonLineState -Path $script:DERStateContext.TransactionJournalPath -Object $event
    if (Test-DERStateCommand -Name 'Write-DERForensicEvent') {
        Write-DERForensicEvent -EventType 'Transaction' -Component $(if([string]::IsNullOrWhiteSpace($Module)){'State'}else{$Module}) -ActionId $ActionId -DerId $DerId -Data $event
    }
    return [pscustomobject]$event
}

function Get-DERStateObject {
    [CmdletBinding()]
    param([string]$ObjectId,[string]$DerId)
    $state=Get-DERCurrentState
    $objects=@($state.Objects)
    if ($ObjectId) { return @($objects | Where-Object {[string]$_.ObjectId -eq $ObjectId} | Select-Object -First 1) }
    if ($DerId) { return @($objects | Where-Object {[string]$_.DerId -eq $DerId} | Select-Object -First 1) }
    throw 'Get-DERStateObject requires ObjectId or DerId.'
}

function Test-DERObjectOwned {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ObjectId)
    $record=Get-DERStateObject -ObjectId $ObjectId
    if (-not $record) { return $false }
    return ([string]$record.OwnershipClass -in @('DER-Owned','DER-Adopted'))
}

function Add-DERStateObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DerId,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$ObjectType,
        [string]$DisplayName,
        [Parameter(Mandatory)][ValidateSet('DER-Owned','DER-Adopted','Customer-Owned')][string]$OwnershipClass,
        [ValidateSet('Planned','Creating','Created','Assigned','Validated','Failed','RolledBack','Adopted','Drifted','Skipped','Retired')][string]$Status='Created',
        [string]$CreatedByRunId,
        [string]$BaselineVersion,
        [string]$DesiredHash,
        $Metadata
    )
    $state=Get-DERCurrentState
    $existingById=@($state.Objects | Where-Object {[string]$_.ObjectId -eq $ObjectId} | Select-Object -First 1)
    if ($existingById) { throw "DER state already contains Microsoft object ID $ObjectId." }
    $existingByDer=@($state.Objects | Where-Object {[string]$_.DerId -eq $DerId} | Select-Object -First 1)
    if ($existingByDer) { throw "DER state already contains DER ID $DerId." }

    $record=[pscustomobject][ordered]@{
        DerId=$DerId;ObjectId=$ObjectId;ObjectType=$ObjectType;DisplayName=$DisplayName;OwnershipClass=$OwnershipClass;Status=$Status;
        CreatedByRunId=if ($CreatedByRunId) {$CreatedByRunId} else {$script:DERStateContext.RunId};CreatedAt=(Get-Date).ToString('o');
        LastValidatedAt=$null;BaselineVersion=$BaselineVersion;DesiredHash=$DesiredHash;Metadata=$Metadata
    }
    $state.Objects=@($state.Objects)+@($record)
    Save-DERCurrentState -State $state | Out-Null
    Add-DERJsonLineState -Path $script:DERStateContext.BuildHistoryPath -Object ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERStateContext.RunId;event='ObjectRegistered';record=$record})
    return $record
}

function Update-DERStateObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [ValidateSet('Planned','Creating','Created','Assigned','Validated','Failed','RolledBack','Adopted','Drifted','Skipped','Retired')][string]$Status,
        [string]$DisplayName,
        [string]$DesiredHash,
        $Metadata,
        [switch]$MarkValidated
    )
    $state=Get-DERCurrentState
    $objects=@($state.Objects)
    $match=@($objects | Where-Object {[string]$_.ObjectId -eq $ObjectId} | Select-Object -First 1)
    if (-not $match) { throw "DER cannot update state for unknown Microsoft object ID $ObjectId." }
    if ($PSBoundParameters.ContainsKey('Status')) {$match.Status=$Status}
    if ($PSBoundParameters.ContainsKey('DisplayName')) {$match.DisplayName=$DisplayName}
    if ($PSBoundParameters.ContainsKey('DesiredHash')) {$match.DesiredHash=$DesiredHash}
    if ($PSBoundParameters.ContainsKey('Metadata')) {$match.Metadata=$Metadata}
    if ($MarkValidated) {$match.LastValidatedAt=(Get-Date).ToString('o');$match.Status='Validated'}
    Save-DERCurrentState -State $state | Out-Null
    return $match
}

function Save-DERQuestionnaireState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Questionnaire)
    $state=Get-DERCurrentState
    $state.Questionnaire=$Questionnaire
    Save-DERCurrentState -State $state | Out-Null
    return $Questionnaire
}

function Save-DERBuildRecipeState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildRecipe)
    $state=Get-DERCurrentState
    $state.BuildRecipe=$BuildRecipe
    Save-DERCurrentState -State $state | Out-Null
    return $BuildRecipe
}


function Get-DERTransactionJournal {
    [CmdletBinding()]
    param([string]$RunId)
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $path=$script:DERStateContext.TransactionJournalPath
    $expectedRunId=$script:DERStateContext.RunId
    if ($RunId -and $RunId -ne $script:DERStateContext.RunId) {
        $expectedRunId=$RunId
        $path=Join-Path (Join-Path (Join-Path $script:DERStateContext.RuntimeRoot 'Runs') $script:DERStateContext.TenantId) (Join-Path $RunId 'TransactionJournal.jsonl')
    }
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $items=New-Object System.Collections.Generic.List[object]
    $lineNumber=0
    foreach($line in Get-Content -LiteralPath $path) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {$event=$line | ConvertFrom-Json -Depth 80}
        catch { throw "DER transaction journal is malformed at line $lineNumber in '$path'. Recovery is required. $($_.Exception.Message)" }
        foreach($required in @('runId','tenantId','actionId','phase')){
            if($event.PSObject.Properties.Name -notcontains $required -or [string]::IsNullOrWhiteSpace([string]$event.$required)){throw "DER transaction journal line $lineNumber is missing required field '$required'. Recovery is required."}
        }
        if([string]$event.runId -ne [string]$expectedRunId){throw "DER transaction journal line $lineNumber has RunId '$($event.runId)' but expected '$expectedRunId'. Recovery is required."}
        if([string]$event.tenantId -ne [string]$script:DERStateContext.TenantId){throw "DER transaction journal line $lineNumber belongs to another tenant. Recovery is required."}
        $items.Add($event)
    }
    return @($items)
}

function Set-DERAdoptedRollbackPreparation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$ActionId,
        [Parameter(Mandatory)]$RollbackMetadata
    )
    $record=Get-DERStateObject -ObjectId $ObjectId
    if(-not $record){throw "DER cannot prepare rollback for unknown Microsoft object ID $ObjectId."}
    if([string]$record.OwnershipClass -ne 'DER-Adopted'){throw "DER refuses adopted-state rollback preparation for ObjectId $ObjectId because ownership is '$($record.OwnershipClass)', not DER-Adopted."}

    $metadata=if($record.Metadata){Copy-DERStateObjectGraph -InputObject $record.Metadata}else{[pscustomobject]@{}}
    if($metadata.PSObject.Properties.Name -contains 'RollbackPreparation'){
        $existing=$metadata.RollbackPreparation
        throw ("DER RECOVERY_REQUIRED: adopted ObjectId {0} already has unresolved rollback preparation from RunId '{1}' / ActionId '{2}'. Resolve that preparation before another tenant write." -f $ObjectId,[string]$existing.RunId,[string]$existing.ActionId)
    }

    # Keep committed metadata describing the last Microsoft state DER actually
    # proved. Desired/current-run values live only inside this transient record
    # until read-back validation succeeds and Clear-DERAdoptedRollbackPreparation
    # promotes them. A crash before Graph therefore cannot move committed state
    # expectations forward ahead of Microsoft.
    $preparation=[pscustomobject][ordered]@{
        RunId=$RunId
        ActionId=$ActionId
        PreparedAt=(Get-Date).ToString('o')
        Eligible=$true
        ChangeMetadata=(Copy-DERStateObjectGraph -InputObject $RollbackMetadata)
    }
    $metadata | Add-Member -NotePropertyName RollbackPreparation -NotePropertyValue $preparation -Force
    Update-DERStateObject -ObjectId $ObjectId -Metadata $metadata -Status Adopted | Out-Null
    return Get-DERStateObject -ObjectId $ObjectId
}

function Clear-DERAdoptedRollbackPreparation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ObjectId,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$ActionId)
    $record=Get-DERStateObject -ObjectId $ObjectId
    if(-not $record){return $null}
    if([string]$record.OwnershipClass -ne 'DER-Adopted'){throw "DER refuses to clear adopted rollback metadata for non-adopted ObjectId $ObjectId."}
    if(-not $record.Metadata -or -not ($record.Metadata.PSObject.Properties.Name -contains 'RollbackPreparation')){
        throw "DER refuses to finalize adopted ObjectId $ObjectId because no rollback preparation is present."
    }
    $preparation=$record.Metadata.RollbackPreparation
    if([string]$preparation.RunId -ne $RunId -or [string]$preparation.ActionId -ne $ActionId){throw 'DER refuses to finalize adopted rollback preparation owned by a different run/action.'}
    if(-not [bool]$preparation.Eligible -or $null -eq $preparation.ChangeMetadata){throw 'DER adopted rollback preparation is incomplete and cannot be finalized.'}

    $metadata=Copy-DERStateObjectGraph -InputObject $record.Metadata
    $changeMetadata=Copy-DERStateObjectGraph -InputObject $preparation.ChangeMetadata
    $rollbackOnly=@('OriginalState','OriginalExpectedSubset','CompositeRestores','UpdateUri','UpdateMethod')
    foreach($property in $changeMetadata.PSObject.Properties){
        if($property.Name -in $rollbackOnly){continue}
        $metadata | Add-Member -NotePropertyName $property.Name -NotePropertyValue (Copy-DERStateObjectGraph -InputObject $property.Value) -Force
    }
    $metadata.PSObject.Properties.Remove('RollbackPreparation')
    # Remove legacy transient fields if a development-state file from an older
    # build is ever encountered; committed metadata must never retain rollback
    # eligibility after successful validation/commit.
    foreach($name in @('RollbackEligibility','OriginalState','OriginalExpectedSubset','CompositeRestores','UpdateUri','UpdateMethod')){
        if($metadata.PSObject.Properties.Name -contains $name){$metadata.PSObject.Properties.Remove($name)}
    }
    Update-DERStateObject -ObjectId $ObjectId -Metadata $metadata -Status Validated | Out-Null
    return Get-DERStateObject -ObjectId $ObjectId
}

function Release-DERTenantStateLock {
    [CmdletBinding()]
    param()
    if($null -eq $script:DERStateContext){return}
    $mutex=$script:DERStateContext.Mutex
    if($mutex){
        try{$mutex.ReleaseMutex()}catch{Write-DERStateLog -Level WARN -Message ("DER tenant mutex release reported: {0}" -f $_.Exception.Message)}
        try{$mutex.Dispose()}catch{Write-DERStateLog -Level WARN -Message ("DER tenant mutex disposal reported: {0}" -f $_.Exception.Message)}
        $script:DERStateContext.Mutex=$null
    }
}

function Remove-DERStateObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ObjectId,[string]$Reason='Removed from active DER ownership state.')
    $state=Get-DERCurrentState
    $record=@($state.Objects | Where-Object {[string]$_.ObjectId -eq $ObjectId} | Select-Object -First 1)
    if (-not $record) { throw "DER cannot remove unknown Microsoft object ID $ObjectId from state." }
    $state.Objects=@($state.Objects | Where-Object {[string]$_.ObjectId -ne $ObjectId})
    Save-DERCurrentState -State $state | Out-Null
    Add-DERJsonLineState -Path $script:DERStateContext.BuildHistoryPath -Object ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERStateContext.RunId;event='ObjectRemovedFromActiveState';reason=$Reason;record=$record})
    return $record
}


function Get-DERPortableStateSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha=[System.Security.Cryptography.SHA256]::Create()
    try {
        $hash=$sha.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($hash)).Replace('-','').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-DERStatePropertyValue {
    param([Parameter(Mandatory)][AllowNull()]$InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $null
}

function Copy-DERStateObjectGraph {
    param([Parameter(Mandatory)]$InputObject)
    return (($InputObject | ConvertTo-Json -Depth 80) | ConvertFrom-Json -Depth 80)
}

function Assert-DERTenantStateStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [string]$ExpectedTenantId
    )
    $errors=New-Object System.Collections.Generic.List[string]
    $tenantId=[string](Get-DERStatePropertyValue -InputObject $State -Name 'TenantId')
    if ([string]::IsNullOrWhiteSpace($tenantId)) { $errors.Add('State TenantId is missing.') }
    elseif ($ExpectedTenantId -and $tenantId -ne $ExpectedTenantId) { $errors.Add("State TenantId $tenantId does not match expected tenant $ExpectedTenantId.") }

    $objects=@(Get-DERStatePropertyValue -InputObject $State -Name 'Objects')
    $seenObjectIds=@{};$seenDerIds=@{}
    foreach ($record in $objects) {
        if ($null -eq $record) { $errors.Add('State contains a null object record.');continue }
        $objectId=[string](Get-DERStatePropertyValue -InputObject $record -Name 'ObjectId')
        $derId=[string](Get-DERStatePropertyValue -InputObject $record -Name 'DerId')
        $ownership=[string](Get-DERStatePropertyValue -InputObject $record -Name 'OwnershipClass')
        $objectType=[string](Get-DERStatePropertyValue -InputObject $record -Name 'ObjectType')
        if ([string]::IsNullOrWhiteSpace($objectId)) { $errors.Add('State object record is missing Microsoft ObjectId.');continue }
        if ([string]::IsNullOrWhiteSpace($derId)) { $errors.Add("State object $objectId is missing DerId.") }
        if ([string]::IsNullOrWhiteSpace($objectType)) { $errors.Add("State object $objectId is missing ObjectType.") }
        if ($ownership -notin @('DER-Owned','DER-Adopted','Customer-Owned')) { $errors.Add("State object $objectId has invalid OwnershipClass '$ownership'.") }
        if ($seenObjectIds.ContainsKey($objectId)) { $errors.Add("Duplicate Microsoft ObjectId found in state: $objectId") } else { $seenObjectIds[$objectId]=$true }
        if (-not [string]::IsNullOrWhiteSpace($derId)) {
            if ($seenDerIds.ContainsKey($derId)) { $errors.Add("Duplicate DerId found in state: $derId") } else { $seenDerIds[$derId]=$true }
        }
    }
    return [pscustomobject][ordered]@{Valid=($errors.Count -eq 0);Errors=@($errors);TenantId=$tenantId;ObjectCount=$objects.Count}
}

function Test-DERPortableState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExpectedTenantId
    )
    $errors=New-Object System.Collections.Generic.List[string]
    $warnings=New-Object System.Collections.Generic.List[string]
    $envelope=$null;$state=$null;$actualHash=$null
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Portable state file not found: $Path" }
        if ([System.IO.Path]::GetExtension($Path) -ne '.derstate') { $warnings.Add('Portable state file does not use the recommended .derstate extension.') }
        $envelope=Read-DERJsonFile -Path $Path
        if (-not $envelope) { throw 'Portable state envelope is empty or unreadable.' }
        if ([string](Get-DERStatePropertyValue $envelope 'EnvelopeSchemaVersion') -ne '1.0') { $errors.Add('Unsupported portable state envelope schema. Expected 1.0.') }
        if ([string](Get-DERStatePropertyValue $envelope 'Format') -ne 'DER.PortableState') { $errors.Add('Portable state Format is not DER.PortableState.') }
        if ([string](Get-DERStatePropertyValue $envelope 'PortableStateVersion') -ne '1.0') { $errors.Add('Unsupported PortableStateVersion. Expected 1.0.') }
        $tenantId=[string](Get-DERStatePropertyValue $envelope 'TenantId')
        if ([string]::IsNullOrWhiteSpace($tenantId)) { $errors.Add('Portable state envelope TenantId is missing.') }
        if ($ExpectedTenantId -and $tenantId -ne $ExpectedTenantId) { $errors.Add("Portable state tenant $tenantId does not match authenticated tenant $ExpectedTenantId.") }
        $encoding=[string](Get-DERStatePropertyValue $envelope 'PayloadEncoding')
        if ($encoding -ne 'base64-utf8-json') { $errors.Add("Unsupported payload encoding '$encoding'.") }
        $payloadBase64=[string](Get-DERStatePropertyValue $envelope 'PayloadBase64')
        if ([string]::IsNullOrWhiteSpace($payloadBase64)) { $errors.Add('Portable state PayloadBase64 is missing.') }
        else {
            try {
                $payloadBytes=[Convert]::FromBase64String($payloadBase64)
                $actualHash=Get-DERPortableStateSha256 -Bytes $payloadBytes
                $integrity=Get-DERStatePropertyValue $envelope 'Integrity'
                $algorithm=[string](Get-DERStatePropertyValue $integrity 'Algorithm')
                $expectedHash=[string](Get-DERStatePropertyValue $integrity 'SHA256')
                if ($algorithm -ne 'SHA256') { $errors.Add("Unsupported integrity algorithm '$algorithm'.") }
                $scope=[string](Get-DERStatePropertyValue $integrity 'Scope')
                if ($scope -ne 'DecodedPayloadBytes') { $errors.Add("Unsupported integrity scope '$scope'.") }
                if ([string]::IsNullOrWhiteSpace($expectedHash)) { $errors.Add('Portable state SHA256 is missing.') }
                elseif ($actualHash -ne $expectedHash.ToLowerInvariant()) { $errors.Add('Portable state payload SHA-256 integrity check failed.') }
                $payloadText=[System.Text.Encoding]::UTF8.GetString($payloadBytes)
                try { $state=$payloadText | ConvertFrom-Json -Depth 80 } catch { $errors.Add("Portable state payload JSON is invalid: $($_.Exception.Message)") }
                if ($state) {
                    $structure=Assert-DERTenantStateStructure -State $state -ExpectedTenantId $tenantId
                    foreach($e in @($structure.Errors)) { $errors.Add($e) }
                    if ([string](Get-DERStatePropertyValue $state 'TenantId') -ne $tenantId) { $errors.Add('Envelope TenantId and payload TenantId do not match.') }
                    $declaredCount=Get-DERStatePropertyValue $envelope 'ObjectCount'
                    if ($null -ne $declaredCount -and [int]$declaredCount -ne [int]$structure.ObjectCount) { $errors.Add('Envelope ObjectCount does not match payload object count.') }
                }
            } catch { $errors.Add("Portable state payload could not be decoded: $($_.Exception.Message)") }
        }
    }
    catch { $errors.Add($_.Exception.Message) }
    return [pscustomobject][ordered]@{Valid=($errors.Count -eq 0);Path=$Path;Errors=@($errors);Warnings=@($warnings);Envelope=$envelope;State=$state;ActualPayloadSHA256=$actualHash}
}

function Export-DERPortableState {
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Force
    )
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $state=Get-DERCurrentState
    $structure=Assert-DERTenantStateStructure -State $state -ExpectedTenantId $script:DERStateContext.TenantId
    if (-not $structure.Valid) { throw ('DER refuses to export invalid tenant state: ' + ($structure.Errors -join '; ')) }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $exportRoot=Join-Path (Join-Path $script:DERStateContext.RuntimeRoot 'Exports') $script:DERStateContext.TenantId
        $name='DER-{0}-{1}.derstate' -f (Get-Date -Format 'yyyyMMdd-HHmmss'),$script:DERStateContext.RunId
        $Path=Join-Path $exportRoot $name
    }
    elseif (Test-Path -LiteralPath $Path -PathType Container) {
        $name='DER-{0}-{1}.derstate' -f (Get-Date -Format 'yyyyMMdd-HHmmss'),$script:DERStateContext.RunId
        $Path=Join-Path $Path $name
    }
    elseif ([System.IO.Path]::GetExtension($Path) -eq '') { $Path += '.derstate' }
    elseif ([System.IO.Path]::GetExtension($Path) -ne '.derstate') { throw 'DER portable state exports must use the .derstate extension.' }

    if ((Test-Path -LiteralPath $Path) -and -not $Force) { throw "DER refuses to overwrite an existing portable state file without -Force: $Path" }
    $directory=Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($directory)) { $directory=(Get-Location).Path;$Path=Join-Path $directory ([System.IO.Path]::GetFileName($Path)) }
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }

    $payloadJson=$state | ConvertTo-Json -Depth 80 -Compress
    $payloadBytes=[System.Text.UTF8Encoding]::new($false).GetBytes($payloadJson)
    $payloadHash=Get-DERPortableStateSha256 -Bytes $payloadBytes
    $envelope=[pscustomobject][ordered]@{
        EnvelopeSchemaVersion='1.0';Format='DER.PortableState';PortableStateVersion='1.0';TenantId=$script:DERStateContext.TenantId;TenantName=$script:DERStateContext.TenantName;
        ExportedAt=(Get-Date).ToString('o');ExportedByRunId=$script:DERStateContext.RunId;EngineVersion=(Get-DERStatePropertyValue $state 'EngineVersion');BaselineVersion=(Get-DERStatePropertyValue $state 'BaselineVersion');
        StateSchemaVersion=(Get-DERStatePropertyValue $state 'SchemaVersion');ObjectCount=[int]$structure.ObjectCount;PayloadEncoding='base64-utf8-json';PayloadBase64=[Convert]::ToBase64String($payloadBytes);
        Integrity=[pscustomobject][ordered]@{Algorithm='SHA256';Scope='DecodedPayloadBytes';SHA256=$payloadHash};
        Notes='Integrity hash detects corruption/tampering but is not a digital signature. Microsoft ObjectId remains the ownership authority.'
    }
    Write-DERAtomicJson -Path $Path -Object $envelope
    Add-DERJsonLineState -Path $script:DERStateContext.BuildHistoryPath -Object ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERStateContext.RunId;tenantId=$script:DERStateContext.TenantId;event='PortableStateExported';path=$Path;sha256=$payloadHash;objectCount=$structure.ObjectCount})
    Write-DERStateLog -Level OK -Message 'Portable DER state exported.' -Data @{path=$Path;tenantId=$script:DERStateContext.TenantId;sha256=$payloadHash;objectCount=$structure.ObjectCount}
    return [pscustomobject][ordered]@{Path=$Path;TenantId=$script:DERStateContext.TenantId;PayloadSHA256=$payloadHash;ObjectCount=$structure.ObjectCount;PortableStateVersion='1.0'}
}

function Merge-DERStateMissingValues {
    param($Local,$Imported)
    if($null -eq $Local){return Copy-DERStateObjectGraph -InputObject $Imported}
    if($null -eq $Imported){return $Local}
    if($Local -is [System.Management.Automation.PSCustomObject] -and $Imported -is [System.Management.Automation.PSCustomObject]){
        foreach($prop in $Imported.PSObject.Properties){
            $localProp=$Local.PSObject.Properties[$prop.Name]
            if(-not $localProp){$Local|Add-Member -NotePropertyName $prop.Name -NotePropertyValue (Copy-DERStateObjectGraph -InputObject $prop.Value);continue}
            $lv=$localProp.Value;$iv=$prop.Value
            if($null -eq $lv -or ($lv -is [string] -and [string]::IsNullOrWhiteSpace($lv))){$localProp.Value=Copy-DERStateObjectGraph -InputObject $iv;continue}
            if($lv -is [System.Management.Automation.PSCustomObject] -and $iv -is [System.Management.Automation.PSCustomObject]){Merge-DERStateMissingValues -Local $lv -Imported $iv|Out-Null}
        }
    }
    return $Local
}

function Merge-DERTenantState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$LocalState,[Parameter(Mandatory)]$ImportedState)
    $localCheck=Assert-DERTenantStateStructure -State $LocalState
    $importCheck=Assert-DERTenantStateStructure -State $ImportedState
    if (-not $localCheck.Valid) { throw ('Local DER state is structurally invalid: ' + ($localCheck.Errors -join '; ')) }
    if (-not $importCheck.Valid) { throw ('Imported DER state is structurally invalid: ' + ($importCheck.Errors -join '; ')) }
    if ($localCheck.TenantId -ne $importCheck.TenantId) { throw 'DER refuses to merge state from different tenants.' }

    $local=Copy-DERStateObjectGraph -InputObject $LocalState
    $imported=Copy-DERStateObjectGraph -InputObject $ImportedState
    $localByObject=@{};$localByDer=@{}
    foreach($r in @($local.Objects)) {$localByObject[[string]$r.ObjectId]=$r;$localByDer[[string]$r.DerId]=$r}

    foreach($r in @($imported.Objects)) {
        $objectId=[string]$r.ObjectId;$derId=[string]$r.DerId
        if ($localByObject.ContainsKey($objectId)) {
            $existing=$localByObject[$objectId]
            if ([string]$existing.DerId -ne $derId) { throw "State merge conflict: Microsoft ObjectId $objectId maps to local DerId '$($existing.DerId)' but imported DerId '$derId'." }
            if ([string]$existing.OwnershipClass -ne [string]$r.OwnershipClass) { throw "State merge conflict: ownership class changed for Microsoft ObjectId $objectId." }
            if ([string]$existing.ObjectType -ne [string]$r.ObjectType) { throw "State merge conflict: object type changed for Microsoft ObjectId $objectId." }
            Merge-DERStateMissingValues -Local $existing -Imported $r | Out-Null
        }
        elseif ($localByDer.ContainsKey($derId)) {
            $existing=$localByDer[$derId]
            throw "State merge conflict: DerId $derId maps to local Microsoft ObjectId '$($existing.ObjectId)' but imported ObjectId '$objectId'."
        }
        else {
            $local.Objects=@($local.Objects)+@(Copy-DERStateObjectGraph -InputObject $r)
            $localByObject[$objectId]=$local.Objects[-1];$localByDer[$derId]=$local.Objects[-1]
        }
    }

    if($null -eq (Get-DERStatePropertyValue $local 'BuildRecipe') -and $null -ne (Get-DERStatePropertyValue $imported 'BuildRecipe')){$local.BuildRecipe=Copy-DERStateObjectGraph -InputObject $imported.BuildRecipe}
    if($null -eq (Get-DERStatePropertyValue $local 'Questionnaire') -and $null -ne (Get-DERStatePropertyValue $imported 'Questionnaire')){$local.Questionnaire=Copy-DERStateObjectGraph -InputObject $imported.Questionnaire}
    if([string]::IsNullOrWhiteSpace([string](Get-DERStatePropertyValue $local 'TenantName')) -and -not [string]::IsNullOrWhiteSpace([string](Get-DERStatePropertyValue $imported 'TenantName'))){$local.TenantName=$imported.TenantName}
    if([string]::IsNullOrWhiteSpace([string](Get-DERStatePropertyValue $local 'BaselineVersion')) -and -not [string]::IsNullOrWhiteSpace([string](Get-DERStatePropertyValue $imported 'BaselineVersion'))){$local.BaselineVersion=$imported.BaselineVersion}
    return $local
}

function New-DERStateImportBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourcePath,[Parameter(Mandatory)][string]$Mode)
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $stamp='{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,6).ToUpperInvariant())
    $backupRoot=Join-Path (Join-Path (Join-Path $script:DERStateContext.TenantStateRoot 'Imports') $script:DERStateContext.RunId) $stamp
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    $currentBackup=Join-Path $backupRoot 'CurrentState.before-import.json'
    if (Test-Path -LiteralPath $script:DERStateContext.CurrentStatePath) { Copy-Item -LiteralPath $script:DERStateContext.CurrentStatePath -Destination $currentBackup -Force }
    $previousBackup=Join-Path $backupRoot 'CurrentState.previous.before-import.json'
    if (Test-Path -LiteralPath $script:DERStateContext.PreviousStatePath) { Copy-Item -LiteralPath $script:DERStateContext.PreviousStatePath -Destination $previousBackup -Force }
    $sourceBackup=Join-Path $backupRoot ([System.IO.Path]::GetFileName($SourcePath))
    Copy-Item -LiteralPath $SourcePath -Destination $sourceBackup -Force
    return [pscustomobject][ordered]@{Root=$backupRoot;CurrentState=$currentBackup;PreviousState=$previousBackup;ImportedFile=$sourceBackup;Mode=$Mode}
}

function Import-DERPortableState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Prompt','Merge','Replace')][string]$Mode='Prompt'
    )
    if ($null -eq $script:DERStateContext) { throw 'DER State has not been initialized.' }
    $validation=Test-DERPortableState -Path $Path -ExpectedTenantId $script:DERStateContext.TenantId
    if (-not $validation.Valid) { throw ('DER portable state import validation failed: ' + ($validation.Errors -join '; ')) }
    $imported=$validation.State
    $local=Get-DERCurrentState

    $effectiveMode=$Mode
    if ($Mode -eq 'Prompt') {
        Write-Host ''
        Write-Host 'DER PORTABLE STATE IMPORT' -ForegroundColor Yellow
        Write-Host (" Tenant: {0}" -f $script:DERStateContext.TenantId) -ForegroundColor Gray
        Write-Host (" Imported objects: {0} | Local objects: {1}" -f @($imported.Objects).Count,@($local.Objects).Count) -ForegroundColor Gray
        Write-Host ' MERGE is recommended. It preserves local-only records and refuses ObjectId/DerId/ownership remaps.' -ForegroundColor Cyan
        Write-Host ' REPLACE discards active local state after DER creates a backup. Microsoft tenant objects are not changed by this import.' -ForegroundColor Gray
        $choice=(Read-Host 'Type MERGE, REPLACE, or STOP').Trim().ToUpperInvariant()
        if ($choice -eq 'STOP') { throw 'Engineer stopped DER portable state import.' }
        if ($choice -notin @('MERGE','REPLACE')) { throw 'Portable state import requires an explicit MERGE or REPLACE decision.' }
        $effectiveMode=if($choice -eq 'MERGE'){'Merge'}else{'Replace'}
    }

    $candidate=if ($effectiveMode -eq 'Merge') { Merge-DERTenantState -LocalState $local -ImportedState $imported } else { Copy-DERStateObjectGraph -InputObject $imported }
    $candidateCheck=Assert-DERTenantStateStructure -State $candidate -ExpectedTenantId $script:DERStateContext.TenantId
    if (-not $candidateCheck.Valid) { throw ('DER refuses to apply imported state: ' + ($candidateCheck.Errors -join '; ')) }

    # Backup is deliberately created only after all preflight validation/conflict
    # checks succeed, but always before CurrentState.json can be changed.
    $backup=New-DERStateImportBackup -SourcePath $Path -Mode $effectiveMode
    if ($null -eq (Get-DERStatePropertyValue $candidate 'Metadata')) { $candidate | Add-Member -NotePropertyName Metadata -NotePropertyValue ([pscustomobject]@{}) -Force }
    $importMeta=[pscustomobject][ordered]@{ImportedAt=(Get-Date).ToString('o');ImportedByRunId=$script:DERStateContext.RunId;Mode=$effectiveMode;SourceFile=[System.IO.Path]::GetFileName($Path);SourcePayloadSHA256=$validation.ActualPayloadSHA256;BackupRoot=$backup.Root}
    $candidate.Metadata | Add-Member -NotePropertyName LastPortableStateImport -NotePropertyValue $importMeta -Force
    Save-DERCurrentState -State $candidate | Out-Null

    $receipt=[pscustomobject][ordered]@{SchemaVersion='1.0';ImportedAt=(Get-Date).ToString('o');RunId=$script:DERStateContext.RunId;TenantId=$script:DERStateContext.TenantId;Mode=$effectiveMode;SourcePath=$Path;SourcePayloadSHA256=$validation.ActualPayloadSHA256;ImportedObjectCount=@($imported.Objects).Count;ResultObjectCount=@($candidate.Objects).Count;Backup=$backup;OwnershipAuthority='Microsoft ObjectId'}
    $receiptPath=Join-Path $backup.Root 'ImportReceipt.json'
    Write-DERAtomicJson -Path $receiptPath -Object $receipt
    Add-DERJsonLineState -Path $script:DERStateContext.BuildHistoryPath -Object ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERStateContext.RunId;tenantId=$script:DERStateContext.TenantId;event='PortableStateImported';mode=$effectiveMode;sourcePayloadSHA256=$validation.ActualPayloadSHA256;backupRoot=$backup.Root;resultObjectCount=@($candidate.Objects).Count})
    Write-DERStateLog -Level OK -Message 'Portable DER state imported after validation and backup.' -Data @{mode=$effectiveMode;backupRoot=$backup.Root;resultObjectCount=@($candidate.Objects).Count}
    return [pscustomobject][ordered]@{Imported=$true;Mode=$effectiveMode;TenantId=$script:DERStateContext.TenantId;ImportedObjectCount=@($imported.Objects).Count;ResultObjectCount=@($candidate.Objects).Count;BackupRoot=$backup.Root;ReceiptPath=$receiptPath;PayloadSHA256=$validation.ActualPayloadSHA256}
}

function Initialize-DERState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $script:DERTransactionSequence=0
    $auth=$null
    if (Test-DERStateCommand -Name 'Get-DERAuthenticationContext') { $auth=Get-DERAuthenticationContext }
    if (-not $auth -or [string]::IsNullOrWhiteSpace([string]$auth.TenantId)) { throw 'DER State initialization requires an authenticated tenant context.' }
    $tenantId=[string]$auth.TenantId;$tenantName=[string]$auth.TenantName
    if($script:DERStateContext){
        if([string]$script:DERStateContext.TenantId -ne $tenantId){throw "DER refuses to switch its state lock from tenant '$($script:DERStateContext.TenantId)' to '$tenantId' within one process."}
        throw 'DER State is already initialized in this process.'
    }

    $mutexName="Global\DER-IntuneBuilder-$tenantId"
    $mutex=[System.Threading.Mutex]::new($false,$mutexName)
    $acquired=$false
    try{$acquired=$mutex.WaitOne(0)}catch [System.Threading.AbandonedMutexException]{$acquired=$true}
    if(-not$acquired){$mutex.Dispose();throw "Another DER process currently owns this tenant's state lock ($tenantId). Stop the other DER process before continuing."}

    $tenantStateRoot=Join-Path (Join-Path $RuntimeRoot 'State') $tenantId
    $runRoot=Join-Path (Join-Path (Join-Path $RuntimeRoot 'Runs') $tenantId) $RunId
    New-Item -ItemType Directory -Path $tenantStateRoot,$runRoot -Force | Out-Null
    $script:DERStateContext=[pscustomobject][ordered]@{
        Initialized=$true;RunId=$RunId;TenantId=$tenantId;TenantName=$tenantName;RuntimeRoot=$RuntimeRoot;TenantStateRoot=$tenantStateRoot;
        CurrentStatePath=(Join-Path $tenantStateRoot 'CurrentState.json');PreviousStatePath=(Join-Path $tenantStateRoot 'CurrentState.previous.json');
        BuildHistoryPath=(Join-Path $tenantStateRoot 'BuildHistory.jsonl');RunRoot=$runRoot;RunStatePath=(Join-Path $runRoot 'RunState.json');
        TransactionJournalPath=(Join-Path $runRoot 'TransactionJournal.jsonl');MutexName=$mutexName;Mutex=$mutex;InitializedAt=Get-Date
    }

    try {
        if (Test-Path -LiteralPath $script:DERStateContext.CurrentStatePath) {
            try {
                $state=Read-DERJsonFile -Path $script:DERStateContext.CurrentStatePath
                if (-not $state) { throw 'CurrentState.json is empty.' }
                if ([string]$state.TenantId -ne $tenantId) { throw 'Stored TenantId does not match current tenant.' }
                Write-DERStateLog -Level OK -Message 'Existing DER tenant state loaded.' -Data @{tenantId=$tenantId;objectCount=@($state.Objects).Count;lastRunId=$state.LastRunId}
            } catch {
                $evidencePath=Join-Path $tenantStateRoot ("CurrentState.corrupt-{0}-{1}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'),$RunId)
                try{Copy-Item -LiteralPath $script:DERStateContext.CurrentStatePath -Destination $evidencePath -Force -ErrorAction Stop}catch{Write-DERStateLog -Level WARN -Message ("Could not copy corrupt CurrentState evidence: {0}" -f $_.Exception.Message)}
                throw "DER CurrentState.json is corrupt/unreadable. DER will NOT restore CurrentState.previous.json because that could rewind ownership state. Evidence copy: '$evidencePath'. Recovery/reconciliation is required. Original error: $($_.Exception.Message)"
            }
        } else {
            $priorStateEvidence=(Test-Path -LiteralPath $script:DERStateContext.PreviousStatePath -PathType Leaf) -or (Test-Path -LiteralPath $script:DERStateContext.BuildHistoryPath -PathType Leaf)
            if($priorStateEvidence){
                throw "DER RECOVERY_REQUIRED: CurrentState.json is missing but prior DER tenant-state evidence exists. DER will not initialize an empty state because that could discard ownership authority. TenantId='$tenantId'."
            }
            $state=New-DEREmptyTenantState -TenantId $tenantId -TenantName $tenantName -RunId $RunId
            Save-DERCurrentState -State $state -SkipPreviousCopy | Out-Null
            Write-DERStateLog -Level OK -Message 'New DER tenant state initialized.' -Data @{tenantId=$tenantId;path=$script:DERStateContext.CurrentStatePath}
        }

        Set-DERRunState -Status Running -Stage 'StateInitialized' -Message 'DER run state initialized and tenant mutex acquired.' | Out-Null
        return Get-DERStateContext
    } catch {
        Release-DERTenantStateLock
        $script:DERStateContext=$null
        throw
    }
}

Export-ModuleMember -Function @(
    'Initialize-DERState','Get-DERStateContext','Get-DERCurrentState','Save-DERCurrentState','Set-DERRunState','Register-DERTransaction',
    'Get-DERStateObject','Test-DERObjectOwned','Add-DERStateObject','Update-DERStateObject','Set-DERAdoptedRollbackPreparation','Clear-DERAdoptedRollbackPreparation','Remove-DERStateObject','Get-DERTransactionJournal','Release-DERTenantStateLock','Save-DERQuestionnaireState','Save-DERBuildRecipeState',
    'Test-DERPortableState','Export-DERPortableState','Import-DERPortableState','Merge-DERTenantState'
)
