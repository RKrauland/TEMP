<#
.SYNOPSIS
    DER module-scoped rollback engine.

.DESCRIPTION
    Reverts only DER-owned changes that can be proven safe to revert. Current-run
    DER-created objects may be deleted after ownership/current-state checks.
    DER-adopted or built-in objects may be restored only when an exact original
    state was recorded and no concurrent external modification is detected.

.NOTES
    Required parent entry point: Invoke-DERModuleRollback
#>


# Maintenance notes
# Responsibility: Primary rollback authority. It may reverse only proven eligible current-run work and must validate the result.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERRollbackCommand {param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERRollbackEngineLog {param([string]$Level,[string]$Message,$Data,[string]$ActionId) if(Test-DERRollbackCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Rollback' -ActionId $ActionId -Message $Message -Data $Data}}



function New-DERRollbackActionException {
    <#
    .SYNOPSIS
        Creates a rollback exception for a known tenant/safety outcome.

    .DESCRIPTION
        Rollback executes inside a safety-critical catch-and-continue loop. Known
        conditions such as concurrent modification, failed delete read-back, or an
        unresolved current-run adoption recipe are ACTION failures: DER executed,
        but automatic restoration could not be proven safe. Unexpected PowerShell,
        state-contract, or runtime defects remain untagged and therefore default to
        ENGINE when Write-DERError records them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$ActionId,
        [string]$DerId
    )
    if (Test-DERRollbackCommand 'New-DERFailureException') {
        return New-DERFailureException -Message $Message -FailureKind Action -Component 'Rollback' -ActionId $ActionId -DerId $DerId
    }
    $exception=[System.InvalidOperationException]::new($Message)
    $exception.Data['DERFailureKind']='Action'
    $exception.Data['DERComponent']='Rollback'
    if(-not [string]::IsNullOrWhiteSpace($ActionId)){$exception.Data['DERActionId']=$ActionId}
    if(-not [string]::IsNullOrWhiteSpace($DerId)){$exception.Data['DERDerId']=$DerId}
    return $exception
}

function Get-DERRollbackPropertyValue {
    param($InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $null
}

function Test-DERRollbackCurrentState {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$ActionId)
    $metadata=Get-DERRollbackPropertyValue -InputObject $Record -Name 'Metadata'
    $validationUri=[string](Get-DERRollbackPropertyValue -InputObject $metadata -Name 'ValidationUri')
    if ([string]::IsNullOrWhiteSpace($validationUri)) {
        return [pscustomobject]@{Safe=$false;Reason='No validation URI is recorded for this object.';Current=$null}
    }
    $apiVersion=[string](Get-DERRollbackPropertyValue -InputObject $metadata -Name 'ApiVersion')
    if ([string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion='v1.0' }
    try {
        $current=Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion $apiVersion -Component 'Rollback' -ActionId $ActionId
    }
    catch {
        return [pscustomobject]@{Safe=$false;Reason=('Unable to reread current object before rollback: '+$_.Exception.Message);Current=$null}
    }
    $expectedSubset=Get-DERRollbackPropertyValue -InputObject $metadata -Name 'ExpectedSubset'
    if ($null -ne $expectedSubset -and (Test-DERRollbackCommand 'Test-DERExpectedSubset')) {
        $comparison=Test-DERExpectedSubset -Actual $current -Expected $expectedSubset
        if (-not $comparison.Success) {
            return [pscustomobject]@{Safe=$false;Reason='Concurrent/external modification detected; current object no longer matches DER expected state.';Current=$current;Differences=$comparison.Differences}
        }
    }
    return [pscustomobject]@{Safe=$true;Reason='Current state matches expected DER-managed state.';Current=$current}
}

function Test-DERRollbackSubsetMatch {
    param($Actual,$Expected)
    if($null -eq $Expected){return $false}
    if(-not (Test-DERRollbackCommand 'Test-DERExpectedSubset')){throw 'DER rollback requires Test-DERExpectedSubset for safe state comparison.'}
    $comparison=Test-DERExpectedSubset -Actual $Actual -Expected $Expected
    return [bool]$comparison.Success
}


function Get-DERAdoptedMetadataAfterRollback {
    param([Parameter(Mandatory)]$Metadata)
    # Committed metadata intentionally remained at the last proven Microsoft
    # state while the current-run desired/rollback recipe lived under
    # RollbackPreparation. Successful rollback therefore only needs to discard
    # that transient preparation; the committed expectations are already the
    # correct post-rollback expectations.
    $restored=(($Metadata|ConvertTo-Json -Depth 100)|ConvertFrom-Json -Depth 100)
    if($restored.PSObject.Properties.Name -contains 'RollbackPreparation'){$restored.PSObject.Properties.Remove('RollbackPreparation')}
    foreach($name in @('RollbackEligibility','OriginalState','OriginalExpectedSubset','CompositeRestores','UpdateUri','UpdateMethod')){
        if($restored.PSObject.Properties.Name -contains $name){$restored.PSObject.Properties.Remove($name)}
    }
    return $restored
}

function Get-DERPreparedRollbackMetadata {
    param([Parameter(Mandatory)]$Metadata,[Parameter(Mandatory)]$Preparation)
    $effective=(($Metadata|ConvertTo-Json -Depth 100)|ConvertFrom-Json -Depth 100)
    if($effective.PSObject.Properties.Name -contains 'RollbackPreparation'){$effective.PSObject.Properties.Remove('RollbackPreparation')}
    $changeMetadata=Get-DERRollbackPropertyValue -InputObject $Preparation -Name 'ChangeMetadata'
    if ($null -eq $changeMetadata) { throw 'Rollback preparation is missing ChangeMetadata.' }
    foreach($property in $changeMetadata.PSObject.Properties){
        $effective | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
    }
    return $effective
}

function Invoke-DERModuleRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [string]$Reason='DER module rollback requested.',
        [string]$DerId,
        [string]$ObjectId
    )
    if (-not (Test-DERRollbackCommand 'Get-DERCurrentState')) { throw 'DER State engine is required for rollback.' }

    $started=Get-Date
    $results=New-Object System.Collections.Generic.List[object]
    $state=Get-DERCurrentState
    $stateObjects=@(Get-DERRollbackPropertyValue -InputObject $state -Name 'Objects')

    # Rollback is scoped only to tenant changes prepared/performed by THIS run.
    # Missing optional metadata never becomes a StrictMode exception and never
    # makes a historical object rollback eligible.
    $targets=@($stateObjects | Where-Object {
        $metadata=Get-DERRollbackPropertyValue -InputObject $_ -Name 'Metadata'
        $moduleName=[string](Get-DERRollbackPropertyValue -InputObject $metadata -Name 'Module')
        $status=[string](Get-DERRollbackPropertyValue -InputObject $_ -Name 'Status')
        $recordDerId=[string](Get-DERRollbackPropertyValue -InputObject $_ -Name 'DerId')
        $recordObjectId=[string](Get-DERRollbackPropertyValue -InputObject $_ -Name 'ObjectId')
        $ownership=[string](Get-DERRollbackPropertyValue -InputObject $_ -Name 'OwnershipClass')

        if ($null -eq $metadata -or $moduleName -ne $Module -or $status -in @('RolledBack','Retired')) { return $false }
        if (-not [string]::IsNullOrWhiteSpace($DerId) -and $recordDerId -ne $DerId) { return $false }
        if (-not [string]::IsNullOrWhiteSpace($ObjectId) -and $recordObjectId -ne $ObjectId) { return $false }
        if ($ownership -eq 'DER-Owned') {
            return ([string](Get-DERRollbackPropertyValue -InputObject $_ -Name 'CreatedByRunId') -eq $RunId)
        }
        if ($ownership -eq 'DER-Adopted') {
            $preparation=Get-DERRollbackPropertyValue -InputObject $metadata -Name 'RollbackPreparation'
            if ($null -eq $preparation) { return $false }
            return ([bool](Get-DERRollbackPropertyValue -InputObject $preparation -Name 'Eligible') -and [string](Get-DERRollbackPropertyValue -InputObject $preparation -Name 'RunId') -eq $RunId)
        }
        return $false
    })

    if (-not [string]::IsNullOrWhiteSpace($DerId) -and -not [string]::IsNullOrWhiteSpace($ObjectId) -and $targets.Count -gt 1) {
        throw 'Exact rollback filter matched more than one state object; automatic rollback refused.'
    }
    Write-DERRollbackEngineLog -Level STEP -Message ("Starting rollback for module {0}; {1} DER-managed object(s) evaluated." -f $Module,$targets.Count) -Data @{reason=$Reason;runId=$RunId;derId=$DerId;objectId=$ObjectId}

    $rollbackWindowOpened=$false
    try {
        if (Test-DERRollbackCommand 'Set-DERGraphRollbackWriteWindow') {
            Set-DERGraphRollbackWriteWindow -Enabled $true -Reason "Central rollback for module $Module / run $RunId" | Out-Null
            $rollbackWindowOpened=$true
        }

        foreach ($record in $targets) {
            $recordDerId=[string](Get-DERRollbackPropertyValue -InputObject $record -Name 'DerId')
            $recordObjectId=[string](Get-DERRollbackPropertyValue -InputObject $record -Name 'ObjectId')
            $displayName=[string](Get-DERRollbackPropertyValue -InputObject $record -Name 'DisplayName')
            $ownership=[string](Get-DERRollbackPropertyValue -InputObject $record -Name 'OwnershipClass')
            $createdByRunId=[string](Get-DERRollbackPropertyValue -InputObject $record -Name 'CreatedByRunId')
            $metadata=Get-DERRollbackPropertyValue -InputObject $record -Name 'Metadata'

            if ([string]::IsNullOrWhiteSpace($recordDerId) -or [string]::IsNullOrWhiteSpace($recordObjectId) -or [string]::IsNullOrWhiteSpace($ownership)) {
                throw 'Rollback encountered a malformed DER state object missing DerId, ObjectId, or OwnershipClass.'
            }

            $actionId=if (Test-DERRollbackCommand 'New-DERActionId') { New-DERActionId -Component 'ROLLBACK' } else { "RB-$recordDerId" }
            $result=[ordered]@{DerId=$recordDerId;ObjectId=$recordObjectId;DisplayName=$displayName;Ownership=$ownership;Status='Skipped';Message=$null;ActionId=$actionId}

            try {
                if ($ownership -eq 'DER-Owned') {
                    if ($createdByRunId -ne $RunId) {
                        $result.Status='ManualRequired'
                        $result.Message='DER-Owned object was not created by the current run; automatic delete rollback is refused.'
                        throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                    }

                    $deleteUri=[string](Get-DERRollbackPropertyValue -InputObject $metadata -Name 'DeleteUri')
                    $validationUri=[string](Get-DERRollbackPropertyValue -InputObject $metadata -Name 'ValidationUri')
                    $apiVersion=[string](Get-DERRollbackPropertyValue -InputObject $metadata -Name 'ApiVersion')
                    $expectedSubset=Get-DERRollbackPropertyValue -InputObject $metadata -Name 'ExpectedSubset'
                    if ([string]::IsNullOrWhiteSpace($deleteUri) -or [string]::IsNullOrWhiteSpace($validationUri)) { throw 'Delete/validation URI is not recorded; automatic rollback refused.' }
                    if ([string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion='v1.0' }

                    $current=Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion $apiVersion -Component 'Rollback' -ActionId $actionId -AllowNotFound
                    if ($null -eq $current) {
                        if (Test-DERRollbackCommand 'Remove-DERStateObject') { Remove-DERStateObject -ObjectId $recordObjectId -Reason "Rollback reconciliation: object already absent. $Reason" | Out-Null }
                        if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK_VALIDATE -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Current-run DER-owned object was already absent; genuine not-found read-back proved no delete remained.' | Out-Null }
                        $result.Status='RolledBack'
                        $result.Message='Object was already absent; genuine not-found read-back proved no delete remained.'
                    }
                    else {
                        if ($null -ne $expectedSubset -and -not (Test-DERRollbackSubsetMatch -Actual $current -Expected $expectedSubset)) {
                            $result.Status='ManualRequired'
                            $result.Message='Concurrent/external modification detected; current object no longer matches DER expected state.'
                            throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                        }
                        if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Deleting current-run DER-owned object during rollback.' | Out-Null }
                        Invoke-DERGraphRequest -Method DELETE -Uri $deleteUri -ApiVersion $apiVersion -Component 'Rollback' -DerId $recordDerId -ActionId $actionId | Out-Null
                        $readBack=Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion $apiVersion -Component 'Rollback' -ActionId $actionId -AllowNotFound
                        if ($null -ne $readBack) { throw (New-DERRollbackActionException -Message 'Rollback delete returned, but object still resolves on read-back.' -ActionId $actionId -DerId $recordDerId) }
                        if (Test-DERRollbackCommand 'Remove-DERStateObject') { Remove-DERStateObject -ObjectId $recordObjectId -Reason "Rollback: $Reason" | Out-Null }
                        if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK_VALIDATE -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Rollback deletion validated by a genuine not-found read-back.' | Out-Null }
                        $result.Status='RolledBack'
                        $result.Message='Current-run DER-owned object deleted and genuine not-found read-back proved deletion.'
                    }
                }
                elseif ($ownership -eq 'DER-Adopted') {
                    $preparation=Get-DERRollbackPropertyValue -InputObject $metadata -Name 'RollbackPreparation'
                    if ($null -eq $preparation) {
                        $result.Status='Skipped'
                        $result.Message='No current-run adopted-object write was prepared; historical adopted state is not rollback eligible.'
                    }
                    else {
                        $eligible=[bool](Get-DERRollbackPropertyValue -InputObject $preparation -Name 'Eligible')
                        $preparedRunId=[string](Get-DERRollbackPropertyValue -InputObject $preparation -Name 'RunId')
                        $preparedActionId=[string](Get-DERRollbackPropertyValue -InputObject $preparation -Name 'ActionId')
                        $changeMetadata=Get-DERRollbackPropertyValue -InputObject $preparation -Name 'ChangeMetadata'
                        if (-not $eligible -or $preparedRunId -ne $RunId -or [string]::IsNullOrWhiteSpace($preparedActionId) -or $null -eq $changeMetadata) {
                            $result.Status='ManualRequired'
                            $result.Message='DER-Adopted object has unresolved rollback preparation that is not eligible for this exact current run. Recovery/reconciliation is required.'
                            throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                        }

                        $rollbackMetadata=Get-DERPreparedRollbackMetadata -Metadata $metadata -Preparation $preparation
                        $compositeRestores=Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'CompositeRestores'
                        if ($null -ne $compositeRestores -and @($compositeRestores).Count -gt 0) {
                            $restores=@($compositeRestores)
                            $needsRestore=New-Object System.Collections.Generic.List[object]
                            foreach ($restore in $restores) {
                                $restoreUri=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'Uri')
                                $restoreApi=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'ApiVersion')
                                $expectedCurrent=Get-DERRollbackPropertyValue -InputObject $restore -Name 'ExpectedCurrentSubset'
                                $originalExpected=Get-DERRollbackPropertyValue -InputObject $restore -Name 'OriginalExpectedSubset'
                                $originalState=Get-DERRollbackPropertyValue -InputObject $restore -Name 'OriginalState'
                                if ([string]::IsNullOrWhiteSpace($restoreUri)) { throw 'Composite rollback entry is missing Uri.' }
                                if ([string]::IsNullOrWhiteSpace($restoreApi)) { $restoreApi='v1.0' }
                                if ($null -eq $originalExpected) { $originalExpected=$originalState }

                                $current=Invoke-DERGraphRequest -Method GET -Uri $restoreUri -ApiVersion $restoreApi -Component 'Rollback' -ActionId $actionId
                                $matchesDesired=if ($null -ne $expectedCurrent) { Test-DERRollbackSubsetMatch -Actual $current -Expected $expectedCurrent } else { $false }
                                $matchesOriginal=if ($null -ne $originalExpected) { Test-DERRollbackSubsetMatch -Actual $current -Expected $originalExpected } else { $false }
                                if ($matchesOriginal) { continue }
                                if ($matchesDesired) { $needsRestore.Add($restore); continue }
                                $result.Status='ManualRequired'
                                $result.Message=("Composite rollback refused because '{0}' matches neither DER's desired state nor the recorded original state; concurrent/external modification is possible." -f $restoreUri)
                                throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                            }

                            if ($needsRestore.Count -gt 0) {
                                if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Restoring only composite entries proven to still contain current-run DER changes.' -Data @{restoreCount=$needsRestore.Count;preparedActionId=$preparedActionId} | Out-Null }
                                for ($index=$needsRestore.Count-1; $index -ge 0; $index--) {
                                    $restore=$needsRestore[$index]
                                    $restoreMethod=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'Method')
                                    $restoreUri=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'Uri')
                                    $restoreApi=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'ApiVersion')
                                    $originalState=Get-DERRollbackPropertyValue -InputObject $restore -Name 'OriginalState'
                                    if ([string]::IsNullOrWhiteSpace($restoreMethod)) { $restoreMethod='PATCH' }
                                    if ([string]::IsNullOrWhiteSpace($restoreApi)) { $restoreApi='v1.0' }
                                    Invoke-DERGraphRequest -Method $restoreMethod -Uri $restoreUri -ApiVersion $restoreApi -Body $originalState -Component 'Rollback' -DerId $recordDerId -ActionId $actionId | Out-Null
                                }
                            }

                            foreach ($restore in $restores) {
                                $restoreUri=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'Uri')
                                $restoreApi=[string](Get-DERRollbackPropertyValue -InputObject $restore -Name 'ApiVersion')
                                $originalExpected=Get-DERRollbackPropertyValue -InputObject $restore -Name 'OriginalExpectedSubset'
                                if ($null -eq $originalExpected) { $originalExpected=Get-DERRollbackPropertyValue -InputObject $restore -Name 'OriginalState' }
                                if ([string]::IsNullOrWhiteSpace($restoreApi)) { $restoreApi='v1.0' }
                                $verify=Invoke-DERGraphRequest -Method GET -Uri $restoreUri -ApiVersion $restoreApi -Component 'Rollback' -ActionId $actionId
                                if ($null -eq $originalExpected -or -not (Test-DERRollbackSubsetMatch -Actual $verify -Expected $originalExpected)) { throw (New-DERRollbackActionException -Message 'Composite rollback original-state read-back validation failed.' -ActionId $actionId -DerId $recordDerId) }
                            }

                            if (Test-DERRollbackCommand 'Update-DERStateObject') { $restoredMetadata=Get-DERAdoptedMetadataAfterRollback -Metadata $metadata; Update-DERStateObject -ObjectId $recordObjectId -Metadata $restoredMetadata -Status RolledBack | Out-Null }
                            if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK_VALIDATE -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Composite rollback validated the recorded original state for every entry; transient current-run preparation was removed.' -Data @{preparedActionId=$preparedActionId;writesPerformed=$needsRestore.Count} | Out-Null }
                            $result.Status='RolledBack'
                            $result.Message=if ($needsRestore.Count) { 'Current-run composite changes restored and original state read-back validated.' } else { 'All composite entries already matched their recorded original state; no rollback writes were needed.' }
                        }
                        else {
                            $originalState=Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'OriginalState'
                            $updateUri=[string](Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'UpdateUri')
                            $validationUri=[string](Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'ValidationUri')
                            if ($null -ne $originalState -and -not [string]::IsNullOrWhiteSpace($updateUri) -and -not [string]::IsNullOrWhiteSpace($validationUri)) {
                                $apiVersion=[string](Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'ApiVersion')
                                $expectedSubset=Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'ExpectedSubset'
                                $originalExpected=Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'OriginalExpectedSubset'
                                $updateMethod=[string](Get-DERRollbackPropertyValue -InputObject $rollbackMetadata -Name 'UpdateMethod')
                                if ([string]::IsNullOrWhiteSpace($apiVersion)) { $apiVersion='v1.0' }
                                if ([string]::IsNullOrWhiteSpace($updateMethod)) { $updateMethod='PATCH' }
                                if ($null -eq $originalExpected) { $originalExpected=$originalState }

                                $current=Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion $apiVersion -Component 'Rollback' -ActionId $actionId
                                $desiredMatches=if ($null -ne $expectedSubset) { Test-DERRollbackSubsetMatch -Actual $current -Expected $expectedSubset } else { $false }
                                $originalMatches=if ($null -ne $originalExpected) { Test-DERRollbackSubsetMatch -Actual $current -Expected $originalExpected } else { $false }
                                if (-not $desiredMatches -and -not $originalMatches) {
                                    $result.Status='ManualRequired'
                                    $result.Message='Adopted-object rollback refused because current state matches neither DER desired state nor recorded original state; concurrent/external modification is possible.'
                                    throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                                }
                                if ($desiredMatches) {
                                    if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Restoring current-run DER-adopted/built-in object original state.' -Data @{preparedActionId=$preparedActionId} | Out-Null }
                                    Invoke-DERGraphRequest -Method $updateMethod -Uri $updateUri -ApiVersion $apiVersion -Body $originalState -Component 'Rollback' -DerId $recordDerId -ActionId $actionId | Out-Null
                                }
                                $verify=Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion $apiVersion -Component 'Rollback' -ActionId $actionId
                                if ($null -eq $originalExpected -or -not (Test-DERRollbackSubsetMatch -Actual $verify -Expected $originalExpected)) { throw (New-DERRollbackActionException -Message 'Adopted-object rollback original-state read-back validation failed.' -ActionId $actionId -DerId $recordDerId) }
                                if (Test-DERRollbackCommand 'Update-DERStateObject') { $restoredMetadata=Get-DERAdoptedMetadataAfterRollback -Metadata $metadata; Update-DERStateObject -ObjectId $recordObjectId -Metadata $restoredMetadata -Status RolledBack | Out-Null }
                                if (Test-DERRollbackCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase ROLLBACK_VALIDATE -Module $Module -DerId $recordDerId -ObjectId $recordObjectId -Message 'Adopted-object rollback validated recorded original state; transient current-run preparation was removed.' -Data @{preparedActionId=$preparedActionId;writePerformed=[bool]$desiredMatches} | Out-Null }
                                $result.Status='RolledBack'
                                $result.Message=if ($desiredMatches) { 'Current-run original recorded state restored and read-back validated.' } else { 'Object already matched its recorded original state; no rollback write was needed.' }
                            }
                            else {
                                $result.Status='ManualRequired'
                                $result.Message='DER-Adopted object has an incomplete current-run rollback recipe.'
                                throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                            }
                        }
                    }
                }
                else {
                    $result.Status='ManualRequired'
                    $result.Message='Object is not eligible for automatic rollback under DER ownership rules.'
                    throw (New-DERRollbackActionException -Message $result.Message -ActionId $actionId -DerId $recordDerId)
                }
            }
            catch {
                $rollbackError=$_
                if ($result.Status -ne 'ManualRequired') { $result.Status='Failed'; $result.Message=$rollbackError.Exception.Message }
                $failureKind='Engine'
                if (Test-DERRollbackCommand 'Get-DERFailureKindFromErrorRecord') {
                    $failureKind=Get-DERFailureKindFromErrorRecord -ErrorRecord $rollbackError
                } elseif ($rollbackError.Exception -and $rollbackError.Exception.Data -and $rollbackError.Exception.Data.Contains('DERFailureKind')) {
                    $candidate=[string]$rollbackError.Exception.Data['DERFailureKind']
                    if($candidate -in @('Action','Engine')){$failureKind=$candidate}
                }
                $result['FailureKind']=$failureKind
                if (Test-DERRollbackCommand 'Write-DERError') {
                    Write-DERError -ErrorRecord $rollbackError -Component 'Rollback' -ActionId $actionId -DerId $recordDerId -FailureKind $failureKind -Message $result.Message
                }
            }

            $output=[pscustomobject]$result
            $results.Add($output)
            if (Test-DERRollbackCommand 'Write-DERRollbackLog') { Write-DERRollbackLog -ActionId $actionId -Module $Module -DerId $recordDerId -Status $output.Status -Message $output.Message -Data $output }
        }
    }
    finally {
        if ($rollbackWindowOpened -and (Test-DERRollbackCommand 'Set-DERGraphRollbackWriteWindow')) {
            try { Set-DERGraphRollbackWriteWindow -Enabled $false -Reason "Central rollback for $Module completed." | Out-Null }
            catch { Write-DERRollbackEngineLog -Level CRITICAL -Message ("Unable to close rollback-only write window: {0}" -f $_.Exception.Message) }
        }
    }

    $completed=Get-Date
    $summary=[pscustomobject]@{
        RolledBack=@($results | Where-Object {$_.Status -eq 'RolledBack'}).Count
        Failed=@($results | Where-Object {$_.Status -eq 'Failed'}).Count
        ManualRequired=@($results | Where-Object {$_.Status -eq 'ManualRequired'}).Count
        Skipped=@($results | Where-Object {$_.Status -eq 'Skipped'}).Count
    }
    $report=[pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$RunId;Module=$Module;Reason=$Reason;StartedAt=$started;CompletedAt=$completed;Summary=$summary;Results=@($results)}
    $context=if (Test-DERRollbackCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($context) {
        $runRoot=[string](Get-DERRollbackPropertyValue -InputObject $context -Name 'RunRoot')
        if (-not [string]::IsNullOrWhiteSpace($runRoot)) {
            $directory=Join-Path $runRoot 'Rollback'
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            $report | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath (Join-Path $directory ("Rollback-$Module.json")) -Encoding UTF8
        }
    }
    Write-DERRollbackEngineLog -Level $(if ($summary.Failed -gt 0 -or $summary.ManualRequired -gt 0) {'WARN'} else {'OK'}) -Message ("Rollback for {0} complete: {1} rolled back, {2} failed, {3} manual." -f $Module,$summary.RolledBack,$summary.Failed,$summary.ManualRequired) -Data $summary
    return $report
}

Export-ModuleMember -Function @('Test-DERRollbackCurrentState','Test-DERRollbackSubsetMatch','Get-DERAdoptedMetadataAfterRollback','Get-DERPreparedRollbackMetadata','Invoke-DERModuleRollback')
