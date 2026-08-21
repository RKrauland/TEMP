<#
.SYNOPSIS
    DER post-build validation engine.

.DESCRIPTION
    Reads DER-managed objects back from Microsoft Graph after workload execution,
    validates expected state without trusting the original create/update response,
    records validation results, and marks successfully validated DER state records.

.NOTES
    Required parent entry point: Invoke-DERPostBuildValidation
#>


# Maintenance notes
# Responsibility: Common existing-object/post-build validation authority. State is never treated as proof; Microsoft must be reread.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERValidationCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERValidationEngineLog {
    param([string]$Level,[string]$Message,$Data,[string]$ActionId)
    if (Test-DERValidationCommand 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Validation' -ActionId $ActionId -Message $Message -Data $Data
    }
}


function New-DERValidationActionException {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$ActionId,
        [string]$DerId
    )
    $exception=[System.InvalidOperationException]::new($Message)
    $exception.Data['DERFailureKind']='Action'
    if(-not [string]::IsNullOrWhiteSpace($ActionId)){$exception.Data['DERActionId']=$ActionId}
    if(-not [string]::IsNullOrWhiteSpace($DerId)){$exception.Data['DERDerId']=$DerId}
    $exception.Data['DERComponent']='Validation'
    return $exception
}

function ConvertTo-DERComparableValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o=[ordered]@{}
        foreach($k in @($Value.Keys | Sort-Object)) {$o[$k]=ConvertTo-DERComparableValue $Value[$k]}
        return [pscustomobject]$o
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value | ForEach-Object {ConvertTo-DERComparableValue $_})
    }
    $o=[ordered]@{}
    foreach($p in @($Value.PSObject.Properties | Where-Object {$_.MemberType -in @('NoteProperty','Property')} | Sort-Object Name)) {
        if ($p.Name -in @('@odata.context','@odata.etag','createdDateTime','modifiedDateTime','deletedDateTime')) {continue}
        $o[$p.Name]=ConvertTo-DERComparableValue $p.Value
    }
    return [pscustomobject]$o
}

function Test-DERExpectedSubset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [string]$Path='$'
    )

    function Compare-Node {
        param($A,$E,[string]$P)
        $local=New-Object System.Collections.Generic.List[object]
        if ($null -eq $E) {
            if ($null -ne $A) {$local.Add([pscustomobject]@{Path=$P;Expected=$null;Actual=$A})}
            return @($local)
        }
        if ($E -is [System.Collections.IDictionary] -or ($E.PSObject -and @($E.PSObject.Properties).Count -gt 0 -and -not ($E -is [string]) -and -not ($E -is [ValueType]) -and -not ($E -is [System.Collections.IEnumerable]))) {
            $props = if ($E -is [System.Collections.IDictionary]) {@($E.Keys)} else {@($E.PSObject.Properties.Name)}
            foreach($name in $props) {
                $expectedValue = if ($E -is [System.Collections.IDictionary]) {$E[$name]} else {$E.$name}
                $actualProp=$null
                if ($A -is [System.Collections.IDictionary]) {if ($A.Contains($name)) {$actualProp=$A[$name]} else {$local.Add([pscustomobject]@{Path="$P.$name";Expected=$expectedValue;Actual='[MISSING]'});continue}}
                elseif ($null -ne $A -and $A.PSObject.Properties.Name -contains $name) {$actualProp=$A.$name}
                else {$local.Add([pscustomobject]@{Path="$P.$name";Expected=$expectedValue;Actual='[MISSING]'});continue}
                foreach($difference in @(Compare-Node -A $actualProp -E $expectedValue -P "$P.$name")){$local.Add($difference)}
            }
            return @($local)
        }
        if ($E -is [System.Collections.IEnumerable] -and -not ($E -is [string])) {
            $ea=@($E);$aa=@($A)
            if ($ea.Count -ne $aa.Count) {$local.Add([pscustomobject]@{Path=$P;Expected=$ea;Actual=$aa});return @($local)}

            # Microsoft Graph collection ordering is not a state invariant for the
            # arrays DER records (reviewers, enabled rules, include/exclude lists,
            # etc.). Match each expected entry to one unused actual entry using the
            # same recursive subset comparison rather than trusting array order.
            $used=[System.Collections.Generic.HashSet[int]]::new()
            for($i=0;$i -lt $ea.Count;$i++){
                $matched=$false
                for($j=0;$j -lt $aa.Count;$j++){
                    if($used.Contains($j)){continue}
                    $candidate=@(Compare-Node -A $aa[$j] -E $ea[$i] -P "$P[$i]")
                    if($candidate.Count -eq 0){$null=$used.Add($j);$matched=$true;break}
                }
                if(-not$matched){$local.Add([pscustomobject]@{Path="$P[$i]";Expected=$ea[$i];Actual=$aa})}
            }
            return @($local)
        }
        if ([string]$A -cne [string]$E) {$local.Add([pscustomobject]@{Path=$P;Expected=$E;Actual=$A})}
        return @($local)
    }

    $differences=@(Compare-Node -A $Actual -E $Expected -P $Path)
    return [pscustomobject]@{Success=($differences.Count -eq 0);Differences=$differences}
}

function Get-DERValidationMetadataValue {
    param($Metadata,[Parameter(Mandatory)][string]$Name)
    if($null -eq $Metadata){return $null}
    if($Metadata -is [System.Collections.IDictionary]){if($Metadata.Contains($Name)){return $Metadata[$Name]};return $null}
    if($Metadata.PSObject.Properties.Name -contains $Name){return $Metadata.$Name}
    return $null
}

function Test-DERAssignmentContainsGroup {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Assignments,[Parameter(Mandatory)][string]$GroupId)
    foreach($assignment in @($Assignments)){
        if($null -eq $assignment){continue}
        $target=Get-DERValidationMetadataValue -Metadata $assignment -Name 'target'
        if($target){
            foreach($propertyName in @('groupId','entraObjectId')){
                $targetId=Get-DERValidationMetadataValue -Metadata $target -Name $propertyName
                if(-not [string]::IsNullOrWhiteSpace([string]$targetId) -and [string]$targetId -eq $GroupId){return $true}
            }
        }
    }
    return $false
}

function Resolve-DERValidationMetadata {
    param(
        [Parameter(Mandatory)]$StateRecord,
        [Parameter(Mandatory)][string]$ActionId
    )
    $metadata=$StateRecord.Metadata
    if($null -eq $metadata){return $null}
    if($metadata.PSObject.Properties.Name -notcontains 'RollbackPreparation'){return $metadata}

    $preparation=$metadata.RollbackPreparation
    if($null -eq $preparation -or [string]::IsNullOrWhiteSpace([string]$preparation.RunId) -or [string]::IsNullOrWhiteSpace([string]$preparation.ActionId)){
        throw (New-DERValidationActionException -Message "DER RECOVERY_REQUIRED: tracked adopted object '$($StateRecord.DerId)' has malformed rollback preparation metadata." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
    }
    if([string]$preparation.ActionId -ne $ActionId){
        throw (New-DERValidationActionException -Message "DER RECOVERY_REQUIRED: tracked adopted object '$($StateRecord.DerId)' has unresolved rollback preparation from RunId '$($preparation.RunId)' / ActionId '$($preparation.ActionId)'." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
    }
    if(Test-DERValidationCommand 'Get-DERStateContext'){
        $context=Get-DERStateContext
        if($context -and [string]$context.RunId -ne [string]$preparation.RunId){
            throw (New-DERValidationActionException -Message "DER RECOVERY_REQUIRED: tracked adopted object '$($StateRecord.DerId)' has rollback preparation from another run." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
        }
    }
    if(-not [bool]$preparation.Eligible -or $null -eq $preparation.ChangeMetadata){
        throw (New-DERValidationActionException -Message "DER RECOVERY_REQUIRED: tracked adopted object '$($StateRecord.DerId)' has incomplete rollback preparation metadata." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
    }

    $effective=(($metadata | ConvertTo-Json -Depth 100) | ConvertFrom-Json -Depth 100)
    $effective.PSObject.Properties.Remove('RollbackPreparation')
    foreach($property in $preparation.ChangeMetadata.PSObject.Properties){
        $effective | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
    }
    return $effective
}

function Assert-DERManagedStateObject {
    <#
    .SYNOPSIS
        Fail-closed validation for an object already recorded in DER state.

    .DESCRIPTION
        DER state is evidence of what DER believes it manages, not proof that the
        Microsoft object still exists or still matches the recorded intent. This
        helper rereads the exact validation URI, treats only a genuine Graph 404 as
        missing, verifies Microsoft ObjectId when Graph returns one, validates the
        recorded expected subset, optional Settings Catalog count, optional group
        assignment, and optional composite validations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$StateRecord,
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$ActionId,
        [string[]]$AllowedOwnershipClass=@('DER-Owned'),
        [switch]$MarkValidated
    )
    if($null -eq $StateRecord){throw (New-DERValidationActionException -Message 'DER existing-object validation requires a state record.' -ActionId $ActionId)}
    $ownership=[string]$StateRecord.OwnershipClass
    if($ownership -notin $AllowedOwnershipClass){throw (New-DERValidationActionException -Message "DER refuses existing-object validation for '$($StateRecord.DerId)' because ownership '$ownership' is not allowed for this operation." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))}
    $metadata=Resolve-DERValidationMetadata -StateRecord $StateRecord -ActionId $ActionId
    $validationUri=[string](Get-DERValidationMetadataValue -Metadata $metadata -Name 'ValidationUri')
    if([string]::IsNullOrWhiteSpace($validationUri)){throw (New-DERValidationActionException -Message "DER state for '$($StateRecord.DerId)' has no ValidationUri; reconciliation is required." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))}
    $apiVersion=[string](Get-DERValidationMetadataValue -Metadata $metadata -Name 'ApiVersion')
    if([string]::IsNullOrWhiteSpace($apiVersion)){$apiVersion='v1.0'}

    $actual=Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion $apiVersion -Component $Component -ActionId $ActionId -AllowNotFound
    if($null -eq $actual){
        if(Test-DERValidationCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$StateRecord.ObjectId) -Status Drifted | Out-Null}
        throw (New-DERValidationActionException -Message "DER RECONCILIATION_REQUIRED: tracked DER object '$($StateRecord.DerId)' / ObjectId '$($StateRecord.ObjectId)' returned Microsoft Graph 404. DER will not create a replacement automatically." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
    }

    $actualId=[string](Get-DERValidationMetadataValue -Metadata $actual -Name 'id')
    if(-not [string]::IsNullOrWhiteSpace($actualId) -and -not [string]::IsNullOrWhiteSpace([string]$StateRecord.ObjectId) -and $actualId -ne [string]$StateRecord.ObjectId){
        throw (New-DERValidationActionException -Message "DER RECONCILIATION_REQUIRED: Microsoft returned ObjectId '$actualId' for tracked DER ObjectId '$($StateRecord.ObjectId)'." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
    }

    $differences=New-Object System.Collections.Generic.List[object]
    $expected=Get-DERValidationMetadataValue -Metadata $metadata -Name 'ExpectedSubset'
    if($null -ne $expected){
        $comparison=Test-DERExpectedSubset -Actual $actual -Expected $expected
        foreach($difference in @($comparison.Differences)){$differences.Add($difference)}
    }

    $composite=Get-DERValidationMetadataValue -Metadata $metadata -Name 'CompositeValidations'
    foreach($entry in @($composite)){
        if($null -eq $entry){continue}
        $entryUri=[string](Get-DERValidationMetadataValue -Metadata $entry -Name 'Uri')
        if([string]::IsNullOrWhiteSpace($entryUri)){throw (New-DERValidationActionException -Message "DER composite validation for '$($StateRecord.DerId)' is missing Uri." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))}
        $entryApi=[string](Get-DERValidationMetadataValue -Metadata $entry -Name 'ApiVersion');if([string]::IsNullOrWhiteSpace($entryApi)){$entryApi=$apiVersion}
        $entryActual=Invoke-DERGraphRequest -Method GET -Uri $entryUri -ApiVersion $entryApi -Component $Component -ActionId $ActionId -AllowNotFound
        if($null -eq $entryActual){throw (New-DERValidationActionException -Message "DER RECONCILIATION_REQUIRED: composite object '$entryUri' for '$($StateRecord.DerId)' returned Microsoft Graph 404." -ActionId $ActionId -DerId ([string]$StateRecord.DerId))}
        $entryExpected=Get-DERValidationMetadataValue -Metadata $entry -Name 'ExpectedSubset'
        if($null -ne $entryExpected){
            $entryComparison=Test-DERExpectedSubset -Actual $entryActual -Expected $entryExpected -Path ("$.Composite[{0}]" -f $entryUri)
            foreach($difference in @($entryComparison.Differences)){$differences.Add($difference)}
        }
    }

    $settingsUri=[string](Get-DERValidationMetadataValue -Metadata $metadata -Name 'SettingsUri')
    $minimumSettings=Get-DERValidationMetadataValue -Metadata $metadata -Name 'MinimumSettingsCount'
    if(-not [string]::IsNullOrWhiteSpace($settingsUri) -and $null -ne $minimumSettings){
        $settings=@(Invoke-DERGraphCollectionRequest -Uri $settingsUri -ApiVersion $apiVersion -Component $Component -ActionId $ActionId)
        if($settings.Count -lt [int]$minimumSettings){
            $differences.Add([pscustomobject]@{Path='$.SettingsCount';Expected=(">={0}" -f [int]$minimumSettings);Actual=$settings.Count})
        }
    }

    $assignmentUri=[string](Get-DERValidationMetadataValue -Metadata $metadata -Name 'AssignmentUri')
    $expectedGroup=[string](Get-DERValidationMetadataValue -Metadata $metadata -Name 'ExpectedAssignmentTargetId')
    if(-not [string]::IsNullOrWhiteSpace($assignmentUri) -and -not [string]::IsNullOrWhiteSpace($expectedGroup)){
        $assignments=@(Invoke-DERGraphCollectionRequest -Uri $assignmentUri -ApiVersion $apiVersion -Component $Component -ActionId $ActionId)
        if(-not (Test-DERAssignmentContainsGroup -Assignments $assignments -GroupId $expectedGroup)){
            $differences.Add([pscustomobject]@{Path='$.Assignments';Expected=("TargetGroup={0}" -f $expectedGroup);Actual='Target group not found'})
        }
    }

    if($differences.Count -gt 0){
        if(Test-DERValidationCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$StateRecord.ObjectId) -Status Drifted | Out-Null}
        $paths=@($differences|ForEach-Object{[string]$_.Path}) -join ', '
        throw (New-DERValidationActionException -Message "DER DRIFT_DETECTED: tracked object '$($StateRecord.DerId)' no longer matches recorded expected state. Differences: $paths" -ActionId $ActionId -DerId ([string]$StateRecord.DerId))
    }
    if($MarkValidated -and (Test-DERValidationCommand 'Update-DERStateObject')){Update-DERStateObject -ObjectId ([string]$StateRecord.ObjectId) -MarkValidated | Out-Null}
    return [pscustomobject]@{Success=$true;StateRecord=$StateRecord;Actual=$actual;Differences=@()}
}

function Get-DERWorkloadEntryPointName {
    param([Parameter(Mandatory)][string]$Module)
    $map=@{
        Groups='Invoke-DERGroupsModule';EntraDevice='Invoke-DEREntraDeviceModule';Enrollment='Invoke-DEREnrollmentModule';Autopilot='Invoke-DERAutopilotModule';
        Compliance='Invoke-DERComplianceModule';BitLocker='Invoke-DERBitLockerModule';LAPS='Invoke-DERLAPSModule';Defender='Invoke-DERDefenderModule';ASR='Invoke-DERASRModule';
        Firewall='Invoke-DERFirewallModule';Configuration='Invoke-DERConfigurationModule';AuthenticationMethods='Invoke-DERAuthenticationMethodsModule';ConditionalAccess='Invoke-DERConditionalAccessModule';
        NamedLocations='Invoke-DERNamedLocationsModule';GuestExternal='Invoke-DERGuestExternalModule';AppConsent='Invoke-DERAppConsentModule';PasswordProtection='Invoke-DERPasswordProtectionModule';
        PIM='Invoke-DERPIMModule';Updates='Invoke-DERUpdatesModule';Drivers='Invoke-DERDriversModule';OneDrive='Invoke-DEROneDriveModule';DeliveryOptimization='Invoke-DERDeliveryOptimizationModule';
        TenantSettings='Invoke-DERTenantSettingsModule';Analytics='Invoke-DERAnalyticsModule';LoggingIntegration='Invoke-DERLoggingIntegrationModule'
    }
    return $map[$Module]
}

function Invoke-DERPostBuildValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $started=Get-Date
    $results=New-Object System.Collections.Generic.List[object]
    Write-DERValidationEngineLog -Level STEP -Message 'Starting DER post-build read-back validation.' -Data @{tenantId=$BuildPlan.TenantId;plannedObjects=$BuildPlan.Summary.PlannedObjects}

    foreach($planned in @($BuildPlan.Objects | Where-Object {$_.Enabled})) {
        $actionId=if(Test-DERValidationCommand 'New-DERActionId'){New-DERActionId -Component 'VALID'}else{"VAL-$($planned.DerId)"}
        $entryPoint=Get-DERWorkloadEntryPointName -Module $planned.Module
        if (-not $entryPoint -or -not (Test-DERValidationCommand $entryPoint)) {
            $r=[pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;DisplayName=$planned.DisplayName;Status='Skipped';Reason='Required workload entry point is unavailable in this package';ObjectId=$null;ActionId=$actionId;Differences=@()}
            $results.Add($r);if(Test-DERValidationCommand 'Write-DERValidationLog'){Write-DERValidationLog -ActionId $actionId -Module $planned.Module -DerId $planned.DerId -Status 'Skipped' -Message $r.Reason -Data $r};continue
        }

        $stateRecord=$null
        if(Test-DERValidationCommand 'Get-DERStateObject') {$stateRecord=Get-DERStateObject -DerId $planned.DerId}
        if (-not $stateRecord -or [string]$stateRecord.Status -in @('RolledBack','Retired','Skipped')) {
            $workloadResult=$null
            $stateContext=if(Test-DERValidationCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null}
            if($stateContext){
                $workloadPath=Join-Path (Join-Path $stateContext.RunRoot 'Workloads') ("{0}.json" -f $planned.Module)
                if(Test-Path -LiteralPath $workloadPath){
                    try{
                        $workloadData=Get-Content -LiteralPath $workloadPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100
                        $workloadResult=@($workloadData.Results | Where-Object {[string]$_.DerId -eq [string]$planned.DerId} | Select-Object -First 1)
                        if($workloadResult.Count -gt 0){$workloadResult=$workloadResult[0]}else{$workloadResult=$null}
                    }catch{Write-DERValidationEngineLog -Level WARN -Message ("Could not read workload result for {0}: {1}" -f $planned.DerId,$_.Exception.Message) -ActionId $actionId}
                }
            }
            $failureKind=$null
            $logAsNewEngineFailure=$false
            if($workloadResult -and [string]$workloadResult.Status -in @('Skipped','Existing')){
                $status='Skipped'
                $reason=if([string]$workloadResult.Message){[string]$workloadResult.Message}else{'Workload intentionally did not create or modify this object.'}
            }elseif($workloadResult -and [string]$workloadResult.Status -eq 'Failed'){
                $status='Failed'
                $reason=if([string]$workloadResult.Message){[string]$workloadResult.Message}else{'Workload reported a failure for this object.'}
                $failureKind=if($workloadResult.PSObject.Properties.Name -contains 'FailureKind' -and [string]$workloadResult.FailureKind -in @('Action','Engine')){[string]$workloadResult.FailureKind}else{'Engine'}
                # The originating workload already persisted the primary error record.
                # Validation records this as correlated downstream evidence instead of
                # inventing a second incident for the same underlying failure.
            }elseif($stateRecord -and [string]$stateRecord.Status -eq 'Skipped'){
                $status='Skipped';$reason='Workload intentionally skipped this object.'
            }else{
                $status='Failed';$reason='No active DER ownership/state record exists for this enabled planned object and no explicit workload failure explains the absence.'
                $failureKind='Engine';$logAsNewEngineFailure=$true
            }
            $r=[pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;DisplayName=$planned.DisplayName;Status=$status;FailureKind=$failureKind;Reason=$reason;ObjectId=if($stateRecord){$stateRecord.ObjectId}else{$null};ActionId=$actionId;Differences=@()}
            if($logAsNewEngineFailure -and (Test-DERValidationCommand 'Write-DEREngineFailure')){Write-DEREngineFailure -Message $reason -Component 'Validation' -ActionId $actionId -DerId ([string]$planned.DerId) -Data $r}
            $results.Add($r);if(Test-DERValidationCommand 'Write-DERValidationLog'){Write-DERValidationLog -ActionId $actionId -Module $planned.Module -DerId $planned.DerId -Status $status -Message $reason -Data $r};continue
        }

        $metadata=$stateRecord.Metadata
        $validationUri=if($metadata -and $metadata.PSObject.Properties.Name -contains 'ValidationUri'){[string]$metadata.ValidationUri}else{$null}
        $apiVersion=if($metadata -and $metadata.PSObject.Properties.Name -contains 'ApiVersion'){[string]$metadata.ApiVersion}else{'v1.0'}
        $expected=if($metadata -and $metadata.PSObject.Properties.Name -contains 'ExpectedSubset'){$metadata.ExpectedSubset}else{$null}

        if ([string]::IsNullOrWhiteSpace($validationUri)) {
            $r=[pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;DisplayName=$planned.DisplayName;Status='Failed';FailureKind='Engine';Reason='DER state record does not contain a validation URI required by the current v1 state contract.';ObjectId=$stateRecord.ObjectId;ActionId=$actionId;Differences=@()}
            if(Test-DERValidationCommand 'Write-DEREngineFailure'){Write-DEREngineFailure -Message $r.Reason -Component 'Validation' -ActionId $actionId -DerId ([string]$planned.DerId) -Data $r}
            $results.Add($r);if(Test-DERValidationCommand 'Write-DERValidationLog'){Write-DERValidationLog -ActionId $actionId -Module $planned.Module -DerId $planned.DerId -Status 'Failed' -Message $r.Reason -Data $r};continue
        }

        try {
            $allowedOwnership=if([string]$stateRecord.OwnershipClass -eq 'DER-Adopted'){@('DER-Adopted')}else{@('DER-Owned')}
            $validated=Assert-DERManagedStateObject -StateRecord $stateRecord -Component 'Validation' -ActionId $actionId -AllowedOwnershipClass $allowedOwnership -MarkValidated
            if(Test-DERValidationCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase VALIDATE -Module $planned.Module -DerId $planned.DerId -ObjectId $stateRecord.ObjectId -Message 'Post-build validation passed.' | Out-Null}
            $r=[pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;DisplayName=$planned.DisplayName;Status='Passed';Reason='Read-back state matches DER recorded expectation, assignment, and settings evidence.';ObjectId=$stateRecord.ObjectId;ActionId=$actionId;Differences=@()}
        } catch {
            $validationError=$_
            $failureKind=if(Test-DERValidationCommand 'Get-DERFailureKindFromErrorRecord'){Get-DERFailureKindFromErrorRecord -ErrorRecord $validationError}else{'Engine'}
            if(Test-DERValidationCommand 'Write-DERError'){Write-DERError -ErrorRecord $validationError -Component 'Validation' -ActionId $actionId -DerId ([string]$planned.DerId)}
            $r=[pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;DisplayName=$planned.DisplayName;Status='Failed';FailureKind=$failureKind;Reason=$validationError.Exception.Message;ObjectId=$stateRecord.ObjectId;ActionId=$actionId;Differences=@()}
        }
        $results.Add($r)
        if(Test-DERValidationCommand 'Write-DERValidationLog'){Write-DERValidationLog -ActionId $actionId -Module $planned.Module -DerId $planned.DerId -Status $r.Status -Message $r.Reason -Data $r}
    }

    $completed=Get-Date
    $summary=[pscustomobject][ordered]@{
        Planned=@($BuildPlan.Objects|Where-Object {$_.Enabled}).Count
        Passed=@($results|Where-Object {$_.Status -eq 'Passed'}).Count
        Failed=@($results|Where-Object {$_.Status -eq 'Failed'}).Count
        Skipped=@($results|Where-Object {$_.Status -eq 'Skipped'}).Count
    }
    $validation=[pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$RunId;TenantId=$BuildPlan.TenantId;StartedAt=$started;CompletedAt=$completed;DurationMs=[int]($completed-$started).TotalMilliseconds;Summary=$summary;Results=@($results)}

    $stateContext=if(Test-DERValidationCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null}
    if($stateContext){
        $dir=Join-Path $stateContext.RunRoot 'Validation';New-Item -ItemType Directory -Path $dir -Force|Out-Null
        $validation|ConvertTo-Json -Depth 60|Set-Content -LiteralPath (Join-Path $dir 'PostBuildValidation.json') -Encoding UTF8
    }
    $level=if($summary.Failed -gt 0){'WARN'}else{'OK'}
    Write-DERValidationEngineLog -Level $level -Message ("Post-build validation complete: {0} passed, {1} failed, {2} skipped." -f $summary.Passed,$summary.Failed,$summary.Skipped) -Data $summary
    return $validation
}

Export-ModuleMember -Function @('ConvertTo-DERComparableValue','Test-DERExpectedSubset','Test-DERAssignmentContainsGroup','Resolve-DERValidationMetadata','Assert-DERManagedStateObject','Invoke-DERPostBuildValidation')
