<#
.SYNOPSIS
    DER Microsoft Entra Privileged Identity Management workload.

.DESCRIPTION
    Applies a conservative PIM activation baseline to a curated set of critical
    built-in Microsoft Entra roles. DER does not convert permanent assignments
    to eligible assignments and does not create/remove principals. It changes
    only role-management policy activation rules that it can read, journal,
    update, and validate end-to-end.

.NOTES
    Required parent entry point: Invoke-DERPIMModule
#>

# Maintenance notes
# Responsibility: Manages curated PIM role-management rules as one composite adopted-state contract with all managed rules validated.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

# Workload-local failure factory.
#
# A deliberate workload safety/precondition/read-back refusal is an ACTION failure:
# DER executed the intended code path, but the requested tenant operation cannot be
# completed safely.  ENGINE is reserved for invariant failures that indicate DER's
# own logic/catalog is inconsistent.  Unexpected PowerShell exceptions are never
# routed through this helper and therefore remain ENGINE by default.
function New-DERWorkloadFailureException {
    <#
    .SYNOPSIS
        Creates a deliberate workload exception without destroying failure provenance.

    .DESCRIPTION
        Use this helper only when the workload intentionally stops because a known
        precondition, tenant condition, read-back result, ownership rule, or internal
        invariant prevents safe completion.

        FailureKind defaults to Auto:
          - No inner exception: ACTION. The workload deliberately refused/completed
            unsuccessfully even though DER itself executed normally.
          - Tagged inner exception: inherit the original ACTION/ENGINE classification.
          - Untagged inner exception: ENGINE. An unexpected PowerShell/runtime problem
            must never be disguised as a tenant/action failure merely because it was
            caught while DER was performing an action.

        DER correlation metadata from the inner exception is copied forward so the
        same Incident ID, Action ID, DER ID, Microsoft context, and originating
        component remain reconstructable when a workload adds a friendlier message.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Auto','Action','Engine')][string]$FailureKind='Auto',
        [System.Exception]$InnerException
    )

    $effectiveFailureKind=$FailureKind
    if($effectiveFailureKind -eq 'Auto'){
        if($InnerException){
            $inherited=$null
            if($InnerException.Data -and $InnerException.Data.Contains('DERFailureKind')){
                $candidate=[string]$InnerException.Data['DERFailureKind']
                if($candidate -in @('Action','Engine')){$inherited=$candidate}
            }
            $effectiveFailureKind=if($inherited){$inherited}else{'Engine'}
        }else{
            $effectiveFailureKind='Action'
        }
    }

    $exception=if($InnerException){
        [System.InvalidOperationException]::new($Message,$InnerException)
    }else{
        [System.InvalidOperationException]::new($Message)
    }
    $exception.Data['DERFailureKind']=$effectiveFailureKind

    # Preserve every DER-prefixed correlation/forensic datum supplied by the
    # originating exception.  Do not copy arbitrary third-party Exception.Data
    # values here because those can be large or contain data DER did not choose
    # to persist.  The original inner exception remains available in diagnostics.
    if($InnerException -and $InnerException.Data){
        foreach($key in $InnerException.Data.Keys){
            $name=[string]$key
            if($name -like 'DER*' -and -not $exception.Data.Contains($name)){
                $exception.Data[$name]=$InnerException.Data[$key]
            }
        }
    }

    $moduleName=[string]$ExecutionContext.SessionState.Module.Name
    if(-not [string]::IsNullOrWhiteSpace($moduleName) -and -not $exception.Data.Contains('DERComponent')){
        $exception.Data['DERComponent']=$moduleName.Replace('DER.','')
    }
    if(-not $exception.Data.Contains('DERIncidentId') -and (Get-Command New-DERIncidentId -ErrorAction SilentlyContinue)){
        $exception.Data['DERIncidentId']=New-DERIncidentId
    }
    return $exception
}


function Test-DERPIMCommand{param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERPIMLog{param([string]$Level,[string]$Message,$Data,[string]$ActionId)if(Test-DERPIMCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'PIM' -ActionId $ActionId -Message $Message -Data $Data}}
function Save-DERPIMResult{param($Result)$ctx=if(Test-DERPIMCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'PIM.json') -Encoding UTF8}}
function Complete-DERPIMResult{param([System.Collections.Generic.List[object]]$Results,[string]$RunId)$s=[pscustomobject]@{Updated=@($Results|Where-Object{$_.Status-eq'Updated'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count};$o=[pscustomobject][ordered]@{Module='PIM';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Updated-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)};Save-DERPIMResult$o;return$o}

function Get-DERPIMTargetRoles{
    param([string]$ActionId)
    $names=@('Global Administrator','Privileged Role Administrator','Conditional Access Administrator','Security Administrator','Intune Administrator')
    $defs=@(Invoke-DERGraphCollectionRequest -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn' -ApiVersion 'v1.0' -Component 'PIM' -ActionId $ActionId)
    return @($defs | Where-Object { $_.displayName -in $names -and $_.isBuiltIn -ne $false })
}

function Get-DERPIMPolicyAssignment{
    param([Parameter(Mandatory)][string]$RoleDefinitionId,[string]$ActionId)
    $filter="scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'"
    $uri='policies/roleManagementPolicyAssignments?$filter='+[System.Uri]::EscapeDataString($filter)
    $items=@(Invoke-DERGraphCollectionRequest -Uri $uri -ApiVersion 'v1.0' -Component 'PIM' -ActionId $ActionId)
    return ($items | Select-Object -First 1)
}

function New-DERPIMEnablementBody{
    param([string[]]$ExistingRules=@())
    $rules=New-Object System.Collections.Generic.List[string]
    foreach($rule in @($ExistingRules)) { if($rule -and -not $rules.Contains([string]$rule)) {$rules.Add([string]$rule)} }
    foreach($required in @('Justification','MultiFactorAuthentication')) { if(-not $rules.Contains($required)) {$rules.Add($required)} }
    return [ordered]@{
        '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
        id='Enablement_EndUser_Assignment'
        enabledRules=@($rules)
    }
}

function New-DERPIMExpirationBody{
    param([Parameter(Mandatory)][int]$Hours)
    return [ordered]@{
        '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
        id='Expiration_EndUser_Assignment'
        isExpirationRequired=$true
        maximumDuration=("PT{0}H" -f $Hours)
    }
}

function Copy-DERPIMRuleForRestore{
    param([Parameter(Mandatory)]$Rule)
    $body=[ordered]@{'@odata.type'=[string]$Rule.'@odata.type';id=[string]$Rule.id}
    foreach($name in @('enabledRules','isExpirationRequired','maximumDuration','setting','target','isEnabled','claimValue','notificationLevel','notificationRecipients','notificationType','recipientType','isDefaultRecipientsEnabled')){
        if($Rule.PSObject.Properties.Name-contains$name){$body[$name]=$Rule.$name}
    }
    return $body
}

function Invoke-DERPIMModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects | Where-Object { $_.Enabled -and $_.Module -eq 'PIM' } | Select-Object -First 1)
    if(-not $planned.Count){return Complete-DERPIMResult $results $RunId}
    $p=$planned[0]
    $aid=if(Test-DERPIMCommand 'New-DERActionId'){New-DERActionId -Component 'PIM'}else{'PIM-001'}

    if($BuildPlan.Safety.ChangeControl -in @('No tenant-wide switch changes','Report-only / no tenant writes')){
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='PIM role policy settings preserved by selected change-control mode.';ActionId=$aid})
        return Complete-DERPIMResult $results $RunId
    }
    if([bool]$BuildPlan.Answers.Identity.PIMRequireApproval){
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='PIM approval was requested, but no approver identities/groups were collected by the current questionnaire. DER refused to enable approval without valid approvers.';ActionId=$aid})
        return Complete-DERPIMResult $results $RunId
    }

    try {
        $hours=[int]$BuildPlan.Answers.Identity.PIMActivationHours
        if($hours -lt 1 -or $hours -gt 24){throw (New-DERWorkloadFailureException -Message "Invalid PIM activation duration: $hours hours.")}

        # Preflight every managed rule before the first write.  This produces one
        # complete composite validation/rollback recipe and prevents a later
        # discovery failure from leaving an earlier role half changed.
        $roles=Get-DERPIMTargetRoles -ActionId $aid
        if(-not $roles.Count){throw (New-DERWorkloadFailureException -Message 'DER could not resolve the curated Microsoft Entra privileged role definitions.')}
        $validations=New-Object System.Collections.Generic.List[object]
        $originalValidations=New-Object System.Collections.Generic.List[object]
        $restores=New-Object System.Collections.Generic.List[object]
        $updates=New-Object System.Collections.Generic.List[object]
        $resolvedPolicyIds=New-Object System.Collections.Generic.List[string]
        $rolePlans=New-Object System.Collections.Generic.List[object]

        foreach($role in $roles){
            $assignment=Get-DERPIMPolicyAssignment -RoleDefinitionId ([string]$role.id) -ActionId $aid
            if(-not $assignment -or -not $assignment.policyId){
                $rolePlans.Add([pscustomobject]@{Role=[string]$role.displayName;PolicyId=$null;Status='Skipped';Message='No tenant-scoped PIM role management policy assignment was resolved for this role.'})
                continue
            }
            $policyId=[string]$assignment.policyId
            if(-not $resolvedPolicyIds.Contains($policyId)){$resolvedPolicyIds.Add($policyId)}
            $rules=@(Invoke-DERGraphCollectionRequest -Uri ("policies/roleManagementPolicies/{0}/rules" -f $policyId) -ApiVersion 'v1.0' -Component 'PIM' -ActionId $aid)
            $enable=@($rules | Where-Object { [string]$_.id -eq 'Enablement_EndUser_Assignment' } | Select-Object -First 1)
            $expire=@($rules | Where-Object { [string]$_.id -eq 'Expiration_EndUser_Assignment' } | Select-Object -First 1)
            if(-not $enable.Count -or -not $expire.Count){
                $rolePlans.Add([pscustomobject]@{Role=[string]$role.displayName;PolicyId=$policyId;Status='Skipped';Message='Required PIM activation rules were not present; DER made no change for this role.'})
                continue
            }
            $enable=$enable[0];$expire=$expire[0]
            $desiredEnable=New-DERPIMEnablementBody -ExistingRules @($enable.enabledRules)
            $desiredExpire=New-DERPIMExpirationBody -Hours $hours
            $enableUri="policies/roleManagementPolicies/$policyId/rules/Enablement_EndUser_Assignment"
            $expireUri="policies/roleManagementPolicies/$policyId/rules/Expiration_EndUser_Assignment"
            $originalEnable=Copy-DERPIMRuleForRestore -Rule $enable
            $originalExpire=Copy-DERPIMRuleForRestore -Rule $expire
            $validations.Add([pscustomobject]@{Uri=$enableUri;ApiVersion='v1.0';ExpectedSubset=[pscustomobject]$desiredEnable})
            $validations.Add([pscustomobject]@{Uri=$expireUri;ApiVersion='v1.0';ExpectedSubset=[pscustomobject]$desiredExpire})
            $originalValidations.Add([pscustomobject]@{Uri=$enableUri;ApiVersion='v1.0';ExpectedSubset=[pscustomobject]$originalEnable})
            $originalValidations.Add([pscustomobject]@{Uri=$expireUri;ApiVersion='v1.0';ExpectedSubset=[pscustomobject]$originalExpire})

            $enableNeedsChange=(@($enable.enabledRules | Where-Object { $_ -in @('Justification','MultiFactorAuthentication') }).Count -lt 2)
            $expireNeedsChange=(-not [bool]$expire.isExpirationRequired -or [string]$expire.maximumDuration -ne ("PT{0}H" -f $hours))
            if($enableNeedsChange){
                $restores.Add([pscustomobject]@{Uri=$enableUri;Method='PATCH';ApiVersion='v1.0';OriginalState=[pscustomobject]$originalEnable;OriginalExpectedSubset=[pscustomobject]$originalEnable;ExpectedCurrentSubset=[pscustomobject]$desiredEnable;Role=[string]$role.displayName})
                $updates.Add([pscustomobject]@{Uri=$enableUri;Body=$desiredEnable;Role=[string]$role.displayName;PolicyId=$policyId;RuleId='Enablement_EndUser_Assignment'})
            }
            if($expireNeedsChange){
                $restores.Add([pscustomobject]@{Uri=$expireUri;Method='PATCH';ApiVersion='v1.0';OriginalState=[pscustomobject]$originalExpire;OriginalExpectedSubset=[pscustomobject]$originalExpire;ExpectedCurrentSubset=[pscustomobject]$desiredExpire;Role=[string]$role.displayName})
                $updates.Add([pscustomobject]@{Uri=$expireUri;Body=$desiredExpire;Role=[string]$role.displayName;PolicyId=$policyId;RuleId='Expiration_EndUser_Assignment'})
            }
            $rolePlans.Add([pscustomobject]@{Role=[string]$role.displayName;PolicyId=$policyId;Status=if($enableNeedsChange -or $expireNeedsChange){'Updated'}else{'Existing'};Message=("PIM activation requires MFA + justification with a {0}-hour maximum activation." -f $hours)})
        }

        if(-not $validations.Count){
            foreach($rolePlan in $rolePlans){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$rolePlan.Role;ObjectId=$rolePlan.PolicyId;Status=$rolePlan.Status;Message=$rolePlan.Message;ActionId=$aid})}
            return Complete-DERPIMResult $results $RunId
        }

        $state=if(Test-DERPIMCommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
        if($state){
            if([string]$state.OwnershipClass -ne 'DER-Adopted'){throw (New-DERWorkloadFailureException -Message "PIM state '$($p.DerId)' is not DER-Adopted; automatic update refused.")}
            if([string]$state.ObjectId -notin @($resolvedPolicyIds)){throw (New-DERWorkloadFailureException -Message "DER RECONCILIATION_REQUIRED: recorded PIM policy anchor '$($state.ObjectId)' is no longer among the resolved managed PIM policies.")}
            Assert-DERManagedStateObject -StateRecord $state -Component 'PIM' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted') | Out-Null
        }

        $anchorPolicyId=if($state){[string]$state.ObjectId}else{[string]$resolvedPolicyIds[0]}
        $anchorUri="policies/roleManagementPolicies/$anchorPolicyId"
        $desiredMetadata=[pscustomobject][ordered]@{
            Module='PIM';ApiVersion='v1.0';ValidationUri=$anchorUri
            ExpectedSubset=[pscustomobject]@{id=$anchorPolicyId}
            CompositeValidations=@($validations)
            BuiltInTenantObjects=$true
            AdoptionNoTenantWrite=($updates.Count -eq 0)
        }
        if(-not $state){
            $initialValidations=if($updates.Count){@($originalValidations)}else{@($validations)}
            $initialMetadata=[pscustomobject][ordered]@{Module='PIM';ApiVersion='v1.0';ValidationUri=$anchorUri;ExpectedSubset=[pscustomobject]@{id=$anchorPolicyId};CompositeValidations=$initialValidations;BuiltInTenantObjects=$true;AdoptionNoTenantWrite=$true}
            $state=Add-DERStateObject -DerId $p.DerId -ObjectId $anchorPolicyId -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $initialMetadata
        } elseif(-not $updates.Count){
            $state=Update-DERStateObject -ObjectId $state.ObjectId -Metadata $desiredMetadata -Status Adopted
        }

        if($updates.Count){
            foreach($restore in $restores){
                if(Test-DERPIMCommand 'Register-DERTransaction'){
                    Register-DERTransaction -ActionId $aid -Phase RECORD_ORIGINAL -Module 'PIM' -DerId $p.DerId -ObjectId $anchorPolicyId -Message ("Recorded original PIM rule before update: {0}." -f $restore.Uri) -Data $restore.OriginalState | Out-Null
                }
            }
            $rollbackMetadata=[pscustomobject][ordered]@{
                Module='PIM';ApiVersion='v1.0';ValidationUri=$anchorUri
                ExpectedSubset=[pscustomobject]@{id=$anchorPolicyId}
                CompositeValidations=@($validations);CompositeRestores=@($restores)
                BuiltInTenantObjects=$true
            }
            $state=Set-DERAdoptedRollbackPreparation -ObjectId $state.ObjectId -RunId $RunId -ActionId $aid -RollbackMetadata $rollbackMetadata
            foreach($update in $updates){
                Invoke-DERGraphRequest -Method PATCH -Uri $update.Uri -ApiVersion 'v1.0' -Body $update.Body -Component 'PIM' -DerId $p.DerId -ActionId $aid | Out-Null
            }
        }

        $state=Get-DERStateObject -DerId $p.DerId
        Assert-DERManagedStateObject -StateRecord $state -Component 'PIM' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted') -MarkValidated | Out-Null
        if($updates.Count){Clear-DERAdoptedRollbackPreparation -ObjectId $state.ObjectId -RunId $RunId -ActionId $aid | Out-Null}
        if(Test-DERPIMCommand 'Register-DERTransaction'){
            Register-DERTransaction -ActionId $aid -Phase COMMIT -Module 'PIM' -DerId $p.DerId -ObjectId $state.ObjectId -Message 'PIM activation baseline read-back validated for every managed rule.' -Data @{PolicyIds=@($resolvedPolicyIds);CompositeValidationCount=$validations.Count;ChangedRuleCount=$updates.Count} | Out-Null
        }

        foreach($rolePlan in $rolePlans){
            $status=$rolePlan.Status
            $message=$rolePlan.Message
            if($status -eq 'Updated'){$message += ' Changes were read-back validated through the central DER validator.'}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$rolePlan.Role;ObjectId=$rolePlan.PolicyId;Status=$status;Message=$message;ActionId=$aid})
        }
    }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'PIM' -ActionId $aid -DerId $p.DerId}

        $failure=$_.Exception.Message
        if(Test-DERPIMCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase FAIL -Module 'PIM' -DerId $p.DerId -Message $failure | Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$failure;ActionId=$aid})
    }
    $out=Complete-DERPIMResult $results $RunId
    Write-DERPIMLog -Level $(if($out.Summary.Failed){'WARN'}else{'OK'}) -Message 'PIM workload completed.' -Data $out.Summary
    return $out
}
Export-ModuleMember -Function @('New-DERPIMEnablementBody','New-DERPIMExpirationBody','Invoke-DERPIMModule')
