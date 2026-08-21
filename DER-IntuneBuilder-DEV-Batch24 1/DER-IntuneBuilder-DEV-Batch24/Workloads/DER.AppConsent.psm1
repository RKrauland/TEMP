<#
.SYNOPSIS
    DER Microsoft Entra app/admin consent workload.

.DESCRIPTION
    Enables the admin consent request workflow only when DER can resolve at
    least one real reviewer from the DER Intune Administrators group. This
    prevents enabling a workflow with nobody able to review requests. The
    tenant's existing consent policy is preserved when that prerequisite is not
    met.

.NOTES
    Required parent entry point: Invoke-DERAppConsentModule
#>

# Maintenance notes
# Responsibility: Manages approved app-consent policy state and reviewer targeting through adopted-state safeguards.
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


function Test-DERConsentCommand{param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERConsentLog{param([string]$Level,[string]$Message,$Data,[string]$ActionId)if(Test-DERConsentCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'AppConsent' -ActionId $ActionId -Message $Message -Data $Data}}
function Save-DERConsentResult{param($Result)$ctx=if(Test-DERConsentCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'AppConsent.json') -Encoding UTF8}}
function Complete-DERConsentResult{param([System.Collections.Generic.List[object]]$Results,[string]$RunId)$s=[pscustomobject]@{Updated=@($Results|Where-Object{$_.Status-eq'Updated'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count};$o=[pscustomobject][ordered]@{Module='AppConsent';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Updated-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)};Save-DERConsentResult$o;return$o}

function Invoke-DERAppConsentModule{
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object]
    $p=@($BuildPlan.Objects|Where-Object{$_.Enabled-and$_.Module-eq'AppConsent'}|Select-Object -First 1)
    if(-not$p){return Complete-DERConsentResult $results $RunId};$p=$p[0]
    $aid=if(Test-DERConsentCommand 'New-DERActionId'){New-DERActionId -Component 'CONSENT'}else{'CONSENT-001'}
    try{
        if($BuildPlan.Safety.ChangeControl -eq 'No tenant-wide switch changes' -or $BuildPlan.Safety.ChangeControl -eq 'Report-only / no tenant writes'){
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Tenant-wide consent settings preserved by selected change-control mode.';ActionId=$aid});return Complete-DERConsentResult $results $RunId
        }
        $adminGroup=if(Test-DERConsentCommand 'Get-DERStateObject'){Get-DERStateObject -DerId 'DER-GRP-U-040'}else{$null}
        if(-not$adminGroup){throw (New-DERWorkloadFailureException -Message 'DER Intune Administrators group is unavailable; admin consent reviewers cannot be resolved.')}
        Assert-DERManagedStateObject -StateRecord $adminGroup -Component 'AppConsent' -ActionId $aid -AllowedOwnershipClass @('DER-Owned') | Out-Null
        $members=@(Invoke-DERGraphCollectionRequest -Uri ("groups/{0}/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName"-f$adminGroup.ObjectId) -ApiVersion 'v1.0' -Component 'AppConsent' -ActionId $aid)
        if(-not$members.Count){
            $msg='DER Intune Administrators group is empty. Admin consent workflow was not enabled because a workflow with zero reviewers would be unusable. Add approved reviewers and rerun DER.'
            if(Test-DERConsentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase SKIP -Module 'AppConsent' -DerId $p.DerId -Message $msg|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=$msg;ActionId=$aid});return Complete-DERConsentResult $results $RunId
        }
        $reviewers=@($members|ForEach-Object{[ordered]@{query=("/users/{0}"-f$_.id);queryType='MicrosoftGraph'}})
        $current=Invoke-DERGraphRequest -Method GET -Uri 'policies/adminConsentRequestPolicy' -ApiVersion 'v1.0' -Component 'AppConsent' -ActionId $aid
        $original=[pscustomobject]@{isEnabled=[bool]$current.isEnabled;notifyReviewers=[bool]$current.notifyReviewers;remindersEnabled=[bool]$current.remindersEnabled;requestDurationInDays=[int]$current.requestDurationInDays;reviewers=@($current.reviewers)}
        $body=[ordered]@{isEnabled=$true;notifyReviewers=$true;remindersEnabled=$true;requestDurationInDays=7;reviewers=$reviewers}
        $expected=[pscustomobject]@{isEnabled=$true;notifyReviewers=$true;remindersEnabled=$true;requestDurationInDays=7;reviewers=$reviewers}
        $state=if(Test-DERConsentCommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
        if($state){
            if([string]$state.OwnershipClass-ne'DER-Adopted'){throw (New-DERWorkloadFailureException -Message "AppConsent state '$($p.DerId)' is not DER-Adopted; automatic update refused.")}
            Assert-DERManagedStateObject -StateRecord $state -Component 'AppConsent' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted')|Out-Null
        }
        $baseMeta=[pscustomobject]@{Module='AppConsent';ApiVersion='v1.0';ValidationUri='policies/adminConsentRequestPolicy';ExpectedSubset=$original;BuiltInTenantObject=$true;AdoptionNoTenantWrite=$true}
        if(-not$state){$state=Add-DERStateObject -DerId $p.DerId -ObjectId 'adminConsentRequestPolicy' -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $baseMeta}
        $rollback=[pscustomobject]@{Module='AppConsent';ApiVersion='v1.0';ValidationUri='policies/adminConsentRequestPolicy';UpdateUri='policies/adminConsentRequestPolicy';UpdateMethod='PUT';OriginalState=$original;OriginalExpectedSubset=$original;ExpectedSubset=$expected;BuiltInTenantObject=$true}
        $state=Set-DERAdoptedRollbackPreparation -ObjectId ([string]$state.ObjectId) -RunId $RunId -ActionId $aid -RollbackMetadata $rollback
        if(Test-DERConsentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase RECORD_ORIGINAL -Module 'AppConsent' -DerId $p.DerId -ObjectId 'adminConsentRequestPolicy' -Message 'Recorded original admin consent request policy.' -Data $original|Out-Null}
        Invoke-DERGraphRequest -Method PUT -Uri 'policies/adminConsentRequestPolicy' -ApiVersion 'v1.0' -Body $body -Component 'AppConsent' -DerId $p.DerId -ActionId $aid|Out-Null
        Assert-DERManagedStateObject -StateRecord (Get-DERStateObject -ObjectId 'adminConsentRequestPolicy') -Component 'AppConsent' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted') -MarkValidated|Out-Null
        Clear-DERAdoptedRollbackPreparation -ObjectId 'adminConsentRequestPolicy' -RunId $RunId -ActionId $aid|Out-Null
        if(Test-DERConsentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase COMMIT -Module 'AppConsent' -DerId $p.DerId -ObjectId 'adminConsentRequestPolicy' -Message 'Admin consent request workflow enabled and validated.'|Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='adminConsentRequestPolicy';Status='Updated';Message=("Admin consent workflow enabled with {0} reviewer(s) from the DER Intune Administrators group."-f$reviewers.Count);ActionId=$aid})
    }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'AppConsent' -ActionId $aid -DerId $p.DerId}

        if(Test-DERConsentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase FAIL -Module 'AppConsent' -DerId $p.DerId -ObjectId 'adminConsentRequestPolicy' -Message $_.Exception.Message|Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$aid})
    }
    $out=Complete-DERConsentResult $results $RunId;Write-DERConsentLog -Level $(if($out.Summary.Failed){'WARN'}else{'OK'}) -Message 'App consent workload completed.' -Data $out.Summary;return$out
}
Export-ModuleMember -Function @('Invoke-DERAppConsentModule')
