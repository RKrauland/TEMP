<#
.SYNOPSIS
    DER Microsoft Entra guest/external collaboration workload.

.DESCRIPTION
    Applies the approved tenant guest collaboration baseline through the
    authorizationPolicy v1.0 endpoint. Partner-specific cross-tenant trust is
    never guessed; when the questionnaire does not contain explicit per-partner
    trust decisions, DER reports the partner configuration as manual/skipped.

.NOTES
    Required parent entry point: Invoke-DERGuestExternalModule
#>

# Maintenance notes
# Responsibility: Manages approved guest/external collaboration tenant settings through explicit adopted-state safeguards.
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


function Test-DERGuestCommand{param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERGuestLog{param([string]$Level,[string]$Message,$Data,[string]$ActionId)if(Test-DERGuestCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'GuestExternal' -ActionId $ActionId -Message $Message -Data $Data}}
function Save-DERGuestResult{param($Result)$ctx=if(Test-DERGuestCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'GuestExternal.json') -Encoding UTF8}}

function Complete-DERGuestResult{param([System.Collections.Generic.List[object]]$Results,[string]$RunId)$s=[pscustomobject]@{Updated=@($Results|Where-Object{$_.Status-eq'Updated'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count};$o=[pscustomobject][ordered]@{Module='GuestExternal';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Updated-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)};Save-DERGuestResult$o;return$o}

function Invoke-DERGuestExternalModule{
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled-and$_.Module-eq'GuestExternal'})
    if(-not$planned.Count){return Complete-DERGuestResult $results $RunId}

    foreach($p in$planned){
        $aid=if(Test-DERGuestCommand 'New-DERActionId'){New-DERActionId -Component 'GUEST'}else{"GUEST-$($p.DerId)"}
        if($p.DerId-eq'DER-XTENANT-010'){
            $partners=@($BuildPlan.Answers.Identity.PartnerTenants)
            $message=if($partners.Count){"Partner list captured ($($partners -join ', ')), but DER has no explicit per-partner inbound MFA/device trust decisions. Cross-tenant policy was preserved and must be reviewed partner-by-partner."}else{'No partner tenants were supplied.'}
            if(Test-DERGuestCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase SKIP -Module 'GuestExternal' -DerId $p.DerId -Message $message|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=$message;ActionId=$aid});continue
        }
        try{
            if($BuildPlan.Safety.ChangeControl -eq 'No tenant-wide switch changes' -or $BuildPlan.Safety.ChangeControl -eq 'Report-only / no tenant writes'){
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Tenant-wide guest collaboration policy preserved by the selected change-control mode.';ActionId=$aid});continue
            }
            $current=Invoke-DERGraphRequest -Method GET -Uri 'policies/authorizationPolicy' -ApiVersion 'v1.0' -Component 'GuestExternal' -ActionId $aid
            $restrictedGuestRole='2af84b1e-32c8-42b7-82bc-daa82404023b'
            $expected=[pscustomobject]@{guestUserRoleId=$restrictedGuestRole;allowInvitesFrom='adminsAndGuestInviters'}
            $original=[pscustomobject]@{guestUserRoleId=[string]$current.guestUserRoleId;allowInvitesFrom=[string]$current.allowInvitesFrom}
            $state=if(Test-DERGuestCommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
            if($state){
                if([string]$state.OwnershipClass-ne'DER-Adopted'){throw (New-DERWorkloadFailureException -Message "GuestExternal state '$($p.DerId)' is not DER-Adopted; automatic update refused.")}
                Assert-DERManagedStateObject -StateRecord $state -Component 'GuestExternal' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted')|Out-Null
            }
            if([string]$current.guestUserRoleId-eq$restrictedGuestRole -and [string]$current.allowInvitesFrom-eq'adminsAndGuestInviters'){
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='authorizationPolicy';Status='Existing';Message='Guest visibility and invitation restrictions already match the DER baseline.';ActionId=$aid});continue
            }
            $body=[ordered]@{guestUserRoleId=$restrictedGuestRole;allowInvitesFrom='adminsAndGuestInviters'}
            $baseMeta=[pscustomobject]@{Module='GuestExternal';ApiVersion='v1.0';ValidationUri='policies/authorizationPolicy';ExpectedSubset=$original;BuiltInTenantObject=$true;AdoptionNoTenantWrite=$true}
            if(-not$state){$state=Add-DERStateObject -DerId $p.DerId -ObjectId 'authorizationPolicy' -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $baseMeta}
            $rollback=[pscustomobject]@{Module='GuestExternal';ApiVersion='v1.0';ValidationUri='policies/authorizationPolicy';UpdateUri='policies/authorizationPolicy';UpdateMethod='PATCH';OriginalState=$original;OriginalExpectedSubset=$original;ExpectedSubset=$expected;BuiltInTenantObject=$true}
            $state=Set-DERAdoptedRollbackPreparation -ObjectId ([string]$state.ObjectId) -RunId $RunId -ActionId $aid -RollbackMetadata $rollback
            if(Test-DERGuestCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase RECORD_ORIGINAL -Module 'GuestExternal' -DerId $p.DerId -ObjectId 'authorizationPolicy' -Message 'Recorded original guest collaboration authorization policy settings.' -Data $original|Out-Null}
            Invoke-DERGraphRequest -Method PATCH -Uri 'policies/authorizationPolicy' -ApiVersion 'v1.0' -Body $body -Component 'GuestExternal' -DerId $p.DerId -ActionId $aid|Out-Null
            Assert-DERManagedStateObject -StateRecord (Get-DERStateObject -ObjectId 'authorizationPolicy') -Component 'GuestExternal' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted') -MarkValidated|Out-Null
            Clear-DERAdoptedRollbackPreparation -ObjectId 'authorizationPolicy' -RunId $RunId -ActionId $aid|Out-Null
            if(Test-DERGuestCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase COMMIT -Module 'GuestExternal' -DerId $p.DerId -ObjectId 'authorizationPolicy' -Message 'Guest collaboration baseline updated and validated.'|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='authorizationPolicy';Status='Updated';Message='Restricted guest visibility applied and invitations limited to administrators/Guest Inviters.';ActionId=$aid})
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'GuestExternal' -ActionId $aid -DerId $p.DerId}

            if(Test-DERGuestCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase FAIL -Module 'GuestExternal' -DerId $p.DerId -ObjectId 'authorizationPolicy' -Message $_.Exception.Message|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$aid})
        }
    }
    $out=Complete-DERGuestResult $results $RunId;Write-DERGuestLog -Level $(if($out.Summary.Failed){'WARN'}else{'OK'}) -Message 'Guest/external collaboration workload completed.' -Data $out.Summary;return$out
}
Export-ModuleMember -Function @('Invoke-DERGuestExternalModule')
