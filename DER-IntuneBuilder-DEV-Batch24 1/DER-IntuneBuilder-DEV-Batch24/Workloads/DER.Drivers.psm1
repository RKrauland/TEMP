<#
.SYNOPSIS
    DER Windows Driver/Firmware update workload.

.DESCRIPTION
    Creates automatic-approval Windows driver update profiles for the DER Pilot
    and empty Production device groups. Microsoft currently exposes this
    management path through Graph beta, so the module obeys DER Safe Preview.
#>


# Maintenance notes
# Responsibility: Manages approved driver update policy and validates exact target-group assignment.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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


function Test-DERDriversCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}
function Save-DERDriversResult {
    param($Result)
    $ctx = if (Test-DERDriversCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath (Join-Path $dir 'Drivers.json') -Encoding UTF8
    }
}
function Get-DERDriversStateObject {
    param([Parameter(Mandatory)][string]$DerId)
    if (Test-DERDriversCommand 'Get-DERStateObject') { return Get-DERStateObject -DerId $DerId }
    return $null
}
function Get-DERDriversTargetGroup {
    param([Parameter(Mandatory)][string]$DerId)
    switch ($DerId) {
        'DER-WU-030' { return Get-DERDriversStateObject -DerId 'DER-GRP-D-010' }
        'DER-WU-040' { return Get-DERDriversStateObject -DerId 'DER-GRP-D-020' }
        default { return $null }
    }
}
function New-DERDriverProfileBody {
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)]$Planned)
    $days = if ([string]$Planned.DerId -eq 'DER-WU-030') { [int]$BuildPlan.Answers.Updates.DriverPilotDelayDays } else { [int]$BuildPlan.Answers.Updates.DriverProductionDelayDays }
    return [ordered]@{
        '@odata.type'='#microsoft.graph.windowsDriverUpdateProfile'
        displayName=$Planned.DisplayName
        description='Customer automatic Windows driver and firmware update policy. Production group remains empty until engineer promotion.'
        approvalType='automatic'
        deploymentDeferralInDays=$days
        roleScopeTagIds=@('0')
    }
}
function New-DERDriverAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId)
    return [ordered]@{
        assignments=@(
            [ordered]@{
                '@odata.type'='#microsoft.graph.windowsDriverUpdateProfileAssignment'
                target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}
            }
        )
    }
}
function Complete-DERDriversResult {
    param($Results,[string]$RunId)
    $summary=[pscustomobject]@{
        Created=@($Results|Where-Object Status -eq 'Created').Count
        Existing=@($Results|Where-Object Status -eq 'Existing').Count
        Skipped=@($Results|Where-Object Status -eq 'Skipped').Count
        Failed=@($Results|Where-Object Status -eq 'Failed').Count
    }
    $out=[pscustomobject]@{
        Module='Drivers';RunId=$RunId
        Status=if($summary.Failed){'CompletedWithFailures'}elseif($summary.Created-or$summary.Existing){'Completed'}else{'Skipped'}
        CriticalFailure=$false;Summary=$summary;Results=@($Results)
    }
    Save-DERDriversResult -Result $out
    return $out
}

function Invoke-DERDriversModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled -and $_.Module -eq 'Drivers'})
    $results=New-Object System.Collections.Generic.List[object]
    if(-not $planned.Count){return Complete-DERDriversResult -Results $results -RunId $RunId}

    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){
        foreach($p in $planned){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Windows Driver Update profile management requires a DER-approved Graph Preview API and Preview APIs are disabled.'})}
        return Complete-DERDriversResult -Results $results -RunId $RunId
    }

    foreach($p in $planned){
        $actionId=if(Test-DERDriversCommand 'New-DERActionId'){New-DERActionId -Component 'DRV'}else{"DRV-$($p.DerId)"}
        try{
            $group=Get-DERDriversTargetGroup -DerId $p.DerId
            if(-not $group){throw (New-DERWorkloadFailureException -Message 'Required DER target group is missing.')}
            Assert-DERManagedStateObject -StateRecord $group -Component 'Drivers' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') | Out-Null

            $state=Get-DERDriversStateObject -DerId $p.DerId
            if($state){
                Assert-DERManagedStateObject -StateRecord $state -Component 'Drivers' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned driver profile exists and matches recorded state.';ActionId=$actionId})
                continue
            }

            $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/windowsDriverUpdateProfiles' -ApiVersion beta -Component 'Drivers' -ActionId $actionId
            $collision=@($all|Where-Object{[string]$_.displayName -eq [string]$p.DisplayName})
            if($collision.Count){
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned driver policy exists; explicit DER adoption is required.';ActionId=$actionId})
                continue
            }

            $body=New-DERDriverProfileBody -BuildPlan $BuildPlan -Planned $p
            $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/windowsDriverUpdateProfiles' -ApiVersion beta -Body $body -Component 'Drivers' -DerId $p.DerId -ActionId $actionId
            if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'Driver profile create response did not include an object ID.')}

            $uri="deviceManagement/windowsDriverUpdateProfiles/$($created.id)"
            $expected=[pscustomobject]@{displayName=$p.DisplayName;approvalType='automatic';deploymentDeferralInDays=[int]$body.deploymentDeferralInDays}
            $meta=[pscustomobject]@{Module='Drivers';ApiVersion='beta';ValidationUri=$uri;DeleteUri=$uri;ExpectedSubset=$expected;AssignmentUri="$uri/assignments";ExpectedAssignmentTargetId=[string]$group.ObjectId}
            Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null

            Invoke-DERGraphRequest -Method POST -Uri "$uri/assign" -ApiVersion beta -Body (New-DERDriverAssignmentBody -GroupId $group.ObjectId) -Component 'Drivers' -DerId $p.DerId -ActionId $actionId | Out-Null
            $read=Invoke-DERGraphRequest -Method GET -Uri $uri -ApiVersion beta -Component 'Drivers' -DerId $p.DerId -ActionId $actionId
            if(Test-DERDriversCommand 'Test-DERExpectedSubset'){
                $compare=Test-DERExpectedSubset -Actual $read -Expected $expected
                if(-not $compare.Success){throw (New-DERWorkloadFailureException -Message 'Driver policy failed read-back validation.')}
            }
            $assignments=Invoke-DERGraphCollectionRequest -Uri "$uri/assignments" -ApiVersion beta -Component 'Drivers' -ActionId $actionId
            if(-not @($assignments|Where-Object{[string]$_.target.groupId -eq [string]$group.ObjectId}).Count){throw (New-DERWorkloadFailureException -Message 'Driver policy assignment failed read-back validation.')}

            Update-DERStateObject -ObjectId $created.id -MarkValidated | Out-Null
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message=("Automatic driver profile created with {0}-day deployment deferral and validated." -f $body.deploymentDeferralInDays);ActionId=$actionId})
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Drivers' -ActionId $actionId -DerId $p.DerId}

            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
        }
    }
    return Complete-DERDriversResult -Results $results -RunId $RunId
}

Export-ModuleMember -Function @('New-DERDriverProfileBody','Invoke-DERDriversModule')
