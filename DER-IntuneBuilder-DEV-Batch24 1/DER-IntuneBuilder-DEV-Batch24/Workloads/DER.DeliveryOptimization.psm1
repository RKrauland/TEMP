<#
.SYNOPSIS
    DER Delivery Optimization workload.

.DESCRIPTION
    Creates a conservative Pilot-only Windows Delivery Optimization profile for
    bandwidth-constrained environments. It enables LAN/NAT peer delivery,
    restricts peer selection to the local subnet, and disables VPN peer caching.
#>


# Maintenance notes
# Responsibility: Manages approved Delivery Optimization profile and validates Pilot assignment.
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


function Test-DERDOCommand{param([Parameter(Mandatory)][string]$Name)return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Save-DERDOResult{param($Result)$ctx=if(Test-DERDOCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 80|Set-Content -LiteralPath(Join-Path $d 'DeliveryOptimization.json') -Encoding UTF8}}
function Get-DERDOStateObject{param([Parameter(Mandatory)][string]$DerId)if(Test-DERDOCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null}
function New-DERDOAssignmentBody{param([Parameter(Mandatory)][string]$GroupId)return [ordered]@{assignments=@([ordered]@{'@odata.type'='#microsoft.graph.deviceConfigurationAssignment';target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}}
function New-DERDeliveryOptimizationBody{
    param([Parameter(Mandatory)]$Planned)
    return [ordered]@{
        '@odata.type'='#microsoft.graph.windowsDeliveryOptimizationConfiguration'
        displayName=$Planned.DisplayName
        description='Customer Delivery Optimization baseline for bandwidth-constrained sites. Pilot devices only.'
        roleScopeTagIds=@('0')
        deliveryOptimizationMode='httpWithPeeringNat'
        restrictPeerSelectionBy='subnetMask'
        backgroundDownloadFromHttpDelayInSeconds=60
        foregroundDownloadFromHttpDelayInSeconds=0
        minimumRamAllowedToPeerInGigabytes=4
        minimumDiskSizeAllowedToPeerInGigabytes=64
        minimumFileSizeToCacheInMegabytes=10
        minimumBatteryPercentageAllowedToUpload=40
        maximumCacheAgeInDays=7
        vpnPeerCaching='disabled'
    }
}
function Complete-DERDOResult{
    param($Results,[string]$RunId)
    $s=[pscustomobject]@{Created=@($Results|Where-Object Status -eq 'Created').Count;Existing=@($Results|Where-Object Status -eq 'Existing').Count;Skipped=@($Results|Where-Object Status -eq 'Skipped').Count;Failed=@($Results|Where-Object Status -eq 'Failed').Count}
    $o=[pscustomobject]@{Module='DeliveryOptimization';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)}
    Save-DERDOResult -Result $o
    return $o
}
function Invoke-DERDeliveryOptimizationModule{
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)

    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled -and $_.Module -eq 'DeliveryOptimization'})
    $results=New-Object System.Collections.Generic.List[object]
    if(-not $planned.Count){return Complete-DERDOResult -Results $results -RunId $RunId}
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){foreach($p in $planned){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Delivery Optimization policy creation requires a DER-approved Graph Preview API and Preview APIs are disabled.'})};return Complete-DERDOResult -Results $results -RunId $RunId}

    $pilot=Get-DERDOStateObject -DerId 'DER-GRP-D-010'
    if(-not $pilot){$results.Add([pscustomobject]@{DerId='DER-DO-010';Status='Failed';Message='DER Pilot device group is missing.'});return Complete-DERDOResult -Results $results -RunId $RunId}
    try { Assert-DERManagedStateObject -StateRecord $pilot -Component 'DeliveryOptimization' -ActionId 'DO-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'DeliveryOptimization' -ActionId 'DO-PILOT-PREFLIGHT' -DerId 'DER-GRP-D-010'}
 $results.Add([pscustomobject]@{DerId='DER-DO-010';Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message)});return Complete-DERDOResult -Results $results -RunId $RunId }

    foreach($p in $planned){
        $actionId=if(Test-DERDOCommand 'New-DERActionId'){New-DERActionId -Component 'DO'}else{"DO-$($p.DerId)"}
        try{
            $state=Get-DERDOStateObject -DerId $p.DerId
            if($state){
                Assert-DERManagedStateObject -StateRecord $state -Component 'DeliveryOptimization' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned Delivery Optimization profile exists and matches recorded state.';ActionId=$actionId});continue
            }
            $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/deviceConfigurations' -ApiVersion beta -Component 'DeliveryOptimization' -ActionId $actionId
            $collision=@($all|Where-Object{[string]$_.displayName -eq [string]$p.DisplayName})
            if($collision.Count){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned Delivery Optimization profile exists; explicit DER adoption is required.';ActionId=$actionId});continue}

            $body=New-DERDeliveryOptimizationBody -Planned $p
            $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/deviceConfigurations' -ApiVersion beta -Body $body -Component 'DeliveryOptimization' -DerId $p.DerId -ActionId $actionId
            if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'Delivery Optimization create response did not include an object ID.')}
            $uri="deviceManagement/deviceConfigurations/$($created.id)"
            $expected=[pscustomobject]@{displayName=$p.DisplayName;deliveryOptimizationMode='httpWithPeeringNat';restrictPeerSelectionBy='subnetMask';vpnPeerCaching='disabled'}
            $meta=[pscustomobject]@{Module='DeliveryOptimization';ApiVersion='beta';ValidationUri=$uri;DeleteUri=$uri;ExpectedSubset=$expected;AssignmentUri="$uri/assignments";ExpectedAssignmentTargetId=[string]$pilot.ObjectId}
            Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null

            Invoke-DERGraphRequest -Method POST -Uri "$uri/assign" -ApiVersion beta -Body (New-DERDOAssignmentBody -GroupId $pilot.ObjectId) -Component 'DeliveryOptimization' -DerId $p.DerId -ActionId $actionId|Out-Null
            $read=Invoke-DERGraphRequest -Method GET -Uri $uri -ApiVersion beta -Component 'DeliveryOptimization' -DerId $p.DerId -ActionId $actionId
            if(Test-DERDOCommand 'Test-DERExpectedSubset'){$cmp=Test-DERExpectedSubset -Actual $read -Expected $expected;if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message 'Delivery Optimization profile failed read-back validation.')}}
            $assignments=Invoke-DERGraphCollectionRequest -Uri "$uri/assignments" -ApiVersion beta -Component 'DeliveryOptimization' -ActionId $actionId
            if(-not @($assignments|Where-Object{[string]$_.target.groupId -eq [string]$pilot.ObjectId}).Count){throw (New-DERWorkloadFailureException -Message 'Delivery Optimization Pilot assignment failed read-back validation.')}
            Update-DERStateObject -ObjectId $created.id -MarkValidated|Out-Null
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Delivery Optimization Pilot policy created and validated.';ActionId=$actionId})
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'DeliveryOptimization' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})}
    }
    return Complete-DERDOResult -Results $results -RunId $RunId
}
Export-ModuleMember -Function @('New-DERDeliveryOptimizationBody','Invoke-DERDeliveryOptimizationModule')
