<#
.SYNOPSIS
    DER Endpoint Analytics enablement workload.

.DESCRIPTION
    Enables Endpoint Analytics data collection by creating a Windows Health
    Monitoring configuration assigned only to the DER Pilot device group.
    Optional Microsoft aggregate-data sharing is not enabled.
#>


# Maintenance notes
# Responsibility: Manages approved Intune analytics configuration and validates assignment/read-back.
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


function Test-DERAnalyticsCommand{param([Parameter(Mandatory)][string]$Name)return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Save-DERAnalyticsResult{param($Result)$ctx=if(Test-DERAnalyticsCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 80|Set-Content -LiteralPath(Join-Path $d 'Analytics.json') -Encoding UTF8}}
function Get-DERAnalyticsStateObject{param([Parameter(Mandatory)][string]$DerId)if(Test-DERAnalyticsCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null}
function New-DERAnalyticsAssignmentBody{param([Parameter(Mandatory)][string]$GroupId)return [ordered]@{assignments=@([ordered]@{'@odata.type'='#microsoft.graph.deviceConfigurationAssignment';target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}}
function New-DERAnalyticsBody{param([Parameter(Mandatory)]$Planned)return [ordered]@{'@odata.type'='#microsoft.graph.windowsHealthMonitoringConfiguration';displayName=$Planned.DisplayName;description='Customer Endpoint Analytics data-collection policy. Pilot devices only.';roleScopeTagIds=@('0');allowDeviceHealthMonitoring='enabled';configDeviceHealthMonitoringScope='healthMonitoring'}}
function Complete-DERAnalyticsResult{
    param($Results,[string]$RunId)
    $s=[pscustomobject]@{Created=@($Results|Where-Object Status -eq 'Created').Count;Existing=@($Results|Where-Object Status -eq 'Existing').Count;Skipped=@($Results|Where-Object Status -eq 'Skipped').Count;Failed=@($Results|Where-Object Status -eq 'Failed').Count}
    $o=[pscustomobject]@{Module='Analytics';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)}
    Save-DERAnalyticsResult -Result $o
    return $o
}
function Invoke-DERAnalyticsModule{
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)

    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled -and $_.Module -eq 'Analytics'})
    $results=New-Object System.Collections.Generic.List[object]
    if(-not $planned.Count){return Complete-DERAnalyticsResult -Results $results -RunId $RunId}
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){foreach($p in $planned){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Endpoint Analytics health-monitoring profile creation requires a DER-approved Graph Preview API and Preview APIs are disabled.'})};return Complete-DERAnalyticsResult -Results $results -RunId $RunId}

    $pilot=Get-DERAnalyticsStateObject -DerId 'DER-GRP-D-010'
    if(-not $pilot){$results.Add([pscustomobject]@{DerId='DER-ANALYTICS-010';Status='Failed';Message='DER Pilot device group is missing.'});return Complete-DERAnalyticsResult -Results $results -RunId $RunId}
    try { Assert-DERManagedStateObject -StateRecord $pilot -Component 'Analytics' -ActionId 'EA-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Analytics' -ActionId 'EA-PILOT-PREFLIGHT' -DerId 'DER-GRP-D-010'}
 $results.Add([pscustomobject]@{DerId='DER-ANALYTICS-010';Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message)});return Complete-DERAnalyticsResult -Results $results -RunId $RunId }

    foreach($p in $planned){
        $actionId=if(Test-DERAnalyticsCommand 'New-DERActionId'){New-DERActionId -Component 'EA'}else{"EA-$($p.DerId)"}
        try{
            $state=Get-DERAnalyticsStateObject -DerId $p.DerId
            if($state){
                Assert-DERManagedStateObject -StateRecord $state -Component 'Analytics' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned Endpoint Analytics profile exists and matches recorded state.';ActionId=$actionId});continue
            }
            $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/deviceConfigurations' -ApiVersion beta -Component 'Analytics' -ActionId $actionId
            $collision=@($all|Where-Object{[string]$_.displayName -eq [string]$p.DisplayName})
            if($collision.Count){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned Endpoint Analytics profile exists; explicit DER adoption is required.';ActionId=$actionId});continue}

            $body=New-DERAnalyticsBody -Planned $p
            $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/deviceConfigurations' -ApiVersion beta -Body $body -Component 'Analytics' -DerId $p.DerId -ActionId $actionId
            if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'Endpoint Analytics profile create response did not include an object ID.')}
            $uri="deviceManagement/deviceConfigurations/$($created.id)"
            $expected=[pscustomobject]@{displayName=$p.DisplayName;allowDeviceHealthMonitoring='enabled';configDeviceHealthMonitoringScope='healthMonitoring'}
            $meta=[pscustomobject]@{Module='Analytics';ApiVersion='beta';ValidationUri=$uri;DeleteUri=$uri;ExpectedSubset=$expected;AssignmentUri="$uri/assignments";ExpectedAssignmentTargetId=[string]$pilot.ObjectId}
            Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null

            Invoke-DERGraphRequest -Method POST -Uri "$uri/assign" -ApiVersion beta -Body (New-DERAnalyticsAssignmentBody -GroupId $pilot.ObjectId) -Component 'Analytics' -DerId $p.DerId -ActionId $actionId|Out-Null
            $read=Invoke-DERGraphRequest -Method GET -Uri $uri -ApiVersion beta -Component 'Analytics' -DerId $p.DerId -ActionId $actionId
            if(Test-DERAnalyticsCommand 'Test-DERExpectedSubset'){$cmp=Test-DERExpectedSubset -Actual $read -Expected $expected;if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message 'Endpoint Analytics profile failed read-back validation.')}}
            $assignments=Invoke-DERGraphCollectionRequest -Uri "$uri/assignments" -ApiVersion beta -Component 'Analytics' -ActionId $actionId
            if(-not @($assignments|Where-Object{[string]$_.target.groupId -eq [string]$pilot.ObjectId}).Count){throw (New-DERWorkloadFailureException -Message 'Endpoint Analytics Pilot assignment failed read-back validation.')}
            Update-DERStateObject -ObjectId $created.id -MarkValidated|Out-Null
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Endpoint Analytics data collection enabled for Pilot devices and validated. Optional aggregate-data sharing was not enabled.';ActionId=$actionId})
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Analytics' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})}
    }
    return Complete-DERAnalyticsResult -Results $results -RunId $RunId
}
Export-ModuleMember -Function @('New-DERAnalyticsBody','Invoke-DERAnalyticsModule')
