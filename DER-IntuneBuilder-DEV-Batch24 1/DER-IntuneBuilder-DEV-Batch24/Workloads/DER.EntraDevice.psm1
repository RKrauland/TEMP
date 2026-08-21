<#
.SYNOPSIS
    DER Microsoft Entra device-registration policy workload.

.DESCRIPTION
    Safely configures the built-in Microsoft Entra deviceRegistrationPolicy only
    when the approved DER plan and environment classification make the change
    safe. Required PUT properties are preserved from current Microsoft state;
    DER changes only approved Entra Join/local-admin properties.

.NOTES
    Required parent entry point: Invoke-DEREntraDeviceModule
#>


# Maintenance notes
# Responsibility: Manages approved Entra device-registration policy state while respecting shared-singleton ownership.
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


function Test-DEREntraDeviceCommand {param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DEREntraDeviceLog {param([string]$Level,[string]$Message,$Data,[string]$ActionId)if(Test-DEREntraDeviceCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'EntraDevice' -ActionId $ActionId -Message $Message -Data $Data}}
function Save-DEREntraDeviceResult {param($Result)$ctx=if(Test-DEREntraDeviceCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$dir=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $dir -Force|Out-Null;$Result|ConvertTo-Json -Depth 80|Set-Content -LiteralPath (Join-Path $dir 'EntraDevice.json') -Encoding UTF8}}
function Copy-DERDeviceRegistrationBody {
    param([Parameter(Mandatory)]$Current)
    return [ordered]@{
        userDeviceQuota=[int]$Current.userDeviceQuota
        multiFactorAuthConfiguration=[string]$Current.multiFactorAuthConfiguration
        azureADRegistration=$Current.azureADRegistration
        azureADJoin=$Current.azureADJoin
        localAdminPassword=$Current.localAdminPassword
    }
}
function Invoke-DEREntraDeviceModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'EntraDevice'}|Select-Object -First 1)
    if(-not$planned){$out=[pscustomobject]@{Module='EntraDevice';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Updated=0;Skipped=0;Failed=0};Results=@()};Save-DEREntraDeviceResult $out;return$out}
    $p=$planned[0]
    $actionId=if(Test-DEREntraDeviceCommand 'New-DERActionId'){New-DERActionId -Component 'ENTRADEV'}else{'ENTRADEV-001'}
    $results=New-Object System.Collections.Generic.List[object]
    Write-DEREntraDeviceLog -Level STEP -Message 'Evaluating Microsoft Entra device registration policy.' -Data @{tenantId=$BuildPlan.TenantId;environmentClass=$BuildPlan.EnvironmentClassification} -ActionId $actionId
    try{
        $current=Invoke-DERGraphRequest -Method GET -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Component 'EntraDevice' -ActionId $actionId
        $appearsExisting=([string]$BuildPlan.EnvironmentClassification -ne 'NewOrMostlyEmpty')
        if($BuildPlan.Safety.ChangeControl -eq 'Report-only / no tenant writes'){
            $msg='Run is report-only; built-in device registration policy preserved.';$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='deviceRegistrationPolicy';Status='Skipped';Message=$msg;ActionId=$actionId});$out=[pscustomobject]@{Module='EntraDevice';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Updated=0;Skipped=1;Failed=0};Results=@($results)};Save-DEREntraDeviceResult $out;return$out
        }
        if($appearsExisting -and $BuildPlan.Profile -ne 'Custom'){
            $msg='Existing tenant detected. DER preserved the tenant-wide Entra Join authorization policy because restricting it to an empty pilot/enrollment group could interrupt existing provisioning. Review/adopt explicitly before changing.'
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='deviceRegistrationPolicy';Status='Skipped';Message=$msg;ActionId=$actionId});if(Test-DEREntraDeviceCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase SKIP -Module 'EntraDevice' -DerId $p.DerId -ObjectId 'deviceRegistrationPolicy' -Message $msg|Out-Null};$out=[pscustomobject]@{Module='EntraDevice';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Updated=0;Skipped=1;Failed=0};Results=@($results)};Save-DEREntraDeviceResult $out;return$out
        }
        $enrollGroup=if(Test-DEREntraDeviceCommand 'Get-DERStateObject'){Get-DERStateObject -DerId 'DER-GRP-U-080'}else{$null}
        if(-not$enrollGroup){throw (New-DERWorkloadFailureException -Message 'DER Intune Enrollment group is not available in state; Entra Join scope cannot be safely configured.')}
        Assert-DERManagedStateObject -StateRecord $enrollGroup -Component 'EntraDevice' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') | Out-Null
        $body=Copy-DERDeviceRegistrationBody -Current $current
        $body.azureADJoin=[ordered]@{isAdminConfigurable=$true;allowedToJoin=[ordered]@{'@odata.type'='#microsoft.graph.enumeratedDeviceRegistrationMembership';users=@();groups=@([string]$enrollGroup.ObjectId)};localAdmins=[ordered]@{enableGlobalAdmins=[bool]$BuildPlan.Answers.Enrollment.GlobalAdminsLocalAdmins;registeringUsers=[ordered]@{'@odata.type'='#microsoft.graph.noDeviceRegistrationMembership'}}}
        $expected=[pscustomobject]@{azureADJoin=[ordered]@{allowedToJoin=[ordered]@{'@odata.type'='#microsoft.graph.enumeratedDeviceRegistrationMembership';users=@();groups=@([string]$enrollGroup.ObjectId)};localAdmins=[ordered]@{enableGlobalAdmins=[bool]$BuildPlan.Answers.Enrollment.GlobalAdminsLocalAdmins;registeringUsers=[ordered]@{'@odata.type'='#microsoft.graph.noDeviceRegistrationMembership'}}}}
        $original=Copy-DERDeviceRegistrationBody -Current $current
        $state=if(Test-DEREntraDeviceCommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
        if($state){
            if([string]$state.OwnershipClass-ne'DER-Adopted'){throw (New-DERWorkloadFailureException -Message "EntraDevice state '$($p.DerId)' is not DER-Adopted; automatic update refused.")}
            Assert-DERManagedStateObject -StateRecord $state -Component 'EntraDevice' -ActionId $actionId -AllowedOwnershipClass @('DER-Adopted')|Out-Null
        }
        $baseMeta=[pscustomobject]@{Module='EntraDevice';ApiVersion='v1.0';ValidationUri='policies/deviceRegistrationPolicy';ExpectedSubset=$original;BuiltInTenantObject=$true;AdoptionNoTenantWrite=$true}
        if(-not$state){$state=Add-DERStateObject -DerId $p.DerId -ObjectId 'deviceRegistrationPolicy' -ObjectType 'DeviceRegistrationPolicy' -DisplayName $p.DisplayName -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $baseMeta}
        $rollback=[pscustomobject]@{Module='EntraDevice';ApiVersion='v1.0';ValidationUri='policies/deviceRegistrationPolicy';UpdateUri='policies/deviceRegistrationPolicy';UpdateMethod='PUT';ExpectedSubset=$expected;OriginalState=$original;OriginalExpectedSubset=$original;BuiltInTenantObject=$true}
        $state=Set-DERAdoptedRollbackPreparation -ObjectId ([string]$state.ObjectId) -RunId $RunId -ActionId $actionId -RollbackMetadata $rollback
        if(Test-DEREntraDeviceCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase RECORD_ORIGINAL -Module 'EntraDevice' -DerId $p.DerId -ObjectId 'deviceRegistrationPolicy' -Message 'Recorded original deviceRegistrationPolicy before approved PUT.' -Data $original|Out-Null}
        Invoke-DERGraphRequest -Method PUT -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Body $body -Component 'EntraDevice' -DerId $p.DerId -ActionId $actionId|Out-Null
        Assert-DERManagedStateObject -StateRecord (Get-DERStateObject -ObjectId 'deviceRegistrationPolicy') -Component 'EntraDevice' -ActionId $actionId -AllowedOwnershipClass @('DER-Adopted') -MarkValidated|Out-Null
        Clear-DERAdoptedRollbackPreparation -ObjectId 'deviceRegistrationPolicy' -RunId $RunId -ActionId $actionId|Out-Null
        if(Test-DEREntraDeviceCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module 'EntraDevice' -DerId $p.DerId -ObjectId 'deviceRegistrationPolicy' -Message 'Entra device registration policy updated and validated.'|Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='deviceRegistrationPolicy';Status='Updated';Message='Approved Entra Join scope/local-admin configuration applied and validated; other required policy properties preserved.';ActionId=$actionId})
    } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'EntraDevice' -ActionId $actionId -DerId $p.DerId}

        if(Test-DEREntraDeviceCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase FAIL -Module 'EntraDevice' -DerId $p.DerId -ObjectId 'deviceRegistrationPolicy' -Message $_.Exception.Message|Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId='deviceRegistrationPolicy';Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
    }
    $summary=[pscustomobject]@{Updated=@($results|Where-Object {$_.Status -eq 'Updated'}).Count;Skipped=@($results|Where-Object {$_.Status -eq 'Skipped'}).Count;Failed=@($results|Where-Object {$_.Status -eq 'Failed'}).Count}
    $out=[pscustomobject][ordered]@{Module='EntraDevice';RunId=$RunId;Status=if($summary.Failed -gt 0){'CompletedWithFailures'}elseif($summary.Updated -gt 0){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$summary;Results=@($results)};Save-DEREntraDeviceResult $out
    Write-DEREntraDeviceLog -Level $(if($summary.Failed -gt 0){'WARN'}else{'OK'}) -Message ("EntraDevice workload complete: {0} updated, {1} skipped, {2} failed." -f $summary.Updated,$summary.Skipped,$summary.Failed) -Data $summary -ActionId $actionId
    return$out
}
Export-ModuleMember -Function @('Copy-DERDeviceRegistrationBody','Invoke-DEREntraDeviceModule')
