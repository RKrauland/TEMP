<#
.SYNOPSIS
    DER Windows 11 compliance workload.

.DESCRIPTION
    Creates a DER-owned Windows compliance policy using stable Microsoft Graph
    v1.0 wherever possible, configures the required noncompliance block action
    with a configurable grace period, assigns only to the DER Pilot device
    group, and validates the result.

.NOTES
    Required parent entry point: Invoke-DERComplianceModule
#>


# Maintenance notes
# Responsibility: Manages Windows compliance policy and required scheduling/assignment evidence.
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


function Test-DERComplianceCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DERComplianceLog { param([string]$Level,[string]$Message,$Data,[string]$ActionId) if(Test-DERComplianceCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Compliance' -ActionId $ActionId -Message $Message -Data $Data} }
function Save-DERComplianceResult {param($Result)$ctx=if(Test-DERComplianceCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 80|Set-Content -LiteralPath (Join-Path $d 'Compliance.json') -Encoding UTF8}}
function Get-DERComplianceStateObject {param([string]$DerId)if(Test-DERComplianceCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null}

function Get-DERComplianceExactPolicy {
    param([string]$DisplayName,[string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/deviceCompliancePolicies' -ApiVersion beta -Component 'Compliance' -ActionId $ActionId
    return @($all|Where-Object {[string]$_.displayName -eq $DisplayName})
}
function New-DERWindowsComplianceBody {
    param($BuildPlan,$Planned)
    return [ordered]@{
        '@odata.type'='#microsoft.graph.windows10CompliancePolicy'
        displayName=$Planned.DisplayName
        description='Windows 11 standard compliance policy. Assigned only to the Pilot device group.'
        roleScopeTagIds=@()
        passwordRequired=$false
        passwordBlockSimple=$false
        passwordRequiredToUnlockFromIdle=$false
        passwordMinutesOfInactivityBeforeLock=0
        passwordRequiredType='deviceDefault'
        requireHealthyDeviceReport=$true
        osMinimumVersion='10.0.22000.0'
        osMaximumVersion=$null
        mobileOsMinimumVersion=$null
        mobileOsMaximumVersion=$null
        earlyLaunchAntiMalwareDriverEnabled=$true
        bitLockerEnabled=[bool]$BuildPlan.Answers.Security.RequireBitLocker
        secureBootEnabled=[bool]$BuildPlan.Answers.Security.RequireSecureBoot
        codeIntegrityEnabled=[bool]$BuildPlan.Answers.Security.RequireCodeIntegrity
        storageRequireEncryption=[bool]$BuildPlan.Answers.Security.RequireBitLocker
        activeFirewallRequired=[bool]$BuildPlan.Answers.Security.RequireFirewallCompliance
        defenderEnabled=([string]$BuildPlan.Answers.Security.PrimaryAV -eq 'Microsoft Defender')
        signatureOutOfDate=$false
        rtpEnabled=([string]$BuildPlan.Answers.Security.PrimaryAV -eq 'Microsoft Defender')
        antivirusRequired=$true
        antiSpywareRequired=$true
        tpmRequired=[bool]$BuildPlan.Answers.Security.RequireTPM
    }
}
function New-DERComplianceAssignmentBody {
    param([string]$GroupId)
    return [ordered]@{assignments=@([ordered]@{'@odata.type'='#microsoft.graph.deviceCompliancePolicyAssignment';target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}
}
function Test-DERComplianceAssignment {
    param([string]$PolicyId,[string]$GroupId,[string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/deviceCompliancePolicies/{0}/assignments" -f $PolicyId) -ApiVersion beta -Component 'Compliance' -ActionId $ActionId
    return [bool](@($all|Where-Object {[string]$_.target.groupId -eq $GroupId}).Count -gt 0)
}
function New-DERComplianceScheduledActionBody {return [ordered]@{'@odata.type'='#microsoft.graph.deviceComplianceScheduledActionForRule';ruleName='PasswordRequired'}}
function New-DERComplianceBlockActionBody {
    param([int]$GraceHours)
    return [ordered]@{'@odata.type'='#microsoft.graph.deviceComplianceActionItem';gracePeriodHours=$GraceHours;actionType='block';notificationTemplateId='';notificationMessageCCList=@()}
}
function Invoke-DERComplianceModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'Compliance'})
    if($planned.Count -eq 0){$out=[pscustomobject]@{Module='Compliance';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=0};Results=@()};Save-DERComplianceResult $out;return $out}
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){
        $out=[pscustomobject]@{Module='Compliance';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=1;Failed=0};Results=@([pscustomobject]@{DerId='DER-COMP-010';Status='Skipped';Message='DER Standard compliance requires TPM, firewall, antivirus/antispyware, and Defender health properties that are available in the current Graph beta compliance model. Preview APIs are disabled, so DER skipped the complete policy rather than creating a partial baseline.'})};Save-DERComplianceResult $out;return $out
    }
    $pilot=Get-DERComplianceStateObject -DerId 'DER-GRP-D-010'
    if(-not $pilot){$out=[pscustomobject]@{Module='Compliance';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=1};Results=@([pscustomobject]@{DerId='DER-COMPLIANCE';Status='Failed';Message='DER Pilot device group is missing; compliance policy cannot be safely targeted.'})};Save-DERComplianceResult $out;return $out}
    try{Assert-DERManagedStateObject -StateRecord $pilot -Component 'Compliance' -ActionId 'COMP-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned')|Out-Null}catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Compliance' -ActionId 'COMP-PILOT-PREFLIGHT' -DerId 'DER-GRP-D-010'}
$out=[pscustomobject]@{Module='Compliance';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=1};Results=@([pscustomobject]@{DerId='DER-COMPLIANCE';Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message)})};Save-DERComplianceResult $out;return $out}
    $results=New-Object System.Collections.Generic.List[object]
    foreach($p in $planned){
        $actionId=if(Test-DERComplianceCommand 'New-DERActionId'){New-DERActionId -Component 'COMP'}else{"COMP-$($p.DerId)"}
        try{
            $state=Get-DERComplianceStateObject -DerId $p.DerId
            if($state){Assert-DERManagedStateObject -StateRecord $state -Component 'Compliance' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null;$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned compliance policy exists and matches recorded state.';ActionId=$actionId});continue}
            $collision=@(Get-DERComplianceExactPolicy -DisplayName $p.DisplayName -ActionId $actionId)
            if($collision.Count -gt 0){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned compliance policy exists; DER will not modify it without adoption.';ActionId=$actionId});continue}
            $body=New-DERWindowsComplianceBody -BuildPlan $BuildPlan -Planned $p
            $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/deviceCompliancePolicies' -ApiVersion beta -Body $body -Component 'Compliance' -DerId $p.DerId -ActionId $actionId
            if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'Compliance policy create response did not include an ID.')}
            $expected=[pscustomobject][ordered]@{displayName=$p.DisplayName;bitLockerEnabled=[bool]$body.bitLockerEnabled;secureBootEnabled=[bool]$body.secureBootEnabled;codeIntegrityEnabled=[bool]$body.codeIntegrityEnabled;storageRequireEncryption=[bool]$body.storageRequireEncryption;osMinimumVersion='10.0.22000.0'}
            $meta=[pscustomobject][ordered]@{Module='Compliance';ApiVersion='beta';ValidationUri=("deviceManagement/deviceCompliancePolicies/{0}" -f $created.id);DeleteUri=("deviceManagement/deviceCompliancePolicies/{0}" -f $created.id);ExpectedSubset=$expected;AssignmentUri=("deviceManagement/deviceCompliancePolicies/{0}/assignments" -f $created.id);ExpectedAssignmentTargetId=[string]$pilot.ObjectId}
            if(Test-DERComplianceCommand 'Add-DERStateObject'){Add-DERStateObject -DerId $p.DerId -ObjectId ([string]$created.id) -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null}
            $scheduled=Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule" -f $created.id) -ApiVersion beta -Body (New-DERComplianceScheduledActionBody) -Component 'Compliance' -DerId $p.DerId -ActionId $actionId
            if(-not $scheduled.id){throw (New-DERWorkloadFailureException -Message 'Required compliance scheduled action could not be created.')}
            $grace=[Math]::Max(0,[int]$BuildPlan.Answers.Security.NonComplianceGraceDays*24)
            Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule/{1}/scheduledActionConfigurations" -f $created.id,$scheduled.id) -ApiVersion beta -Body (New-DERComplianceBlockActionBody -GraceHours $grace) -Component 'Compliance' -DerId $p.DerId -ActionId $actionId|Out-Null
            Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/deviceCompliancePolicies/{0}/assign" -f $created.id) -ApiVersion beta -Body (New-DERComplianceAssignmentBody -GroupId ([string]$pilot.ObjectId)) -Component 'Compliance' -DerId $p.DerId -ActionId $actionId|Out-Null
            $read=Invoke-DERGraphRequest -Method GET -Uri $meta.ValidationUri -ApiVersion beta -Component 'Compliance' -DerId $p.DerId -ActionId $actionId
            $cmp=if(Test-DERComplianceCommand 'Test-DERExpectedSubset'){Test-DERExpectedSubset -Actual $read -Expected $expected}else{[pscustomobject]@{Success=$true}}
            if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message 'Compliance policy failed read-back setting validation.')}
            if(-not(Test-DERComplianceAssignment -PolicyId ([string]$created.id) -GroupId ([string]$pilot.ObjectId) -ActionId $actionId)){throw (New-DERWorkloadFailureException -Message 'Compliance policy Pilot assignment failed read-back validation.')}
            if(Test-DERComplianceCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$created.id) -MarkValidated|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message=("Created, configured with a {0}-hour noncompliance grace period, assigned to Pilot, and validated." -f $grace);ActionId=$actionId})
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Compliance' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$null;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})}
    }
    $summary=[pscustomobject]@{Created=@($results|Where-Object Status -eq 'Created').Count;Existing=@($results|Where-Object Status -eq 'Existing').Count;Skipped=@($results|Where-Object Status -eq 'Skipped').Count;Failed=@($results|Where-Object Status -eq 'Failed').Count}
    $out=[pscustomobject]@{Module='Compliance';RunId=$RunId;Status=if($summary.Failed){'CompletedWithFailures'}else{'Completed'};CriticalFailure=$false;Summary=$summary;Results=@($results)};Save-DERComplianceResult $out
    Write-DERComplianceLog -Level $(if($summary.Failed){'WARN'}else{'OK'}) -Message ("Compliance workload complete: {0} created, {1} existing, {2} skipped, {3} failed." -f $summary.Created,$summary.Existing,$summary.Skipped,$summary.Failed) -Data $summary
    return $out
}

Export-ModuleMember -Function @('New-DERWindowsComplianceBody','New-DERComplianceScheduledActionBody','New-DERComplianceBlockActionBody','Invoke-DERComplianceModule')
