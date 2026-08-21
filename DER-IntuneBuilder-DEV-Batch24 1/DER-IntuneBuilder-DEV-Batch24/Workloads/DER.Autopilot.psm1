<#
.SYNOPSIS
    DER Windows Autopilot and Enrollment Status Page workload.

.DESCRIPTION
    Creates DER-owned Windows Autopilot deployment profiles and an Enrollment
    Status Page, assigns them only to DER-owned device groups, reads everything
    back, and validates before committing ownership state.

    Traditional Windows Autopilot deployment profile operations currently use
    Microsoft Graph beta and are therefore gated by DER Safe Preview approval.

.NOTES
    Required parent entry point: Invoke-DERAutopilotModule
#>


# Maintenance notes
# Responsibility: Manages approved Autopilot deployment profiles and Enrollment Status Page configuration with exact group targeting.
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


function Test-DERAutopilotCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DERAutopilotLog { param([string]$Level,[string]$Message,$Data,[string]$ActionId,[string]$DerId) if(Test-DERAutopilotCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Autopilot' -DerId $DerId -ActionId $ActionId -Message $Message -Data $Data} }
function Save-DERAutopilotResult {
    param($Result)
    $ctx=if(Test-DERAutopilotCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null}
    if($ctx){$dir=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $dir -Force|Out-Null;$Result|ConvertTo-Json -Depth 80|Set-Content -LiteralPath (Join-Path $dir 'Autopilot.json') -Encoding UTF8}
}
function Get-DERAutopilotStateObject { param([string]$DerId) if(Test-DERAutopilotCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null }

function Get-DERAutopilotExactProfile {
    param([Parameter(Mandatory)][string]$DisplayName,[Parameter(Mandatory)][string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/windowsAutopilotDeploymentProfiles' -ApiVersion beta -Component 'Autopilot' -ActionId $ActionId
    return @($all|Where-Object {[string]$_.displayName -eq $DisplayName})
}
function Get-DERAutopilotExactEnrollmentConfig {
    param([Parameter(Mandatory)][string]$DisplayName,[Parameter(Mandatory)][string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/deviceEnrollmentConfigurations' -ApiVersion v1.0 -Component 'Autopilot' -ActionId $ActionId
    return @($all|Where-Object {[string]$_.displayName -eq $DisplayName})
}
function New-DERAutopilotProfileBody {
    param($BuildPlan,$Planned,[ValidateSet('singleUser','shared')][string]$DeviceUsageType='singleUser')
    $userType=if([string]$BuildPlan.Answers.Enrollment.EndUserAccountType -eq 'Local Administrator'){'administrator'}else{'standard'}
    $extract=([string]$BuildPlan.Answers.Enrollment.ExistingDeviceAutopilotAction -eq 'Convert approved targeted devices')
    if($DeviceUsageType -eq 'shared'){$extract=$false}
    return [ordered]@{
        '@odata.type'='#microsoft.graph.azureADWindowsAutopilotDeploymentProfile'
        displayName=$Planned.DisplayName
        description=if($DeviceUsageType -eq 'shared'){'Windows Autopilot self-deploying/shared-device profile. Assigned only to the empty self-deploying device group.'}else{'Windows Autopilot user-driven Microsoft Entra join profile. Assigned only to the Autopilot Windows device group.'}
        locale='os-default'
        outOfBoxExperienceSetting=[ordered]@{
            '@odata.type'='microsoft.graph.outOfBoxExperienceSetting'
            privacySettingsHidden=[bool]$BuildPlan.Answers.Enrollment.HidePrivacyOobe
            eulaHidden=$true
            userType=$userType
            deviceUsageType=$DeviceUsageType
            keyboardSelectionPageSkipped=$false
            escapeLinkHidden=$true
        }
        enrollmentStatusScreenSettings=[ordered]@{
            '@odata.type'='microsoft.graph.windowsEnrollmentStatusScreenSettings'
            hideInstallationProgress=$false
            allowDeviceUseBeforeProfileAndAppInstallComplete=$false
            blockDeviceSetupRetryByUser=$false
            allowLogCollectionOnInstallFailure=$true
            customErrorMessage='Device setup could not complete. Contact your IT support team.'
            installProgressTimeoutInMinutes=[int]$BuildPlan.Answers.Enrollment.ESPTimeoutMinutes
            allowDeviceUseOnInstallFailure=[bool]$BuildPlan.Answers.Enrollment.ESPAllowContinueOnFailure
        }
        hardwareHashExtractionEnabled=$extract
        deviceNameTemplate=if($DeviceUsageType -eq 'shared'){$null}else{[string]$BuildPlan.Answers.Enrollment.ComputerNameTemplate}
        deviceType='windowsPc'
        preprovisioningAllowed=if($DeviceUsageType -eq 'shared'){$false}else{[bool]$BuildPlan.Answers.Enrollment.PreProvisioning}
        roleScopeTagIds=@()
    }
}
function New-DERAutopilotAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId)
    return [ordered]@{
        assignments=@(
            [ordered]@{
                '@odata.type'='#microsoft.graph.windowsAutopilotDeploymentProfileAssignment'
                target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}
            }
        )
    }
}
function Test-DERAutopilotProfileAssignment {
    param([Parameter(Mandatory)][string]$ProfileId,[Parameter(Mandatory)][string]$GroupId,[Parameter(Mandatory)][string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/windowsAutopilotDeploymentProfiles/{0}/assignments" -f $ProfileId) -ApiVersion beta -Component 'Autopilot' -ActionId $ActionId
    return [bool](@($all|Where-Object {[string]$_.target.groupId -eq $GroupId}).Count -gt 0)
}
function New-DERESPBody {
    param($BuildPlan,$Planned)
    return [ordered]@{
        '@odata.type'='#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'
        displayName=$Planned.DisplayName
        description='Windows Autopilot Enrollment Status Page. Targeted only to the Autopilot Windows device group.'
        priority=1
        version=1
        allowNonBlockingAppInstallation=$true
    }
}
function New-DERESPAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId)
    return [ordered]@{
        '@odata.type'='#microsoft.graph.enrollmentConfigurationAssignment'
        target=[ordered]@{
            '@odata.type'='microsoft.graph.scopeTagGroupAssignmentTarget'
            targetType='device'
            entraObjectId=$GroupId
        }
    }
}
function Test-DERESPAssignment {
    param([Parameter(Mandatory)][string]$ConfigurationId,[Parameter(Mandatory)][string]$GroupId,[Parameter(Mandatory)][string]$ActionId,[Parameter(Mandatory)][string]$DerId)
    $r=Invoke-DERGraphRequest -Method GET -Uri ("deviceManagement/deviceEnrollmentConfigurations/{0}/assignments" -f $ConfigurationId) -ApiVersion v1.0 -Component 'Autopilot' -DerId $DerId -ActionId $ActionId
    return [bool](@($r.value|Where-Object {[string]$_.target.entraObjectId -eq $GroupId -and [string]$_.target.targetType -eq 'device'}).Count -gt 0)
}
function Register-DERAutopilotOwnedObject {
    param($Planned,$Created,[string]$RunId,$BuildPlan,[string]$ApiVersion,[string]$ValidationUri,[string]$DeleteUri,$ExpectedSubset,[string]$AssignmentUri,[string]$AssignmentGroupId)
    $meta=[pscustomobject][ordered]@{Module='Autopilot';ApiVersion=$ApiVersion;ValidationUri=$ValidationUri;DeleteUri=$DeleteUri;ExpectedSubset=$ExpectedSubset;AssignmentUri=$AssignmentUri;ExpectedAssignmentTargetId=$AssignmentGroupId}
    if(Test-DERAutopilotCommand 'Add-DERStateObject'){
        Add-DERStateObject -DerId $Planned.DerId -ObjectId ([string]$Created.id) -ObjectType $Planned.ObjectType -DisplayName $Planned.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null
    }
    return $meta
}
function Invoke-DERCreateAutopilotProfile {
    param($Planned,$BuildPlan,[string]$RunId,[string]$GroupId,[ValidateSet('singleUser','shared')][string]$DeviceUsageType,[Parameter(Mandatory)][string]$ActionId)
    $state=Get-DERAutopilotStateObject -DerId $Planned.DerId
    if($state){
        Assert-DERManagedStateObject -StateRecord $state -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId -MarkValidated | Out-Null
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned Autopilot profile exists and matches recorded state.';ActionId=$ActionId}
    }
    $collision=@(Get-DERAutopilotExactProfile -DisplayName $Planned.DisplayName -ActionId $ActionId)
    if($collision.Count -gt 0){return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned Autopilot profile exists; DER will not modify it without adoption.';ActionId=$ActionId}}
    $body=New-DERAutopilotProfileBody -BuildPlan $BuildPlan -Planned $Planned -DeviceUsageType $DeviceUsageType
    if(Test-DERAutopilotCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $ActionId -Phase PRECHECK -Module 'Autopilot' -DerId $Planned.DerId -Message 'Prepared DER Autopilot profile create.' -Data @{displayName=$Planned.DisplayName;usage=$DeviceUsageType}|Out-Null}
    $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/windowsAutopilotDeploymentProfiles' -ApiVersion beta -Body $body -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId
    if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'Autopilot profile create response did not include an ID.')}
    $expected=[pscustomobject][ordered]@{displayName=$Planned.DisplayName;deviceType='windowsPc';preprovisioningAllowed=[bool]$body.preprovisioningAllowed}
    $meta=Register-DERAutopilotOwnedObject -Planned $Planned -Created $created -RunId $RunId -BuildPlan $BuildPlan -ApiVersion beta -ValidationUri ("deviceManagement/windowsAutopilotDeploymentProfiles/{0}" -f $created.id) -DeleteUri ("deviceManagement/windowsAutopilotDeploymentProfiles/{0}" -f $created.id) -ExpectedSubset $expected -AssignmentUri ("deviceManagement/windowsAutopilotDeploymentProfiles/{0}/assignments" -f $created.id) -AssignmentGroupId $GroupId
    Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/windowsAutopilotDeploymentProfiles/{0}/assign" -f $created.id) -ApiVersion beta -Body (New-DERAutopilotAssignmentBody -GroupId $GroupId) -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId|Out-Null
    $read=Invoke-DERGraphRequest -Method GET -Uri $meta.ValidationUri -ApiVersion beta -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId
    $cmp=if(Test-DERAutopilotCommand 'Test-DERExpectedSubset'){Test-DERExpectedSubset -Actual $read -Expected $expected}else{[pscustomobject]@{Success=$true}}
    if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message "Autopilot profile $($Planned.DerId) failed read-back validation.")}
    if(-not(Test-DERAutopilotProfileAssignment -ProfileId ([string]$created.id) -GroupId $GroupId -ActionId $ActionId)){throw (New-DERWorkloadFailureException -Message "Autopilot profile $($Planned.DerId) assignment failed read-back validation.")}
    if(Test-DERAutopilotCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$created.id) -MarkValidated|Out-Null}
    if(Test-DERAutopilotCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $ActionId -Phase COMMIT -Module 'Autopilot' -DerId $Planned.DerId -ObjectId $created.id -Message 'Autopilot profile created, assigned, and validated.'|Out-Null}
    return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$created.id;Status='Created';Message='Created, assigned, and validated.';ActionId=$ActionId}
}
function Invoke-DERCreateESP {
    param($Planned,$BuildPlan,[string]$RunId,[string]$GroupId,[Parameter(Mandatory)][string]$ActionId)
    $state=Get-DERAutopilotStateObject -DerId $Planned.DerId
    if($state){
        Assert-DERManagedStateObject -StateRecord $state -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId -MarkValidated | Out-Null
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned Enrollment Status Page exists and matches recorded state.';ActionId=$ActionId}
    }
    $collision=@(Get-DERAutopilotExactEnrollmentConfig -DisplayName $Planned.DisplayName -ActionId $ActionId)
    if($collision.Count -gt 0){return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned Enrollment Status Page exists; DER will not modify it without adoption.';ActionId=$ActionId}}
    $body=New-DERESPBody -BuildPlan $BuildPlan -Planned $Planned
    $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/deviceEnrollmentConfigurations' -ApiVersion v1.0 -Body $body -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId
    if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'ESP create response did not include an ID.')}
    $expected=[pscustomobject][ordered]@{displayName=$Planned.DisplayName;'@odata.type'='#microsoft.graph.windows10EnrollmentCompletionPageConfiguration';allowNonBlockingAppInstallation=$true}
    $meta=Register-DERAutopilotOwnedObject -Planned $Planned -Created $created -RunId $RunId -BuildPlan $BuildPlan -ApiVersion v1.0 -ValidationUri ("deviceManagement/deviceEnrollmentConfigurations/{0}" -f $created.id) -DeleteUri ("deviceManagement/deviceEnrollmentConfigurations/{0}" -f $created.id) -ExpectedSubset $expected -AssignmentUri ("deviceManagement/deviceEnrollmentConfigurations/{0}/assignments" -f $created.id) -AssignmentGroupId $GroupId
    Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/deviceEnrollmentConfigurations/{0}/assignments" -f $created.id) -ApiVersion v1.0 -Body (New-DERESPAssignmentBody -GroupId $GroupId) -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId|Out-Null
    $read=Invoke-DERGraphRequest -Method GET -Uri $meta.ValidationUri -ApiVersion v1.0 -Component 'Autopilot' -DerId $Planned.DerId -ActionId $ActionId
    $cmp=if(Test-DERAutopilotCommand 'Test-DERExpectedSubset'){Test-DERExpectedSubset -Actual $read -Expected $expected}else{[pscustomobject]@{Success=$true}}
    if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message 'Enrollment Status Page failed read-back validation.')}
    if(-not(Test-DERESPAssignment -ConfigurationId ([string]$created.id) -GroupId $GroupId -ActionId $ActionId -DerId $Planned.DerId)){throw (New-DERWorkloadFailureException -Message 'Enrollment Status Page assignment failed read-back validation.')}
    if(Test-DERAutopilotCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$created.id) -MarkValidated|Out-Null}
    return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$created.id;Status='Created';Message='Created, assigned to DER Autopilot Windows devices, and validated.';ActionId=$ActionId}
}
function Invoke-DERAutopilotModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)

    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'Autopilot'})
    if($planned.Count -eq 0){$out=[pscustomobject]@{Module='Autopilot';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=0};Results=@()};Save-DERAutopilotResult $out;return $out}
    $results=New-Object System.Collections.Generic.List[object]

    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){
        foreach($p in $planned){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$null;Status='Skipped';Message='Autopilot workload requires a DER-approved Microsoft Graph preview API path; Preview APIs are disabled for this build.';ActionId=$null})}
        $summary=[pscustomobject]@{Created=0;Existing=0;Skipped=$results.Count;Failed=0}
        $out=[pscustomobject]@{Module='Autopilot';RunId=$RunId;Status='Completed';CriticalFailure=$false;Summary=$summary;Results=@($results)};Save-DERAutopilotResult $out;return $out
    }

    $apGroup=Get-DERAutopilotStateObject -DerId 'DER-GRP-DY-D-040'
    if(-not $apGroup){
        $out=[pscustomobject]@{Module='Autopilot';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=1};Results=@([pscustomobject]@{DerId='DER-AUTOPILOT';Status='Failed';Message='DER Autopilot Windows dynamic group is missing; Autopilot cannot be safely targeted.'})};Save-DERAutopilotResult $out;return $out
    }
    try { Assert-DERManagedStateObject -StateRecord $apGroup -Component 'Autopilot' -ActionId 'AUTOPILOT-GROUP-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Autopilot' -ActionId 'AUTOPILOT-GROUP-PREFLIGHT' -DerId 'DER-GRP-DY-D-040'}
 $out=[pscustomobject]@{Module='Autopilot';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=1};Results=@([pscustomobject]@{DerId='DER-AUTOPILOT';Status='Failed';FailureKind=$derFailureKind;Message=('DER Autopilot target group failed Microsoft state validation: '+$_.Exception.Message)})};Save-DERAutopilotResult $out;return $out }

    foreach($p in $planned){
        $actionId=if(Test-DERAutopilotCommand 'New-DERActionId'){New-DERActionId -Component 'AUTOPILOT'}else{"AUTOPILOT-$($p.DerId)"}
        try{
            switch($p.DerId){
                'DER-AP-010' {$results.Add((Invoke-DERCreateAutopilotProfile -Planned $p -BuildPlan $BuildPlan -RunId $RunId -GroupId ([string]$apGroup.ObjectId) -DeviceUsageType singleUser -ActionId $actionId))}
                'DER-ESP-010' {$results.Add((Invoke-DERCreateESP -Planned $p -BuildPlan $BuildPlan -RunId $RunId -GroupId ([string]$apGroup.ObjectId) -ActionId $actionId))}
                'DER-AP-030' {
                    $selfGroup=Get-DERAutopilotStateObject -DerId 'DER-GRP-D-150'
                    if(-not $selfGroup){throw (New-DERWorkloadFailureException -Message 'Self-deploying Autopilot was selected, but the DER self-deploying device group is missing.')}
                    Assert-DERManagedStateObject -StateRecord $selfGroup -Component 'Autopilot' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') | Out-Null
                    $results.Add((Invoke-DERCreateAutopilotProfile -Planned $p -BuildPlan $BuildPlan -RunId $RunId -GroupId ([string]$selfGroup.ObjectId) -DeviceUsageType shared -ActionId $actionId))
                }
                default {$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$null;Status='Skipped';Message='No approved Autopilot handler exists for this planned object.';ActionId=$actionId})}
            }
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Autopilot' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$null;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})}
    }
    $summary=[pscustomobject]@{Created=@($results|Where-Object Status -eq 'Created').Count;Existing=@($results|Where-Object Status -eq 'Existing').Count;Skipped=@($results|Where-Object Status -eq 'Skipped').Count;Failed=@($results|Where-Object Status -eq 'Failed').Count}
    $out=[pscustomobject][ordered]@{Module='Autopilot';RunId=$RunId;Status=if($summary.Failed){'CompletedWithFailures'}else{'Completed'};CriticalFailure=$false;Summary=$summary;Results=@($results)};Save-DERAutopilotResult $out
    Write-DERAutopilotLog -Level $(if($summary.Failed){'WARN'}else{'OK'}) -Message ("Autopilot workload complete: {0} created, {1} existing, {2} skipped, {3} failed." -f $summary.Created,$summary.Existing,$summary.Skipped,$summary.Failed) -Data $summary
    return $out
}

Export-ModuleMember -Function @('New-DERAutopilotProfileBody','New-DERAutopilotAssignmentBody','New-DERESPBody','Invoke-DERAutopilotModule')
