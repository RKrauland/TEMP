<#
.SYNOPSIS
    DER Windows enrollment workload.

.DESCRIPTION
    Creates DER-owned Windows enrollment restrictions and user enrollment limit,
    targets them only to the DER Intune Enrollment user group, and optionally
    configures the built-in Microsoft Intune MDM automatic-enrollment scope on
    new/mostly-empty tenants through the approved Graph beta mobility policy API.

.NOTES
    Required parent entry point: Invoke-DEREnrollmentModule
#>


# Maintenance notes
# Responsibility: Manages Intune enrollment configurations plus the special tenant-wide MDM scope relationship with explicit cleanup proof.
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


function Test-DEREnrollmentCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DEREnrollmentLog { param([string]$Level,[string]$Message,$Data,[string]$ActionId) if(Test-DEREnrollmentCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Enrollment' -ActionId $ActionId -Message $Message -Data $Data} }
function Save-DEREnrollmentResult { param($Result) $ctx=if(Test-DEREnrollmentCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$dir=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $dir -Force|Out-Null;$Result|ConvertTo-Json -Depth 80|Set-Content -LiteralPath (Join-Path $dir 'Enrollment.json') -Encoding UTF8} }
function Get-DEREnrollmentStateObject { param([string]$DerId) if(Test-DEREnrollmentCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null }
function Get-DEREnrollmentExactConfig {
    param([Parameter(Mandatory)][string]$DisplayName,[Parameter(Mandatory)][string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/deviceEnrollmentConfigurations' -ApiVersion 'v1.0' -Component 'Enrollment' -ActionId $ActionId
    return @($all | Where-Object {[string]$_.displayName -eq $DisplayName})
}
function New-DEREnrollmentAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId,[ValidateSet('user','device')][string]$TargetType='user')
    return [ordered]@{
        '@odata.type'='#microsoft.graph.enrollmentConfigurationAssignment'
        target=[ordered]@{
            '@odata.type'='microsoft.graph.scopeTagGroupAssignmentTarget'
            targetType=$TargetType
            entraObjectId=$GroupId
        }
    }
}
function Test-DEREnrollmentAssignment {
    param([Parameter(Mandatory)][string]$ConfigurationId,[Parameter(Mandatory)][string]$GroupId,[ValidateSet('user','device')][string]$TargetType='user',[Parameter(Mandatory)][string]$ActionId)
    $r=Invoke-DERGraphRequest -Method GET -Uri ("deviceManagement/deviceEnrollmentConfigurations/{0}/assignments" -f $ConfigurationId) -ApiVersion 'v1.0' -Component 'Enrollment' -ActionId $ActionId
    return [bool](@($r.value | Where-Object {[string]$_.target.entraObjectId -eq $GroupId -and [string]$_.target.targetType -eq $TargetType}).Count -gt 0)
}
function Register-DEREnrollmentOwnedObject {
    param($Planned,$Created,[string]$RunId,$BuildPlan,[string]$ExpectedODataType,[string]$AssignmentGroupId)
    $expected=[ordered]@{displayName=$Planned.DisplayName;'@odata.type'=$ExpectedODataType}
    $meta=[pscustomobject][ordered]@{
        Module='Enrollment';ApiVersion='v1.0';ValidationUri=("deviceManagement/deviceEnrollmentConfigurations/{0}" -f $Created.id);
        DeleteUri=("deviceManagement/deviceEnrollmentConfigurations/{0}" -f $Created.id);ExpectedSubset=[pscustomobject]$expected;AssignmentUri=("deviceManagement/deviceEnrollmentConfigurations/{0}/assignments" -f $Created.id);ExpectedAssignmentTargetId=$AssignmentGroupId
    }
    if(Test-DEREnrollmentCommand 'Add-DERStateObject'){
        Add-DERStateObject -DerId $Planned.DerId -ObjectId ([string]$Created.id) -ObjectType $Planned.ObjectType -DisplayName $Planned.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null
    }
    return $meta
}
function New-DERWindowsRestrictionBody {
    param($BuildPlan,$Planned)
    $minVersion=if([bool]$BuildPlan.Answers.Enrollment.BlockNewWindows10){'10.0.22000.0'}else{$null}
    $base=[ordered]@{platformBlocked=$false;personalDeviceEnrollmentBlocked=$false;osMinimumVersion=$null;osMaximumVersion=$null;blockedManufacturers=@();blockedSkus=@()}
    $windows=[ordered]@{platformBlocked=$false;personalDeviceEnrollmentBlocked=[bool]$BuildPlan.Answers.Enrollment.CorporateWindowsOnly;osMinimumVersion=$minVersion;osMaximumVersion=$null;blockedManufacturers=@();blockedSkus=@()}
    return [ordered]@{
        '@odata.type'='#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
        displayName=$Planned.DisplayName
        description='Windows corporate enrollment restrictions. Scoped only to the Intune Enrollment user group.'
        priority=1
        version=1
        iosRestriction=$base
        windowsRestriction=$windows
        windowsMobileRestriction=$base
        androidRestriction=$base
        macOSRestriction=$base
    }
}
function New-DEREnrollmentLimitBody {
    param($BuildPlan,$Planned)
    return [ordered]@{
        '@odata.type'='#microsoft.graph.deviceEnrollmentLimitConfiguration'
        displayName=$Planned.DisplayName
        description='User device enrollment limit. Scoped only to the Intune Enrollment user group.'
        priority=1
        version=1
        limit=[int]$BuildPlan.Answers.Enrollment.MaxEnrollmentsPerUser
    }
}
function Invoke-DERCreateEnrollmentConfiguration {
    param($Planned,$BuildPlan,[string]$RunId,[string]$EnrollmentGroupId,[Parameter(Mandatory)][string]$ActionId)
    $state=Get-DEREnrollmentStateObject -DerId $Planned.DerId
    if($state){
        Assert-DERManagedStateObject -StateRecord $state -Component 'Enrollment' -ActionId $ActionId -MarkValidated | Out-Null
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned enrollment configuration exists and matches recorded state.';ActionId=$ActionId}
    }
    $collision=@(Get-DEREnrollmentExactConfig -DisplayName $Planned.DisplayName -ActionId $ActionId)
    if($collision.Count -gt 0){return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned enrollment configuration exists; DER will not modify it without adoption.';ActionId=$ActionId}}
    $body=switch($Planned.ObjectType){'EnrollmentLimit'{New-DEREnrollmentLimitBody -BuildPlan $BuildPlan -Planned $Planned}default{New-DERWindowsRestrictionBody -BuildPlan $BuildPlan -Planned $Planned}}
    if(Test-DEREnrollmentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $ActionId -Phase PRECHECK -Module 'Enrollment' -DerId $Planned.DerId -Message 'Prepared DER enrollment configuration create.' -Data @{displayName=$Planned.DisplayName;type=$Planned.ObjectType}|Out-Null}
    $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/deviceEnrollmentConfigurations' -ApiVersion 'v1.0' -Body $body -Component 'Enrollment' -DerId $Planned.DerId -ActionId $ActionId
    if(-not $created.id){throw (New-DERWorkloadFailureException -Message "Graph create response for $($Planned.DerId) did not contain an ID.")}
    $odata=if($Planned.ObjectType -eq 'EnrollmentLimit'){'#microsoft.graph.deviceEnrollmentLimitConfiguration'}else{'#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'}
    $meta=Register-DEREnrollmentOwnedObject -Planned $Planned -Created $created -RunId $RunId -BuildPlan $BuildPlan -ExpectedODataType $odata -AssignmentGroupId $EnrollmentGroupId
    $assignBody=New-DEREnrollmentAssignmentBody -GroupId $EnrollmentGroupId -TargetType user
    Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/deviceEnrollmentConfigurations/{0}/assignments" -f $created.id) -ApiVersion 'v1.0' -Body $assignBody -Component 'Enrollment' -DerId $Planned.DerId -ActionId $ActionId|Out-Null
    $read=Invoke-DERGraphRequest -Method GET -Uri $meta.ValidationUri -ApiVersion 'v1.0' -Component 'Enrollment' -ActionId $ActionId
    $cmp=if(Test-DEREnrollmentCommand 'Test-DERExpectedSubset'){Test-DERExpectedSubset -Actual $read -Expected $meta.ExpectedSubset}else{[pscustomobject]@{Success=$true}}
    if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message "Enrollment configuration $($Planned.DerId) failed read-back validation.")}
    if(-not (Test-DEREnrollmentAssignment -ConfigurationId ([string]$created.id) -GroupId $EnrollmentGroupId -TargetType user -ActionId $ActionId)){throw (New-DERWorkloadFailureException -Message "Enrollment configuration $($Planned.DerId) assignment failed read-back validation.")}
    if(Test-DEREnrollmentCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$created.id) -MarkValidated|Out-Null}
    if(Test-DEREnrollmentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $ActionId -Phase COMMIT -Module 'Enrollment' -DerId $Planned.DerId -ObjectId $created.id -Message 'Enrollment configuration created, assigned, and validated.'|Out-Null}
    return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$created.id;Status='Created';Message='Created, assigned to DER Intune Enrollment users, and validated.';ActionId=$ActionId}
}
function Invoke-DERConfigureMdmScope {
    param($BuildPlan,[string]$EnrollmentGroupId,[string]$RunId,[Parameter(Mandatory)][string]$ActionId)
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){return [pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$null;Status='Skipped';Message='Preview APIs disabled; MDM user scope left unchanged.';ActionId=$ActionId}}
    if($BuildPlan.Safety.ChangeControl -eq 'No tenant-wide switch changes' -or $BuildPlan.Safety.ChangeControl -eq 'Report-only / no tenant writes'){return [pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$null;Status='Skipped';Message='Tenant-wide switches are disabled for this run; MDM user scope left unchanged.';ActionId=$ActionId}}
    if([string]$BuildPlan.EnvironmentClassification -ne 'NewOrMostlyEmpty' -and $BuildPlan.Profile -ne 'Custom'){
        return [pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$null;Status='Skipped';Message='Existing tenant detected. DER Standard preserves the existing MDM auto-enrollment scope; review it in Manual Actions / findings before adopting a tenant-wide change.';ActionId=$ActionId}
    }
    $r=Invoke-DERGraphRequest -Method GET -Uri "policies/mobileDeviceManagementPolicies?`$filter=displayName eq 'Microsoft Intune'&`$expand=includedGroups" -ApiVersion beta -Component 'Enrollment' -ActionId $ActionId
    $policy=@($r.value|Select-Object -First 1)
    if(-not $policy){throw (New-DERWorkloadFailureException -Message 'Microsoft Intune mobileDeviceManagementPolicy was not returned; MDM scope cannot be safely configured.')}
    $currentGroups=@($policy.includedGroups|ForEach-Object {[string]$_.id})
    if([string]$policy.appliesTo -eq 'selected' -and $currentGroups -contains $EnrollmentGroupId){return [pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$policy.id;Status='Existing';Message='MDM automatic enrollment is already scoped to the DER enrollment group.';ActionId=$ActionId}}
    # Adding an included group is the Microsoft-supported way to select a scoped group.
    $graphContext=Get-DERGraphEngineContext
    if(-not $graphContext -or [string]::IsNullOrWhiteSpace([string]$graphContext.GraphEndpoint)){throw (New-DERWorkloadFailureException -Message 'DER Graph environment is not initialized; MDM included-group reference cannot be built safely.' -FailureKind Engine)}
    $graphRoot=([string]$graphContext.GraphEndpoint).TrimEnd('/')
    $body=[ordered]@{'@odata.id'=("{0}/odata/groups('{1}')" -f $graphRoot,$EnrollmentGroupId)}
    Invoke-DERGraphRequest -Method POST -Uri ("policies/mobileDeviceManagementPolicies/{0}/includedGroups/`$ref" -f $policy.id) -ApiVersion beta -Body $body -Component 'Enrollment' -DerId 'DER-MDM-SCOPE' -ActionId $ActionId|Out-Null
    $after=Invoke-DERGraphRequest -Method GET -Uri ("policies/mobileDeviceManagementPolicies/{0}?`$expand=includedGroups" -f $policy.id) -ApiVersion beta -Component 'Enrollment' -ActionId $ActionId
    $afterGroups=@($after.includedGroups|ForEach-Object {[string]$_.id})
    if([string]$after.appliesTo -ne 'selected' -or $afterGroups -notcontains $EnrollmentGroupId){
        # Reverse only the relation this action attempted to add, then prove the
        # relation is absent.  Cleanup failure is never swallowed.
        if(Test-DEREnrollmentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $ActionId -Phase ROLLBACK -Module 'Enrollment' -DerId 'DER-MDM-SCOPE' -ObjectId $policy.id -Message 'MDM scope validation failed; removing the current-run included-group relation.'|Out-Null}
        $cleanupError=$null
        try{Invoke-DERGraphRequest -Method DELETE -Uri ("policies/mobileDeviceManagementPolicies/{0}/includedGroups/{1}/`$ref" -f $policy.id,$EnrollmentGroupId) -ApiVersion beta -Component 'Rollback' -DerId 'DER-MDM-SCOPE' -ActionId $ActionId|Out-Null}catch{$cleanupError=$_.Exception.Message}
        $cleanupRead=$null
        try{$cleanupRead=Invoke-DERGraphRequest -Method GET -Uri ("policies/mobileDeviceManagementPolicies/{0}?`$expand=includedGroups" -f $policy.id) -ApiVersion beta -Component 'Rollback' -ActionId $ActionId}catch{throw (New-DERWorkloadFailureException -Message ("MDM automatic enrollment scope failed validation, and cleanup could not be proven because read-back failed: {0}" -f $_.Exception.Message) -InnerException $_.Exception)}
        $remaining=@($cleanupRead.includedGroups|ForEach-Object {[string]$_.id})
        if($remaining -contains $EnrollmentGroupId){throw (New-DERWorkloadFailureException -Message ("MDM automatic enrollment scope failed validation and current-run relation cleanup was not proven. DELETE result: {0}" -f $(if($cleanupError){$cleanupError}else{'relation still present'})))}
        if(Test-DEREnrollmentCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $ActionId -Phase ROLLBACK_VALIDATE -Module 'Enrollment' -DerId 'DER-MDM-SCOPE' -ObjectId $policy.id -Message 'Current-run MDM included-group relation cleanup proven by read-back.' -Data @{deleteError=$cleanupError}|Out-Null}
        throw (New-DERWorkloadFailureException -Message 'MDM automatic enrollment scope did not validate as Selected with the DER enrollment group. DER removed and read-back verified the current-run relation before stopping.')
    }
    return [pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$policy.id;Status='Updated';Message='MDM automatic enrollment scope set to Selected using the DER Intune Enrollment group.';ActionId=$ActionId}
}
function Invoke-DEREnrollmentModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'Enrollment'})
    if($planned.Count -eq 0){$out=[pscustomobject]@{Module='Enrollment';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Updated=0;Existing=0;Skipped=0;Failed=0};Results=@()};Save-DEREnrollmentResult $out;return$out}
    $results=New-Object System.Collections.Generic.List[object]
    $group=Get-DEREnrollmentStateObject -DerId 'DER-GRP-U-080'
    if(-not $group){$out=[pscustomobject]@{Module='Enrollment';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Updated=0;Existing=0;Skipped=0;Failed=1};Results=@([pscustomobject]@{DerId='DER-ENROLLMENT';Status='Failed';Message='DER Intune Enrollment user group is missing; enrollment workload cannot be safely targeted.'})};Save-DEREnrollmentResult $out;return$out}
    try{Assert-DERManagedStateObject -StateRecord $group -Component 'Enrollment' -ActionId 'ENROLL-GROUP-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned')|Out-Null}catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Enrollment' -ActionId 'ENROLL-GROUP-PREFLIGHT' -DerId 'DER-GRP-U-080'}
$out=[pscustomobject]@{Module='Enrollment';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Updated=0;Existing=0;Skipped=0;Failed=1};Results=@([pscustomobject]@{DerId='DER-ENROLLMENT';Status='Failed';FailureKind=$derFailureKind;Message=('DER Intune Enrollment user group failed Microsoft state validation: '+$_.Exception.Message)})};Save-DEREnrollmentResult $out;return$out}
    Write-DEREnrollmentLog -Level STEP -Message ("Starting Enrollment workload for {0} planned object(s)." -f $planned.Count) -Data @{tenantId=$BuildPlan.TenantId;groupId=$group.ObjectId}
    foreach($p in $planned){
        $actionId=if(Test-DEREnrollmentCommand 'New-DERActionId'){New-DERActionId -Component 'ENROLL'}else{"ENROLL-$($p.DerId)"}
        try{$results.Add((Invoke-DERCreateEnrollmentConfiguration -Planned $p -BuildPlan $BuildPlan -RunId $RunId -EnrollmentGroupId ([string]$group.ObjectId) -ActionId $actionId))}catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Enrollment' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$null;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})}
    }
    $mdmAction=if(Test-DEREnrollmentCommand 'New-DERActionId'){New-DERActionId -Component 'MDMSCOPE'}else{'MDMSCOPE-001'}
    if(@($results|Where-Object{$_.Status -eq 'Failed'}).Count){
        $results.Add([pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$null;Status='Skipped';Message='Earlier Enrollment object work failed; DER refused the tenant-wide MDM scope write.';ActionId=$mdmAction})
    }else{
        try{$results.Add((Invoke-DERConfigureMdmScope -BuildPlan $BuildPlan -EnrollmentGroupId ([string]$group.ObjectId) -RunId $RunId -ActionId $mdmAction))}catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Enrollment' -ActionId $mdmAction -DerId 'DER-MDM-SCOPE'}
$results.Add([pscustomobject]@{DerId='DER-MDM-SCOPE';DisplayName='Microsoft Intune MDM user scope';ObjectId=$null;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$mdmAction})}
    }
    $summary=[pscustomobject]@{Created=@($results|Where-Object Status -eq 'Created').Count;Updated=@($results|Where-Object Status -eq 'Updated').Count;Existing=@($results|Where-Object Status -eq 'Existing').Count;Skipped=@($results|Where-Object Status -eq 'Skipped').Count;Failed=@($results|Where-Object Status -eq 'Failed').Count}
    $out=[pscustomobject][ordered]@{Module='Enrollment';RunId=$RunId;Status=if($summary.Failed){'CompletedWithFailures'}else{'Completed'};CriticalFailure=$false;Summary=$summary;Results=@($results)};Save-DEREnrollmentResult $out
    Write-DEREnrollmentLog -Level $(if($summary.Failed){'WARN'}else{'OK'}) -Message ("Enrollment workload complete: {0} created, {1} updated, {2} existing, {3} skipped, {4} failed." -f $summary.Created,$summary.Updated,$summary.Existing,$summary.Skipped,$summary.Failed) -Data $summary
    return$out
}

Export-ModuleMember -Function @('New-DEREnrollmentAssignmentBody','New-DERWindowsRestrictionBody','New-DEREnrollmentLimitBody','Invoke-DEREnrollmentModule')
