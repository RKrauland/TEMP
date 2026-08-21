<#
.SYNOPSIS
    DER Microsoft Entra security-group workload.

.DESCRIPTION
    Creates only DER-planned security groups, including assigned framework
    groups and approved dynamic inventory groups. Exact-name collisions that
    DER does not own are skipped and reported; they are never modified.

.NOTES
    Required parent entry point: Invoke-DERGroupsModule
#>


# Maintenance notes
# Responsibility: Creates/validates DER security groups and dynamic membership groups; Groups is also the controlled real-workload pilot surface.
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


function Test-DERGroupsCommand {param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERGroupsLog {param([string]$Level,[string]$Message,$Data,[string]$ActionId)if(Test-DERGroupsCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Groups' -ActionId $ActionId -Message $Message -Data $Data}}
function ConvertTo-DERMailNickname {
    param([Parameter(Mandatory)][string]$DisplayName,[Parameter(Mandatory)][string]$DerId)
    $base=($DisplayName -replace '[^A-Za-z0-9._-]','')
    if([string]::IsNullOrWhiteSpace($base)){$base='SecurityGroup'}
    if($base.Length -gt 48){$base=$base.Substring(0,48)}
    $bytes=[System.Text.Encoding]::UTF8.GetBytes($DerId);$sha=[System.Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').Substring(0,8)}finally{$sha.Dispose()}
    return (($base+'-'+$hash).Substring(0,[Math]::Min(64,($base+'-'+$hash).Length)))
}
function Get-DERDynamicGroupRule {
    param([Parameter(Mandatory)]$PlannedObject,[Parameter(Mandatory)]$BuildPlan)
    switch($PlannedObject.DerId){
        'DER-GRP-DY-D-010' {return '(device.deviceOSType -eq "Windows") -and (device.deviceOSVersion -startsWith "10.0.2")'}
        'DER-GRP-DY-D-020' {return '(device.deviceOSType -eq "Windows") -and (device.deviceOSVersion -startsWith "10.0.1")'}
        'DER-GRP-DY-D-030' {return '(device.deviceOSType -eq "MacMDM")'}
        'DER-GRP-DY-D-040' {
            $tag=[string]$BuildPlan.Answers.Enrollment.AutopilotGroupTag
            $escaped=$tag.Replace('"','\"')
            return ('(device.devicePhysicalIds -any (_ -eq "[OrderID]:{0}"))' -f $escaped)
        }
        'DER-GRP-DY-D-050' {return '((device.deviceOSType -eq "iPad") -or (device.deviceOSType -eq "iPhone"))'}
        'DER-GRP-DY-D-060' {return '((device.deviceOSType -startsWith "AndroidEnterprise") -or (device.deviceOSType -eq "AndroidForWork") -or (device.deviceOSType -eq "Android"))'}
        default {throw (New-DERWorkloadFailureException -Message "No approved DER dynamic membership rule exists for $($PlannedObject.DerId)." -FailureKind Engine)}
    }
}
function Get-DERExactGroupByDisplayName {
    param([Parameter(Mandatory)][string]$DisplayName,[string]$ActionId)
    $escaped=$DisplayName.Replace("'","''")
    try{$r=Invoke-DERGraphRequest -Method GET -Uri ("groups?`$filter=displayName eq '{0}'&`$select=id,displayName,description,mailEnabled,mailNickname,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState" -f $escaped) -ApiVersion 'v1.0' -Component 'Groups' -ActionId $ActionId;return @($r.value)}catch{throw (New-DERWorkloadFailureException -Message "DER cannot safely determine whether group '$DisplayName' already exists because the exact-name Graph read failed: $($_.Exception.Message)" -InnerException $_.Exception)}
}
function Save-DERGroupsResult {
    param([Parameter(Mandatory)]$Result)
    $ctx=if(Test-DERGroupsCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if(-not$ctx){return}
    $dir=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $dir -Force|Out-Null
    $Result|ConvertTo-Json -Depth 60|Set-Content -LiteralPath (Join-Path $dir 'Groups.json') -Encoding UTF8
}
function Invoke-DERGroupsModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $started=Get-Date;$results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'Groups'})
    if($planned.Count -eq 0){$out=[pscustomobject]@{Module='Groups';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Results=@();Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=0}};Save-DERGroupsResult $out;return$out}
    Write-DERGroupsLog -Level STEP -Message ("Starting DER Groups workload for {0} planned group(s)." -f $planned.Count) -Data @{tenantId=$BuildPlan.TenantId}
    foreach($p in $planned){
        $actionId=if(Test-DERGroupsCommand 'New-DERActionId'){New-DERActionId -Component 'GROUP'}else{"GROUP-$($p.DerId)"}
        $record=if(Test-DERGroupsCommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
        if($record -and [string]$record.Status -notin @('RolledBack','Retired')){
            Assert-DERManagedStateObject -StateRecord $record -Component 'Groups' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$record.ObjectId;Status='Existing';Message='Tracked DER-owned group exists and matches recorded state.';ActionId=$actionId});continue
        }
        $collisions=@(Get-DERExactGroupByDisplayName -DisplayName $p.DisplayName -ActionId $actionId)
        if($collisions.Count -gt 0){
            $msg='An existing customer-owned group with the exact planned display name exists. DER skipped it; adoption/compare is required.'
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collisions[0].id;Status='Skipped';Message=$msg;ActionId=$actionId});if(Test-DERGroupsCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase SKIP -Module 'Groups' -DerId $p.DerId -ObjectId $collisions[0].id -Message $msg|Out-Null};continue
        }
        try{
            if(Test-DERGroupsCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module 'Groups' -DerId $p.DerId -Message 'No DER ownership or exact-name collision found; group create allowed.'|Out-Null}
            $dynamic=([string]$p.ObjectType -eq 'DynamicSecurityGroup')
            $body=[ordered]@{displayName=$p.DisplayName;description=if($dynamic){'Dynamic device inventory group.'}else{'Standard security group for tenant management and policy targeting.'};mailEnabled=$false;mailNickname=(ConvertTo-DERMailNickname -DisplayName $p.DisplayName -DerId $p.DerId);securityEnabled=$true;groupTypes=if($dynamic){@('DynamicMembership')}else{@()}}
            $rule=$null
            if($dynamic){$rule=Get-DERDynamicGroupRule -PlannedObject $p -BuildPlan $BuildPlan;$body.membershipRule=$rule;$body.membershipRuleProcessingState='On'}
            if(Test-DERGroupsCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module 'Groups' -DerId $p.DerId -Message 'Prepared DER security group create.' -Data @{displayName=$p.DisplayName;dynamic=$dynamic}|Out-Null}
            $created=Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion 'v1.0' -Body $body -Component 'Groups' -DerId $p.DerId -ActionId $actionId
            if(-not$created.id){throw (New-DERWorkloadFailureException -Message 'Graph create response did not contain a group object ID.')}
            $expected=[ordered]@{displayName=$p.DisplayName;mailEnabled=$false;securityEnabled=$true;groupTypes=if($dynamic){@('DynamicMembership')}else{@()}}
            if($dynamic){$expected.membershipRule=$rule;$expected.membershipRuleProcessingState='On'}
            $meta=[pscustomobject][ordered]@{Module='Groups';ApiVersion='v1.0';ValidationUri=("groups/{0}?`$select=id,displayName,description,mailEnabled,mailNickname,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState" -f $created.id);DeleteUri=("groups/{0}" -f $created.id);ExpectedSubset=[pscustomobject]$expected;PrincipalType=$p.Metadata.PrincipalType;Membership=$p.Metadata.Membership}
            if(Test-DERGroupsCommand 'Add-DERStateObject'){Add-DERStateObject -DerId $p.DerId -ObjectId ([string]$created.id) -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null}
            $readback=Invoke-DERGraphRequest -Method GET -Uri $meta.ValidationUri -ApiVersion 'v1.0' -Component 'Groups' -DerId $p.DerId -ActionId $actionId
            $cmp=if(Test-DERGroupsCommand 'Test-DERExpectedSubset'){Test-DERExpectedSubset -Actual $readback -Expected $meta.ExpectedSubset}else{[pscustomobject]@{Success=$true}}
            if(-not$cmp.Success){throw (New-DERWorkloadFailureException -Message 'Created group failed immediate DER read-back validation.')}
            if(Test-DERGroupsCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$created.id) -MarkValidated|Out-Null}
            if(Test-DERGroupsCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module 'Groups' -DerId $p.DerId -ObjectId $created.id -Message 'Group created and validated.'|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Created and validated.';ActionId=$actionId})
        } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Groups' -ActionId $actionId -DerId $p.DerId}

            if(Test-DERGroupsCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase FAIL -Module 'Groups' -DerId $p.DerId -Message $_.Exception.Message|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$null;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
        }
    }
    $summary=[pscustomobject]@{Created=@($results|Where-Object {$_.Status -eq 'Created'}).Count;Existing=@($results|Where-Object {$_.Status -eq 'Existing'}).Count;Skipped=@($results|Where-Object {$_.Status -eq 'Skipped'}).Count;Failed=@($results|Where-Object {$_.Status -eq 'Failed'}).Count}
    $out=[pscustomobject][ordered]@{Module='Groups';RunId=$RunId;StartedAt=$started;CompletedAt=Get-Date;Status=if($summary.Failed -gt 0){'CompletedWithFailures'}else{'Completed'};CriticalFailure=($summary.Failed -gt 0);Summary=$summary;Results=@($results)};Save-DERGroupsResult $out
    Write-DERGroupsLog -Level $(if($summary.Failed -gt 0){'WARN'}else{'OK'}) -Message ("Groups workload complete: {0} created, {1} existing, {2} skipped, {3} failed." -f $summary.Created,$summary.Existing,$summary.Skipped,$summary.Failed) -Data $summary
    return$out
}

Export-ModuleMember -Function @('ConvertTo-DERMailNickname','Get-DERDynamicGroupRule','Invoke-DERGroupsModule')
