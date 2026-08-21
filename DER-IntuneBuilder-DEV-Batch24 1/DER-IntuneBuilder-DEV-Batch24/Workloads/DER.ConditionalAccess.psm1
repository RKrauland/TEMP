<#
.SYNOPSIS
    DER Microsoft Entra Conditional Access workload.

.DESCRIPTION
    Creates the DER standard Conditional Access family in Report-only state.
    No DER Conditional Access policy is created enabled or enforced. Emergency
    Access exclusions are required before broad user-targeted policies can be
    created. Existing exact-name policies are preserved unless explicitly
    adopted outside this module.

.NOTES
    Required parent entry point: Invoke-DERConditionalAccessModule
#>


# Maintenance notes
# Responsibility: Creates only approved Report-only Conditional Access policies; enforcement is outside this baseline contract.
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


function Test-DERCACommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DERCALog { param([string]$Level,[string]$Message,$Data,[string]$ActionId) if(Test-DERCACommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'ConditionalAccess' -ActionId $ActionId -Message $Message -Data $Data} }
function Save-DERCAResult { param($Result) $ctx=if(Test-DERCACommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'ConditionalAccess.json') -Encoding UTF8} }

function Get-DERCAStateGroupId {
    param([Parameter(Mandatory)][string]$DerId,[switch]$Optional,[string]$ActionId='CAP-GROUP-PREFLIGHT')
    $s=if(Test-DERCACommand 'Get-DERStateObject'){Get-DERStateObject -DerId $DerId}else{$null}
    if (-not $s -and -not $Optional) { throw (New-DERWorkloadFailureException -Message "Required DER group $DerId does not exist in DER state.") }
    if ($s) { Assert-DERManagedStateObject -StateRecord $s -Component 'ConditionalAccess' -ActionId $ActionId -AllowedOwnershipClass @('DER-Owned') | Out-Null;return [string]$s.ObjectId }
    return $null
}

function Get-DERPrivilegedRoleIds {
    param([string]$ActionId)
    $wanted=@('Global Administrator','Privileged Role Administrator','Conditional Access Administrator','Security Administrator','Intune Administrator','Privileged Authentication Administrator','Authentication Administrator','User Administrator','Application Administrator','Cloud Application Administrator','Exchange Administrator','SharePoint Administrator')
    $defs=@(Invoke-DERGraphCollectionRequest -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn' -ApiVersion 'v1.0' -Component 'ConditionalAccess' -ActionId $ActionId)
    return @($defs | Where-Object {$_.isBuiltIn -ne $false -and $_.displayName -in $wanted} | Select-Object -ExpandProperty id -Unique)
}

function Get-DERPhishingResistantStrengthId {
    param([string]$ActionId)
    $strengths=@(Invoke-DERGraphCollectionRequest -Uri 'policies/authenticationStrengthPolicies' -ApiVersion 'v1.0' -Component 'ConditionalAccess' -ActionId $ActionId)
    $match=@($strengths|Where-Object {[string]$_.displayName -match '(?i)phishing[- ]resistant'}|Select-Object -First 1)
    if ($match) { return [string]$match[0].id }
    return $null
}

function New-DERCAUsers {
    param([string[]]$IncludeUsers=@('All'),[string[]]$IncludeRoles=@(),[string[]]$ExcludeGroups=@(),[switch]$Guests)
    $u=[ordered]@{excludeUsers=@();excludeGroups=@($ExcludeGroups);excludeRoles=@()}
    if ($Guests) {$u.includeUsers=@('GuestsOrExternalUsers');$u.includeGroups=@();$u.includeRoles=@()}
    else {$u.includeUsers=@($IncludeUsers);$u.includeGroups=@();$u.includeRoles=@($IncludeRoles)}
    return $u
}

function New-DERCAApplications { param([string[]]$Applications=@('All'),[string[]]$UserActions=@()) if($UserActions.Count){return [ordered]@{includeApplications=@();excludeApplications=@();includeUserActions=@($UserActions)}} return [ordered]@{includeApplications=@($Applications);excludeApplications=@();includeUserActions=@()} }
function New-DERCAGrant { param([string[]]$BuiltInControls=@(),[string]$AuthenticationStrengthId,[string]$Operator='OR') $g=[ordered]@{operator=$Operator;builtInControls=@($BuiltInControls);customAuthenticationFactors=@();termsOfUse=@()} if($AuthenticationStrengthId){$g.authenticationStrength=[ordered]@{id=$AuthenticationStrengthId}} return $g }

function New-DERConditionalAccessBody {
    param([Parameter(Mandatory)]$PlannedObject,[Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$EmergencyGroupId,[string[]]$PrivilegedRoleIds,[string]$PhishingStrengthId,[string]$ApprovedCountryLocationId,[string]$TravelGroupId)
    $conditions=[ordered]@{users=(New-DERCAUsers -ExcludeGroups @($EmergencyGroupId));applications=(New-DERCAApplications);clientAppTypes=@('all')}
    $grant=$null
    switch ([string]$PlannedObject.DerId) {
        'DER-CAP-010' { $conditions.clientAppTypes=@('exchangeActiveSync','other');$grant=New-DERCAGrant -BuiltInControls @('block') }
        'DER-CAP-020' { $grant=New-DERCAGrant -BuiltInControls @('mfa') }
        'DER-CAP-030' { if(-not$PrivilegedRoleIds.Count){throw (New-DERWorkloadFailureException -Message 'No privileged Microsoft Entra role definitions could be resolved.')};if(-not$PhishingStrengthId){throw (New-DERWorkloadFailureException -Message 'Built-in Phishing-resistant MFA authentication strength could not be resolved.')};$conditions.users=New-DERCAUsers -IncludeUsers @() -IncludeRoles $PrivilegedRoleIds -ExcludeGroups @($EmergencyGroupId);$grant=New-DERCAGrant -AuthenticationStrengthId $PhishingStrengthId }
        'DER-CAP-040' { $conditions.applications=New-DERCAApplications -UserActions @('urn:user:registersecurityinfo');$grant=New-DERCAGrant -BuiltInControls @('mfa') }
        'DER-CAP-050' { $conditions.applications=New-DERCAApplications -UserActions @('urn:user:registerdevice');$grant=New-DERCAGrant -BuiltInControls @('mfa') }
        'DER-CAP-060' { $conditions.platforms=[ordered]@{includePlatforms=@('windows');excludePlatforms=@()};$grant=New-DERCAGrant -BuiltInControls @('compliantDevice') }
        'DER-CAP-070' { if(-not$PrivilegedRoleIds.Count){throw (New-DERWorkloadFailureException -Message 'No privileged Microsoft Entra role definitions could be resolved.')};$conditions.users=New-DERCAUsers -IncludeUsers @() -IncludeRoles $PrivilegedRoleIds -ExcludeGroups @($EmergencyGroupId);$grant=New-DERCAGrant -BuiltInControls @('compliantDevice') }
        'DER-CAP-080' { $conditions.users=New-DERCAUsers -Guests -ExcludeGroups @($EmergencyGroupId);$grant=New-DERCAGrant -BuiltInControls @('mfa') }
        'DER-CAP-090' { $conditions.signInRiskLevels=@('medium','high');$grant=New-DERCAGrant -BuiltInControls @('mfa') }
        'DER-CAP-100' { $conditions.userRiskLevels=@('high');$grant=New-DERCAGrant -BuiltInControls @('mfa','passwordChange') -Operator 'AND' }
        'DER-CAP-110' { $conditions.authenticationFlows=[ordered]@{transferMethods='deviceCodeFlow'};$grant=New-DERCAGrant -BuiltInControls @('block') }
        'DER-CAP-120' {
            if(-not$ApprovedCountryLocationId){throw (New-DERWorkloadFailureException -Message 'Approved-countries Named Location does not exist; geographic CAP cannot be safely created.')}
            $excludeGroups=@($EmergencyGroupId);if($TravelGroupId){$excludeGroups+=@($TravelGroupId)}
            $conditions.users=New-DERCAUsers -ExcludeGroups $excludeGroups
            $conditions.locations=[ordered]@{includeLocations=@('All');excludeLocations=@($ApprovedCountryLocationId)}
            $grant=New-DERCAGrant -BuiltInControls @('block')
        }
        default { throw (New-DERWorkloadFailureException -Message "Unknown DER Conditional Access definition $($PlannedObject.DerId)." -FailureKind Engine) }
    }
    return [ordered]@{displayName=[string]$PlannedObject.DisplayName;state='enabledForReportingButNotEnforced';conditions=$conditions;grantControls=$grant;sessionControls=$null}
}

function Complete-DERCAResult {
    param([System.Collections.Generic.List[object]]$Results,[string]$RunId)
    $s=[pscustomobject]@{Created=@($Results|Where-Object{$_.Status-eq'Created'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count}
    $o=[pscustomobject][ordered]@{Module='ConditionalAccess';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)};Save-DERCAResult$o;return$o
}

function Invoke-DERConditionalAccessModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled-and$_.Module-eq'ConditionalAccess'})
    if(-not$planned.Count){return Complete-DERCAResult $results $RunId}
    $emergency=Get-DERCAStateGroupId -DerId 'DER-GRP-U-030'
    $travel=Get-DERCAStateGroupId -DerId 'DER-GRP-U-100' -Optional
    $approvedLocState=if(Test-DERCACommand 'Get-DERStateObject'){Get-DERStateObject -DerId 'DER-LOC-COUNTRY-010'}else{$null}
    if($approvedLocState){Assert-DERManagedStateObject -StateRecord $approvedLocState -Component 'ConditionalAccess' -ActionId 'CAP-LOCATION-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null}
    $roles=Get-DERPrivilegedRoleIds -ActionId 'CAP-ROLESCAN'
    $strength=Get-DERPhishingResistantStrengthId -ActionId 'CAP-AUTHSTRENGTH'
    $existing=@(Invoke-DERGraphCollectionRequest -Uri 'identity/conditionalAccess/policies' -ApiVersion 'v1.0' -Component 'ConditionalAccess' -ActionId 'CAP-SCAN')

    foreach($p in$planned){
        $aid=if(Test-DERCACommand 'New-DERActionId'){New-DERActionId -Component 'CAP'}else{"CAP-$($p.DerId)"}
        try{
            $state=if(Test-DERCACommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
            if($state){
                Assert-DERManagedStateObject -StateRecord $state -Component 'ConditionalAccess' -ActionId $aid -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='DER-managed Report-only policy exists and matches recorded Microsoft state.';ActionId=$aid});continue
            }
            $collision=@($existing|Where-Object{[string]$_.displayName-eq[string]$p.DisplayName})
            if($collision.Count){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned Conditional Access policy exists; explicit adoption is required.';ActionId=$aid});continue}
            $body=New-DERConditionalAccessBody -PlannedObject $p -BuildPlan $BuildPlan -EmergencyGroupId $emergency -PrivilegedRoleIds $roles -PhishingStrengthId $strength -ApprovedCountryLocationId $(if($approvedLocState){[string]$approvedLocState.ObjectId}else{$null}) -TravelGroupId $travel
            if([string]$body.state-ne'enabledForReportingButNotEnforced'){throw (New-DERWorkloadFailureException -Message 'DER safety gate refused a Conditional Access body that was not Report-only.')}
            if(Test-DERCACommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase PRECHECK -Module 'ConditionalAccess' -DerId $p.DerId -Message 'Prepared DER Conditional Access policy create in Report-only state.' -Data $body|Out-Null}
            $created=Invoke-DERGraphRequest -Method POST -Uri 'identity/conditionalAccess/policies' -ApiVersion 'v1.0' -Body $body -Component 'ConditionalAccess' -DerId $p.DerId -ActionId $aid
            if(-not$created.id){throw (New-DERWorkloadFailureException -Message 'Conditional Access create response did not contain an object ID.')}
            $meta=[pscustomobject]@{Module='ConditionalAccess';ApiVersion='v1.0';ValidationUri=("identity/conditionalAccess/policies/{0}"-f$created.id);DeleteUri=("identity/conditionalAccess/policies/{0}"-f$created.id);ExpectedSubset=[pscustomobject]@{displayName=$p.DisplayName;state='enabledForReportingButNotEnforced'}}
            if(Test-DERCACommand 'Add-DERStateObject'){Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null}
            Assert-DERManagedStateObject -StateRecord (Get-DERStateObject -DerId $p.DerId) -Component 'ConditionalAccess' -ActionId $aid -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null
            if(Test-DERCACommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase COMMIT -Module 'ConditionalAccess' -DerId $p.DerId -ObjectId $created.id -Message 'Report-only Conditional Access policy created and validated.'|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Conditional Access policy created and validated in Report-only state.';ActionId=$aid});$existing+=$created
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'ConditionalAccess' -ActionId $aid -DerId $p.DerId}

            if(Test-DERCACommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase FAIL -Module 'ConditionalAccess' -DerId $p.DerId -Message $_.Exception.Message|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$aid})
        }
    }
    $out=Complete-DERCAResult $results $RunId
    Write-DERCALog -Level $(if($out.Summary.Failed){'WARN'}else{'OK'}) -Message 'Conditional Access workload completed. DER created no enforced policies.' -Data $out.Summary
    return$out
}

Export-ModuleMember -Function @('New-DERConditionalAccessBody','Invoke-DERConditionalAccessModule')
