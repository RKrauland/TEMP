<#
.SYNOPSIS
    DER Windows LAPS endpoint-security workload.

.DESCRIPTION
    Creates a DER Windows LAPS policy from the current Intune Endpoint Security
    Account Protection template and enables the Microsoft Entra tenant LAPS
    switch only after the client policy is successfully created, Pilot assigned,
    and validated. If DER cannot resolve the current template safely, or if the
    tenant-wide switch cannot be changed under the approved run safety mode,
    the module skips before partially configuring LAPS.

.NOTES
    Required parent entry point: Invoke-DERLAPSModule
#>


# Maintenance notes
# Responsibility: Manages LAPS policy and the shared deviceRegistrationPolicy switch without creating duplicate singleton ownership records.
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


function Test-DERLAPSCommand {param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERLAPSLog {param([string]$Level,[string]$Message,$Data,[string]$ActionId)if(Test-DERLAPSCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'LAPS' -ActionId $ActionId -Message $Message -Data $Data}}
function Save-DERLAPSResult {param($Result)$ctx=if(Test-DERLAPSCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'LAPS.json') -Encoding UTF8}}
function Get-DERLAPSStateObject {param([string]$DerId)if(Test-DERLAPSCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null}
function ConvertTo-DERLAPSSearchText {param($Object)$p=@();foreach($n in @('id','name','displayName','description','helpText','offsetUri','baseUri')){if($Object -and $Object.PSObject.Properties.Name -contains $n -and $null-ne$Object.$n){$p+=[string]$Object.$n}};return (($p-join' ') -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant()}
function Test-DERLAPSAlias {param([string]$Text,[string[]]$Aliases)foreach($a in @($Aliases)){$n=(($a-replace'[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant());if($n -and $Text.Contains($n)){return $true}};return $false}
function Get-DERLAPSExactPolicy {param([string]$Name,[string]$ActionId)$all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Component 'LAPS' -ActionId $ActionId;return @($all|Where-Object{[string]$_.name-eq$Name})}
function Get-DERLAPSTemplate {
    param([string]$ActionId)
    $templates=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicyTemplates' -ApiVersion beta -Component 'LAPS' -ActionId $ActionId
    $c=@($templates|Where-Object{[string]$_.templateFamily-eq'endpointSecurityAccountProtection' -and ((-not$_.PSObject.Properties['platforms']) -or [string]$_.platforms-match'windows') -and ((-not$_.PSObject.Properties['lifecycleState']) -or [string]$_.lifecycleState-in@('active','unknownFutureValue') -or [string]::IsNullOrWhiteSpace([string]$_.lifecycleState))})
    # Prefer templates explicitly named LAPS; Account Protection also contains unrelated profile types.
    $laps=@($c|Where-Object{(ConvertTo-DERLAPSSearchText $_) -match 'laps|local administrator password'})
    if($laps.Count){$c=$laps}
    if(-not$c.Count){return$null}
    return @($c|Sort-Object @{Expression={try{[version]([string]$_.displayVersion)}catch{[version]'0.0'}};Descending=$true},@{Expression={[string]$_.id};Descending=$true})[0]
}
function Get-DERLAPSCatalog {
    param([string]$TemplateId,[string]$ActionId)
    $sts=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates"-f$TemplateId) -ApiVersion beta -Component 'LAPS' -ActionId $ActionId
    $out=New-Object System.Collections.Generic.List[object]
    foreach($st in @($sts)){try{$defs=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates/{1}/settingDefinitions"-f$TemplateId,$st.id) -ApiVersion beta -Component 'LAPS' -ActionId $ActionId;foreach($d in @($defs)){$out.Add([pscustomobject]@{SettingTemplate=$st;Definition=$d;SearchText=(ConvertTo-DERLAPSSearchText $d)})}}catch{throw (New-DERWorkloadFailureException -Message ("DER cannot safely build the LAPS settings catalog because template entry '{0}' could not be enumerated: {1}"-f$st.id,$_.Exception.Message) -InnerException $_.Exception)}}
    return @($out)
}
function Find-DERLAPSDefinition {param($Catalog,[string[]]$Aliases,[switch]$RootOnly)$m=@($Catalog|Where-Object{(Test-DERLAPSAlias -Text ([string]$_.SearchText) -Aliases $Aliases) -and ((-not$RootOnly) -or (-not($_.Definition.PSObject.Properties.Name-contains'rootDefinitionId')) -or [string]::IsNullOrWhiteSpace([string]$_.Definition.rootDefinitionId))});if(-not$m.Count){return$null};return @($m|Sort-Object @{Expression={if($_.Definition.PSObject.Properties.Name-contains'rootDefinitionId' -and -not[string]::IsNullOrWhiteSpace([string]$_.Definition.rootDefinitionId)){1}else{0}}},@{Expression={([string]$_.Definition.displayName).Length}})[0]}
function Find-DERLAPSChoice {param($Definition,[string[]]$Aliases)$m=@($Definition.options|Where-Object{Test-DERLAPSAlias -Text (ConvertTo-DERLAPSSearchText $_) -Aliases $Aliases});if(-not$m.Count){return$null};return @($m|Sort-Object @{Expression={([string]$_.displayName).Length}})[0]}
function Get-DERLAPSValueTemplateId {param($SettingTemplate,$Option,[switch]$Simple)if($Option -and $Option.optionValue -and $Option.optionValue.settingValueTemplateReference){return[string]$Option.optionValue.settingValueTemplateReference.settingValueTemplateId};$si=$SettingTemplate.settingInstanceTemplate;if($Simple -and $si.simpleSettingValueTemplate){return[string]$si.simpleSettingValueTemplate.settingValueTemplateId};if((-not$Simple)-and$si.choiceSettingValueTemplate){return[string]$si.choiceSettingValueTemplate.settingValueTemplateId};return$null}
function New-DERLAPSSetting {
    param($CatalogItem,[string[]]$ChoiceAliases,$SimpleValue)
    $d=$CatalogItem.Definition;$st=$CatalogItem.SettingTemplate
    if($d.PSObject.Properties.Name-contains'rootDefinitionId' -and -not[string]::IsNullOrWhiteSpace([string]$d.rootDefinitionId)){return$null}
    $dt=[string]$d.'@odata.type';$it=[string]$st.settingInstanceTemplate.settingInstanceTemplateId
    if($dt-match'ChoiceSettingDefinition'){$o=Find-DERLAPSChoice -Definition $d -Aliases $ChoiceAliases;if(-not$o){return$null};$v=if($o.itemId){[string]$o.itemId}elseif($o.name){[string]$o.name}else{return$null};$vr=Get-DERLAPSValueTemplateId -SettingTemplate $st -Option $o;$cv=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingValue';children=@();value=$v};if($vr){$cv.settingValueTemplateReference=[ordered]@{settingValueTemplateId=$vr}};return[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance';settingDefinitionId=[string]$d.id;settingInstanceTemplateReference=[ordered]@{settingInstanceTemplateId=$it};choiceSettingValue=$cv}}}
    if($dt-match'SimpleSettingDefinition'){$vd=if($d.valueDefinition){[string]$d.valueDefinition.'@odata.type'}else{''};$type=if($vd-match'Integer'){'Integer'}elseif($vd-match'Boolean'){'Boolean'}else{'String'};$val=switch($type){'Integer'{[int]$SimpleValue};'Boolean'{[bool]$SimpleValue};default{[string]$SimpleValue}};$vr=Get-DERLAPSValueTemplateId -SettingTemplate $st -Simple;$sv=[ordered]@{'@odata.type'=("#microsoft.graph.deviceManagementConfiguration{0}SettingValue"-f$type);value=$val};if($vr){$sv.settingValueTemplateReference=[ordered]@{settingValueTemplateId=$vr}};return[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance';settingDefinitionId=[string]$d.id;settingInstanceTemplateReference=[ordered]@{settingInstanceTemplateId=$it};simpleSettingValue=$sv}}}
    return$null
}
function Resolve-DERLAPSSettings {
    param($Catalog,$BuildPlan)
    $specs=@(
        [pscustomobject]@{Name='Backup directory Microsoft Entra ID';Aliases=@('backup directory','backupdirectory');Choice=@('microsoft entra id','azure ad','entra id');Simple=$null;Required=$true},
        [pscustomobject]@{Name='Password age days';Aliases=@('password age days','passwordagedays');Choice=$null;Simple=[int]$BuildPlan.Answers.Security.LAPSRotationDays;Required=$true},
        [pscustomobject]@{Name='Password length';Aliases=@('password length','passwordlength');Choice=$null;Simple=[int]$BuildPlan.Answers.Security.LAPSPasswordLength;Required=$true},
        [pscustomobject]@{Name='Password complexity';Aliases=@('password complexity','passwordcomplexity');Choice=@('large letters small letters numbers special','uppercase lowercase numbers special','complexity 4','letters numbers special');Simple=$null;Required=$true}
    )
    if([bool]$BuildPlan.Answers.Security.LAPSPostAuthRotation){$specs+= [pscustomobject]@{Name='Post authentication actions';Aliases=@('post authentication actions','postauthenticationactions');Choice=@('reset password','password reset','reset the password');Simple=1;Required=$true}}
    $settings=New-Object System.Collections.Generic.List[object];$resolved=New-Object System.Collections.Generic.List[object];$missing=New-Object System.Collections.Generic.List[string]
    foreach($s in $specs){$i=Find-DERLAPSDefinition -Catalog $Catalog -Aliases $s.Aliases -RootOnly;if(-not$i){if($s.Required){$missing.Add($s.Name)};continue};$set=if($s.Choice){New-DERLAPSSetting -CatalogItem $i -ChoiceAliases $s.Choice}else{New-DERLAPSSetting -CatalogItem $i -SimpleValue $s.Simple};if(-not$set -and $s.Name-eq'Post authentication actions'){$set=New-DERLAPSSetting -CatalogItem $i -SimpleValue $s.Simple};if(-not$set){if($s.Required){$missing.Add($s.Name)};continue};$settings.Add($set);$resolved.Add([pscustomobject]@{Intent=$s.Name;DefinitionId=$i.Definition.id;DisplayName=$i.Definition.displayName})}
    # Automatic Account Management is optional. Add it only when the current template exposes a resolvable, root-level enable control.
    $auto=Find-DERLAPSDefinition -Catalog $Catalog -Aliases @('automatic account management enabled','automaticaccountmanagementenabled','automatic account management') -RootOnly
    $optionalMessage=$null
    if($auto){$aset=New-DERLAPSSetting -CatalogItem $auto -ChoiceAliases @('enabled','enable','yes','true');if(-not$aset){$aset=New-DERLAPSSetting -CatalogItem $auto -SimpleValue $true};if($aset){$settings.Add($aset);$resolved.Add([pscustomobject]@{Intent='Automatic account management';DefinitionId=$auto.Definition.id;DisplayName=$auto.Definition.displayName})}else{$optionalMessage='Automatic LAPS account management was exposed but DER could not safely resolve its enable value; the core LAPS policy will proceed without that optional setting.'}}
    else{$optionalMessage='Current LAPS template does not expose a safely resolvable automatic account-management setting. DER will manage LAPS password policy only; account creation/enablement remains a manual follow-up where required.'}
    return[pscustomobject]@{Success=($missing.Count-eq0);Settings=@($settings);Resolved=@($resolved);Missing=@($missing);OptionalMessage=$optionalMessage}
}
function Copy-DERLAPSDeviceRegistrationBody {
    param($Current)
    return [ordered]@{
        userDeviceQuota=[int]$Current.userDeviceQuota
        multiFactorAuthConfiguration=[string]$Current.multiFactorAuthConfiguration
        azureADRegistration=$Current.azureADRegistration
        azureADJoin=$Current.azureADJoin
        localAdminPassword=$Current.localAdminPassword
    }
}

function New-DERLAPSTenantSwitchChange {
    param([Parameter(Mandatory)]$CurrentPolicy)
    $original=Copy-DERLAPSDeviceRegistrationBody -Current $CurrentPolicy
    if([bool]$CurrentPolicy.localAdminPassword.isEnabled){
        return [pscustomobject]@{Changed=$false;Original=$original;Desired=$original}
    }
    $desired=Copy-DERLAPSDeviceRegistrationBody -Current $CurrentPolicy
    $desired.localAdminPassword=[ordered]@{isEnabled=$true}
    return [pscustomobject]@{Changed=$true;Original=$original;Desired=$desired}
}

function Enable-DERLAPSTenantSwitch {
    param([Parameter(Mandatory)]$SwitchChange,[Parameter(Mandatory)][string]$ActionId)
    if(-not [bool]$SwitchChange.Changed){return $SwitchChange}
    if(Test-DERLAPSCommand 'Register-DERTransaction'){
        Register-DERTransaction -ActionId $ActionId -Phase RECORD_ORIGINAL -Module 'LAPS' -DerId 'DER-LAPS-TENANT' -ObjectId 'deviceRegistrationPolicy' -Message 'Recorded deviceRegistrationPolicy before enabling Entra LAPS tenant switch.' -Data $SwitchChange.Original | Out-Null
    }
    Invoke-DERGraphRequest -Method PUT -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Body $SwitchChange.Desired -Component 'LAPS' -DerId 'DER-LAPS-TENANT' -ActionId $ActionId | Out-Null
    $verify=Invoke-DERGraphRequest -Method GET -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Component 'LAPS' -ActionId $ActionId
    $cmp=Test-DERExpectedSubset -Actual $verify -Expected $SwitchChange.Desired
    if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message 'Entra LAPS tenant switch failed read-back validation.')}
    if(Test-DERLAPSCommand 'Register-DERTransaction'){
        Register-DERTransaction -ActionId $ActionId -Phase COMMIT -Module 'LAPS' -DerId 'DER-LAPS-TENANT' -ObjectId 'deviceRegistrationPolicy' -Message 'Entra LAPS tenant switch enabled and validated.' | Out-Null
    }
    return $SwitchChange
}

function Restore-DERLAPSTenantSwitch {
    param([Parameter(Mandatory)]$SwitchChange,[Parameter(Mandatory)][string]$ActionId)
    if(-not [bool]$SwitchChange.Changed){return [pscustomobject]@{Restored=$false;WritePerformed=$false;Reason='Tenant switch was not changed.'}}

    # This switch shares deviceRegistrationPolicy with EntraDevice, so LAPS does
    # not create a second ownership record.  Re-read it and restore only when it
    # still equals either this run's desired value or its recorded original.
    $current=Invoke-DERGraphRequest -Method GET -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Component 'Rollback' -ActionId $ActionId
    $matchesOriginal=(Test-DERExpectedSubset -Actual $current -Expected $SwitchChange.Original).Success
    if($matchesOriginal){
        if(Test-DERLAPSCommand 'Register-DERTransaction'){
            Register-DERTransaction -ActionId $ActionId -Phase ROLLBACK_VALIDATE -Module 'LAPS' -DerId 'DER-LAPS-TENANT' -ObjectId 'deviceRegistrationPolicy' -Message 'LAPS tenant switch already matched the recorded original state; no rollback write was required.' | Out-Null
        }
        return [pscustomobject]@{Restored=$true;WritePerformed=$false;Reason='Already original.'}
    }
    $matchesDesired=(Test-DERExpectedSubset -Actual $current -Expected $SwitchChange.Desired).Success
    if(-not $matchesDesired){throw (New-DERWorkloadFailureException -Message 'LAPS tenant-switch rollback refused: deviceRegistrationPolicy matches neither this run''s desired state nor its recorded original state. Concurrent change is possible.')}

    $opened=$false
    try {
        if(Test-DERLAPSCommand 'Set-DERGraphRollbackWriteWindow'){
            Set-DERGraphRollbackWriteWindow -Enabled $true -Reason 'LAPS current-run deviceRegistrationPolicy switch rollback.' | Out-Null
            $opened=$true
        }
        if(Test-DERLAPSCommand 'Register-DERTransaction'){
            Register-DERTransaction -ActionId $ActionId -Phase ROLLBACK -Module 'LAPS' -DerId 'DER-LAPS-TENANT' -ObjectId 'deviceRegistrationPolicy' -Message 'Restoring current-run LAPS tenant switch after workload failure.' | Out-Null
        }
        Invoke-DERGraphRequest -Method PUT -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Body $SwitchChange.Original -Component 'Rollback' -DerId 'DER-LAPS-TENANT' -ActionId $ActionId | Out-Null
    }
    finally {
        if($opened){Set-DERGraphRollbackWriteWindow -Enabled $false -Reason 'LAPS tenant-switch rollback write completed.' | Out-Null}
    }
    $verify=Invoke-DERGraphRequest -Method GET -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Component 'Rollback' -ActionId $ActionId
    if(-not (Test-DERExpectedSubset -Actual $verify -Expected $SwitchChange.Original).Success){throw (New-DERWorkloadFailureException -Message 'LAPS tenant-switch rollback write returned, but original state did not validate.')}
    if(Test-DERLAPSCommand 'Register-DERTransaction'){
        Register-DERTransaction -ActionId $ActionId -Phase ROLLBACK_VALIDATE -Module 'LAPS' -DerId 'DER-LAPS-TENANT' -ObjectId 'deviceRegistrationPolicy' -Message 'LAPS tenant switch original state restored and read-back validated.' | Out-Null
    }
    return [pscustomobject]@{Restored=$true;WritePerformed=$true;Reason='Original state restored.'}
}

function New-DERLAPSAssignmentBody {param([string]$GroupId)return[ordered]@{assignments=@([ordered]@{target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}}
function Test-DERLAPSAssignment {param([string]$PolicyId,[string]$GroupId,[string]$ActionId)$a=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicies/{0}/assignments"-f$PolicyId) -ApiVersion beta -Component 'LAPS' -ActionId $ActionId;return[bool](@($a|Where-Object{[string]$_.target.groupId-eq$GroupId}).Count-gt0)}

function Invoke-DERLAPSModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)

    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled -and $_.Module -eq 'LAPS'}|Select-Object -First 1)
    if(-not $planned.Count){$out=[pscustomobject]@{Module='LAPS';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Updated=0;Skipped=0;Failed=0};Results=@()};Save-DERLAPSResult $out;return $out}
    $p=$planned[0]
    $results=New-Object System.Collections.Generic.List[object]
    $actionId=if(Test-DERLAPSCommand 'New-DERActionId'){New-DERActionId -Component 'LAPS'}else{'LAPS-001'}
    # The shared deviceRegistrationPolicy switch is a separate transaction from
    # the DER-owned Settings Catalog policy. A validated switch rollback must
    # never resolve/mask an unrelated policy create that used the same workload.
    $switchActionId=if(Test-DERLAPSCommand 'New-DERActionId'){New-DERActionId -Component 'LAPS-SWITCH'}else{'LAPS-SWITCH-001'}
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='LAPS Endpoint Security policy requires a DER-approved Microsoft Graph beta API; Preview APIs are disabled.';ActionId=$actionId})
        $out=[pscustomobject]@{Module='LAPS';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Updated=0;Skipped=1;Failed=0};Results=@($results)};Save-DERLAPSResult $out;return $out
    }

    $pilot=Get-DERLAPSStateObject -DerId 'DER-GRP-D-010'
    if(-not $pilot){
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';Message='DER Pilot device group is missing; LAPS cannot be safely targeted.';ActionId=$actionId})
        $out=[pscustomobject]@{Module='LAPS';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Updated=0;Skipped=0;Failed=1};Results=@($results)};Save-DERLAPSResult $out;return $out
    }

    $switchChange=$null
    try {
        Assert-DERManagedStateObject -StateRecord $pilot -Component 'LAPS' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') | Out-Null
        $devicePolicy=Invoke-DERGraphRequest -Method GET -Uri 'policies/deviceRegistrationPolicy' -ApiVersion 'v1.0' -Component 'LAPS' -ActionId $actionId
        $switchChange=New-DERLAPSTenantSwitchChange -CurrentPolicy $devicePolicy
        $tenantChangesAllowed=([string]$BuildPlan.Answers.Safety.ChangeControl -notin @('Report-only / no tenant writes','No tenant-wide switch changes'))
        if([bool]$switchChange.Changed -and -not $tenantChangesAllowed){
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Microsoft Entra LAPS tenant switch is disabled and this run forbids tenant-wide switch changes. DER skipped the entire LAPS workload to avoid a half-configured deployment.';ActionId=$actionId})
            $out=[pscustomobject]@{Module='LAPS';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Updated=0;Skipped=1;Failed=0};Results=@($results)};Save-DERLAPSResult $out;return $out
        }

        $state=Get-DERLAPSStateObject -DerId $p.DerId
        if($state){
            Assert-DERManagedStateObject -StateRecord $state -Component 'LAPS' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') | Out-Null
            if([bool]$switchChange.Changed){Enable-DERLAPSTenantSwitch -SwitchChange $switchChange -ActionId $switchActionId | Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='DER-owned LAPS policy and Pilot assignment match recorded Microsoft state; tenant LAPS prerequisite is verified.';ActionId=$actionId})
        }
        else {
            $collision=@(Get-DERLAPSExactPolicy -Name $p.DisplayName -ActionId $actionId)
            if($collision.Count){
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned LAPS/configuration policy exists; DER will not modify it without adoption.';ActionId=$actionId})
                $out=[pscustomobject]@{Module='LAPS';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Updated=0;Skipped=1;Failed=0};Results=@($results)};Save-DERLAPSResult $out;return $out
            }
            $template=Get-DERLAPSTemplate -ActionId $actionId
            if(-not $template){throw (New-DERWorkloadFailureException -Message 'No active Windows Endpoint Security Account Protection / Windows LAPS template could be resolved.')}
            $catalog=Get-DERLAPSCatalog -TemplateId ([string]$template.id) -ActionId $actionId
            $resolved=Resolve-DERLAPSSettings -Catalog $catalog -BuildPlan $BuildPlan
            if(-not $resolved.Success){
                $msg=("Current Intune LAPS template schema could not be safely resolved for: {0}. DER skipped the entire LAPS workload before writing anything." -f (@($resolved.Missing)-join'; '))
                if(Test-DERLAPSCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase SKIP -Module 'LAPS' -DerId $p.DerId -Message $msg -Data @{templateId=$template.id;missing=$resolved.Missing;resolved=$resolved.Resolved}|Out-Null}
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=$msg;ActionId=$actionId})
                $out=[pscustomobject]@{Module='LAPS';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Updated=0;Skipped=1;Failed=0};Results=@($results)};Save-DERLAPSResult $out;return $out
            }

            $body=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationPolicy';name=$p.DisplayName;description='Windows Local Administrator Password Solution policy. Assigned only to the Pilot device group.';platforms='windows10';technologies='mdm';roleScopeTagIds=@('0');settings=@($resolved.Settings);templateReference=[ordered]@{templateId=[string]$template.id}}
            $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Body $body -Component 'LAPS' -DerId $p.DerId -ActionId $actionId
            if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'LAPS policy create response did not include an object ID.')}
            $policyId=[string]$created.id
            $expected=[pscustomobject][ordered]@{name=$p.DisplayName;platforms='windows10'}
            $meta=[pscustomobject][ordered]@{
                Module='LAPS';ApiVersion='beta';ValidationUri=("deviceManagement/configurationPolicies/{0}" -f $policyId);DeleteUri=("deviceManagement/configurationPolicies/{0}" -f $policyId);ExpectedSubset=$expected
                SettingsUri=("deviceManagement/configurationPolicies/{0}/settings" -f $policyId);MinimumSettingsCount=@($resolved.Settings).Count
                AssignmentUri=("deviceManagement/configurationPolicies/{0}/assignments" -f $policyId);ExpectedAssignmentTargetId=[string]$pilot.ObjectId
                TemplateId=$template.id;TemplateFamily=$template.templateFamily;ResolvedSettings=$resolved.Resolved
            }
            Add-DERStateObject -DerId $p.DerId -ObjectId $policyId -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null
            Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/configurationPolicies/{0}/assign" -f $policyId) -ApiVersion beta -Body (New-DERLAPSAssignmentBody -GroupId ([string]$pilot.ObjectId)) -Component 'LAPS' -DerId $p.DerId -ActionId $actionId | Out-Null
            $state=Get-DERLAPSStateObject -DerId $p.DerId
            Assert-DERManagedStateObject -StateRecord $state -Component 'LAPS' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null

            # Tenant switch remains intentionally last.  LAPS does not claim a
            # second ownership record for the shared deviceRegistrationPolicy.
            if([bool]$switchChange.Changed){Enable-DERLAPSTenantSwitch -SwitchChange $switchChange -ActionId $switchActionId | Out-Null}
            if(Test-DERLAPSCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module 'LAPS' -DerId $p.DerId -ObjectId $policyId -Message 'LAPS policy created, Pilot assigned, validated, and tenant prerequisite verified.' | Out-Null}
            $message='Created current-schema LAPS policy, assigned to Pilot, validated, and verified Entra LAPS tenant support.'
            if($resolved.OptionalMessage){$message+=' '+$resolved.OptionalMessage}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$policyId;Status='Created';Message=$message;ActionId=$actionId})
        }
    }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'LAPS' -ActionId $actionId -DerId $p.DerId}

        $failureMessage=$_.Exception.Message
        if($switchChange -and [bool]$switchChange.Changed){
            try {Restore-DERLAPSTenantSwitch -SwitchChange $switchChange -ActionId $switchActionId | Out-Null}
            catch {$lapsRollbackError=$_;$failureMessage += ' Tenant-switch rollback also failed or was unsafe: '+$lapsRollbackError.Exception.Message;if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $lapsRollbackError -Component 'LAPS' -ActionId $switchActionId -Message 'LAPS tenant-switch rollback failed or was unsafe.'}else{Write-DERLAPSLog -Level ERROR -ActionId $switchActionId -Message $failureMessage}}
        }
        if(Test-DERLAPSCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase FAIL -Module 'LAPS' -DerId $p.DerId -Message $failureMessage | Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$failureMessage;ActionId=$actionId})
    }

    $summary=[pscustomobject]@{Created=@($results|Where-Object{$_.Status -eq 'Created'}).Count;Existing=@($results|Where-Object{$_.Status -eq 'Existing'}).Count;Updated=0;Skipped=@($results|Where-Object{$_.Status -eq 'Skipped'}).Count;Failed=@($results|Where-Object{$_.Status -eq 'Failed'}).Count}
    $out=[pscustomobject][ordered]@{Module='LAPS';RunId=$RunId;Status=if($summary.Failed){'CompletedWithFailures'}elseif($summary.Created -or $summary.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$summary;Results=@($results)}
    Save-DERLAPSResult $out
    return $out
}

Export-ModuleMember -Function @('Invoke-DERLAPSModule')
